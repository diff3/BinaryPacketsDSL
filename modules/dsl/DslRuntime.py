#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""High-level DSL runtime with cached ASTs and optional filesystem watching.

This module loads .def files into cached ASTs, restores scope variables, and
exposes decode helpers that reset session state. Optional filesystem watching
keeps cached definitions in sync with disk changes.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from modules.dsl.DecoderHandler import DecoderHandler
from modules.dsl.NodeTreeParser import NodeTreeParser
from modules.dsl.Session import BlockDefinition, get_session
from utils.ConfigLoader import ConfigLoader
from utils.FileUtils import FileHandler
from utils.Logger import Logger

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:
    FileSystemEventHandler = None
    Observer = None

# Provide a no-op base class when watchdog is missing.
if FileSystemEventHandler is None:
    class FileSystemEventHandler:  # type: ignore
        """Fallback watchdog handler when the dependency is unavailable."""

        def __init__(self, *args, **kwargs) -> None:
            return None


@dataclass
class CompiledDefinition:
    """Container for compiled .def data used by the runtime cache."""

    name: str
    path: Path
    lines: list[str]
    expected: Any
    fields: list[Any] = field(default_factory=list)
    variables: dict[str, Any] = field(default_factory=dict)
    blocks: dict[str, BlockDefinition] = field(default_factory=dict)
    mtime: float = 0.0


class _DefChangeHandler(FileSystemEventHandler):
    """Watchdog event handler that triggers runtime recompilation."""

    def __init__(self, runtime: "DslRuntime") -> None:
        self.runtime = runtime

    def on_created(self, event: Any) -> None:
        self._maybe_reload(event)

    def on_modified(self, event: Any) -> None:
        self._maybe_reload(event)

    def on_moved(self, event: Any) -> None:
        self._maybe_reload(event)

    def on_deleted(self, event: Any) -> None:
        if getattr(event, "is_directory", False):
            return
        path = Path(event.src_path)
        if path.suffix == ".def":
            self.runtime.drop(path.stem)

    def _maybe_reload(self, event: Any) -> None:
        if getattr(event, "is_directory", False):
            return
        path = Path(event.src_path)
        if path.suffix == ".def":
            self.runtime.compile_file(path, force=True, log_prefix="[watch]")


class DslRuntime:
    """Load, cache, and decode DSL definitions."""

    def __init__(
        self,
        program: Optional[str] = None,
        version: Optional[str] = None,
        watch: bool = False,
        expansion: Optional[str] = None,
    ) -> None:
        """Initialize a runtime instance.

        Args:
            program (str | None): Program name override.
            version (str | None): Protocol version override.
            watch (bool): Enable filesystem watching for .def changes.
            expansion (str | None): Expansion override.
        """
        cfg = ConfigLoader.load_config()
        self.program = program or cfg["program"]
        self.expansion = expansion or cfg.get("expansion")
        self.version = version or cfg["version"]

        if self.expansion:
            base = Path("protocols") / self.program / self.expansion / self.version
        else:
            base = Path("protocols") / self.program / self.version
        self.def_dir = base / "data" / "def"
        self.json_dir = base / "data" / "json"

        self.cache: dict[str, CompiledDefinition] = {}
        self.lock = threading.RLock()
        self.session = get_session()
        self.observer: Optional[Observer] = None

        if watch:
            self.start_watcher()

    def load_all(self) -> None:
        """Compile all .def files and cache them with expected JSON."""
        if not self.def_dir.exists():
            Logger.warning(f"DEF directory not found: {self.def_dir}")
            return

        paths = sorted(self.def_dir.glob("*.def"))
        if not paths:
            Logger.warning(f"No def files found in {self.def_dir}")
            return

        total = len(paths)
        for idx, path in enumerate(paths, start=1):
            self.compile_file(path)
            Logger.progress("DSL load", idx, total, inline=True, detail=path.stem)

    def load_runtime_all(self) -> None:
        """Compile all .def files without loading expected JSON."""
        if not self.def_dir.exists():
            Logger.warning(f"DEF directory not found: {self.def_dir}")
            return

        paths = sorted(self.def_dir.glob("*.def"))
        if not paths:
            Logger.warning(f"No def files found in {self.def_dir}")
            return

        total = len(paths)
        for idx, path in enumerate(paths, start=1):
            self.compile_file_runtime(path)
            Logger.progress("DSL runtime load", idx, total, inline=True, detail=path.stem)

    def decode(self, name: str, payload: bytes, silent: bool = False) -> dict[str, Any]:
        """Decode a packet payload using the cached definition.

        Args:
            name (str): Definition name (without extension).
            payload (bytes): Raw packet payload.
            silent (bool): Skip success logging when True.

        Returns:
            dict[str, Any]: Decoded public fields.
        """
        compiled = self.cache.get(name) or self.compile_file(
            self.def_dir / f"{name}.def"
        )
        if not compiled:
            raise FileNotFoundError(f"Missing def for {name}")

        with self.lock:
            self.session.reset()
            self.session.program = self.program
            self.session.expansion = self.expansion
            self.session.version = self.version

            self.session.fields = [node.copy() for node in compiled.fields]

            self.session.scope.set_all(
                {k: v.copy() for k, v in compiled.variables.items()}
            )

            self.session.blocks = {
                k: BlockDefinition(name=b.name, nodes=[n.copy() for n in b.nodes])
                for k, b in compiled.blocks.items()
            }

            return DecoderHandler.decode(
                (name, compiled.lines, payload, compiled.expected or {}),
                silent=silent,
            )

    def stop(self) -> None:
        """Stop the filesystem watcher if running."""
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=2)
            self.observer = None

    def compile_file(
        self,
        path: Path,
        force: bool = False,
        log_prefix: str = "",
    ) -> Optional[CompiledDefinition]:
        """Compile a .def file and cache it along with expected JSON."""
        path = Path(path)
        if not path.exists():
            Logger.warning(f"{log_prefix} Missing def file: {path}")
            return None

        name = path.stem
        mtime = path.stat().st_mtime

        cached = self.cache.get(name)
        if cached and cached.mtime >= mtime and not force:
            return cached

        lines = FileHandler.load_file(str(path))

        expected_path = self.json_dir / f"{name}.json"
        if expected_path.exists():
            expected = FileHandler.load_json_file(str(expected_path))
        else:
            expected = {}

        with self.lock:
            self.session.reset()
            self.session.program = self.program
            self.session.expansion = self.expansion
            self.session.version = self.version

            NodeTreeParser.parse((name, lines, b"", expected))

            compiled = CompiledDefinition(
                name=name,
                path=path,
                lines=lines,
                expected=expected,
                fields=[n.copy() for n in self.session.fields],
                variables=self.session.scope.get_all().copy(),
                blocks={
                    k: BlockDefinition(name=b.name, nodes=[n.copy() for n in b.nodes])
                    for k, b in self.session.blocks.items()
                },
                mtime=mtime,
            )

            self.cache[name] = compiled
            Logger.debug(f"{log_prefix}Cached {name} ({len(compiled.fields)} fields)")
            return compiled

    def compile_file_runtime(
        self,
        path: Path,
        force: bool = False,
        log_prefix: str = "",
    ) -> Optional[CompiledDefinition]:
        """Compile a .def file without loading expected JSON."""
        path = Path(path)
        if not path.exists():
            Logger.warning(f"{log_prefix} Missing def file: {path}")
            return None

        name = path.stem
        mtime = path.stat().st_mtime

        cached = self.cache.get(name)
        if cached and cached.mtime >= mtime and not force:
            return cached

        lines = FileHandler.load_file(str(path))

        with self.lock:
            self.session.reset()
            self.session.program = self.program
            self.session.version = self.version

            NodeTreeParser.parse((name, lines, b"", {}))

            compiled = CompiledDefinition(
                name=name,
                path=path,
                lines=lines,
                expected={},
                fields=[n.copy() for n in self.session.fields],
                variables=self.session.scope.get_all().copy(),
                blocks={
                    k: BlockDefinition(name=b.name, nodes=[n.copy() for n in b.nodes])
                    for k, b in self.session.blocks.items()
                },
                mtime=mtime,
            )

            self.cache[name] = compiled
            Logger.debug(f"{log_prefix}Runtime cached {name} ({len(compiled.fields)} fields)")
            return compiled

    def drop(self, name: str) -> None:
        """Drop a cached definition by name."""
        with self.lock:
            if name in self.cache:
                del self.cache[name]
                Logger.info(f"[watch] Dropped cache for {name}")

    def start_watcher(self) -> None:
        """Start a watchdog observer for live .def reloads."""
        if Observer is None or FileSystemEventHandler is None:
            Logger.warning("watchdog not installed; live reload disabled")
            return

        if not self.def_dir.exists():
            self.def_dir.mkdir(parents=True, exist_ok=True)

        handler = _DefChangeHandler(self)
        self.observer = Observer()
        self.observer.schedule(handler, str(self.def_dir), recursive=False)
        self.observer.start()
        Logger.info(f"Watching {self.def_dir} for changes")


__all__ = ["DslRuntime", "CompiledDefinition"]
