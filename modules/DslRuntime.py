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

from DSL.modules.DecoderHandler import DecoderHandler
from DSL.modules.NodeTreeParser import NodeTreeParser
from DSL.modules.Session import BlockDefinition, get_session
from shared.FileUtils import FileHandler
from shared.Logger import Logger
from shared.PathUtils import get_def_root, get_json_root, get_project_root

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
        self.program = program
        self.expansion = expansion
        self.version = version
        self.def_dir = get_def_root()
        self.json_dir = get_json_root()

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

    def load_runtime_all(self, progress: bool = False) -> tuple[int, int]:
        """Compile all .def files without loading expected JSON."""
        if not self.def_dir.exists():
            Logger.warning(f"DEF directory not found: {self.def_dir}")
            return 0, 0

        paths = sorted(self.def_dir.glob("*.def"))
        if not paths:
            Logger.warning(f"No def files found in {self.def_dir}")
            return 0, 0

        total = len(paths)
        for idx, path in enumerate(paths, start=1):
            self.compile_file_runtime(path, log_cache=False)
            if progress:
                Logger.progress("DSL runtime load", idx, total, inline=True, detail=path.stem)
        return total, total

    def decode(
        self,
        name: str,
        payload: bytes,
        silent: bool = False,
        warn: bool = True,
    ) -> dict[str, Any]:
        """Decode a packet payload using the cached definition.

        Args:
            name (str): Definition name (without extension).
            payload (bytes): Raw packet payload.
            silent (bool): Skip success logging when True.

        Returns:
            dict[str, Any]: Decoded public fields.
        """
        compiled = self.cache.get(name) or self.compile_file(
            self.def_dir / f"{name}.def",
            warn_missing=warn,
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
                warn=warn,
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
        log_cache: bool = True,
        warn_missing: bool = True,
    ) -> Optional[CompiledDefinition]:
        """Compile a .def file and cache it along with expected JSON."""
        path = Path(path)
        if not path.exists():
            if warn_missing:
                Logger.warning(f"{log_prefix} Missing file {path.name}")
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
            if log_cache:
                Logger.trace(
                    f"{log_prefix}Cached {name} ({len(compiled.fields)} fields)",
                    scope="dsl",
                )
            return compiled

    def compile_file_runtime(
        self,
        path: Path,
        force: bool = False,
        log_prefix: str = "",
        log_cache: bool = True,
    ) -> Optional[CompiledDefinition]:
        """Compile a .def file without loading expected JSON."""
        path = Path(path)
        if not path.exists():
            Logger.warning(f"{log_prefix} Missing file {path.name}")
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
            self.session.expansion = self.expansion
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
            if log_cache:
                Logger.trace(
                    f"{log_prefix}Runtime cached {name} ({len(compiled.fields)} fields)",
                    scope="dsl",
                )
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
            Logger.warning(f"Watch path does not exist: {self.def_dir}")
            return

        handler = _DefChangeHandler(self)
        self.observer = Observer()
        self.observer.schedule(handler, str(self.def_dir), recursive=False)
        self.observer.start()
        try:
            relative = self.def_dir.relative_to(get_project_root())
            watch_path = f"[{relative.as_posix()}]"
        except Exception:
            watch_path = f"[{self.def_dir}]"
        Logger.info(f"Watching {watch_path} for changes")


__all__ = ["DslRuntime", "CompiledDefinition"]
