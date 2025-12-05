#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
High-level DSL runtime with cached ASTs and optional filesystem watching.

Features:
- Loads all .def files for a given program/version and compiles them into ASTs.
- Provides decode() that reuses cached node trees (no re-parse per packet).
- Optional watchdog-based hot reload on file changes.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from modules.DecoderHandler import DecoderHandler
from modules.NodeTreeParser import NodeTreeParser
from modules.Session import BlockDefinition, get_session
from utils.ConfigLoader import ConfigLoader
from utils.FileUtils import FileHandler
from utils.Logger import Logger

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:  # pragma: no cover - optional dependency
    FileSystemEventHandler = None  # type: ignore
    Observer = None  # type: ignore


@dataclass
class CompiledDefinition:
    """Represents a compiled DSL file cached in memory."""

    name: str
    path: Path
    lines: List[str]
    expected: Any
    fields: List[Any] = field(default_factory=list)
    variables: Dict[str, Any] = field(default_factory=dict)
    blocks: Dict[str, BlockDefinition] = field(default_factory=dict)
    mtime: float = 0.0


class _DefChangeHandler(FileSystemEventHandler):  # type: ignore[misc]
    """Watchdog handler that triggers recompilation on file changes."""

    def __init__(self, runtime: "DslRuntime"):
        self.runtime = runtime

    def on_created(self, event):  # pragma: no cover - filesystem callback
        self._maybe_reload(event)

    def on_modified(self, event):  # pragma: no cover - filesystem callback
        self._maybe_reload(event)

    def on_moved(self, event):  # pragma: no cover - filesystem callback
        self._maybe_reload(event)

    def on_deleted(self, event):  # pragma: no cover - filesystem callback
        if getattr(event, "is_directory", False):
            return
        path = Path(event.src_path)
        if path.suffix == ".def":
            self.runtime.drop(path.stem)

    def _maybe_reload(self, event):  # pragma: no cover - filesystem callback
        if getattr(event, "is_directory", False):
            return
        path = Path(event.src_path)
        if path.suffix != ".def":
            return
        self.runtime.compile_file(path, force=True, log_prefix="[watch]")


class DslRuntime:
    """
    Cache + interpreter facade for DSL packets.

    Typical usage:
        rt = DslRuntime(program="mop", version="v18414", watch=True)
        rt.load_all()
        result = rt.decode("SMSG_AUTH_RESPONSE", payload_bytes)
    """

    def __init__(self, program: Optional[str] = None, version: Optional[str] = None, watch: bool = False):
        cfg = ConfigLoader.load_config()
        self.program = program or cfg["program"]
        self.version = version or cfg["version"]

        base = Path("protocols") / self.program / self.version
        self.def_dir = base / "def"
        self.json_dir = base / "json"

        self.cache: Dict[str, CompiledDefinition] = {}
        self.lock = threading.RLock()
        self.session = get_session()
        self.observer: Optional[Observer] = None

        if watch:
            self.start_watcher()

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def load_all(self) -> None:
        """Compile all .def files into the in-memory cache."""
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

    def decode(self, name: str, payload: bytes, silent: bool = False) -> dict:
        """
        Decode a payload using a cached AST. Falls back to compile if missing.
        """
        compiled = self.cache.get(name) or self.compile_file(self.def_dir / f"{name}.def")
        if not compiled:
            raise FileNotFoundError(f"Missing def for {name}")

        with self.lock:
            self.session.reset()
            self.session.program = self.program
            self.session.version = self.version

            # Fresh copies so DecoderHandler can mutate safely
            self.session.fields = [node.copy() for node in compiled.fields]
            self.session.variables = {k: v.copy() for k, v in compiled.variables.items()}
            self.session.blocks = {
                k: BlockDefinition(name=b.name, nodes=[n.copy() for n in b.nodes])
                for k, b in compiled.blocks.items()
            }

            return DecoderHandler.decode((name, compiled.lines, payload, compiled.expected or {}), silent=silent)

    def stop(self) -> None:
        """Stop watchdog observer if running."""
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=2)
            self.observer = None

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #
    def compile_file(self, path: Path, force: bool = False, log_prefix: str = "") -> Optional[CompiledDefinition]:
        """
        Parse + cache a single def file. Skips unchanged files unless force=True.
        """
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
        expected = FileHandler.load_json_file(str(expected_path)) if expected_path.exists() else {}

        with self.lock:
            self.session.reset()
            self.session.program = self.program
            self.session.version = self.version

            NodeTreeParser.parse((name, lines, b"", expected))

            compiled = CompiledDefinition(
                name=name,
                path=path,
                lines=lines,
                expected=expected,
                fields=[n.copy() for n in self.session.fields],
                variables={k: v.copy() for k, v in self.session.variables.items()},
                blocks={k: BlockDefinition(name=b.name, nodes=[n.copy() for n in b.nodes]) for k, b in self.session.blocks.items()},
                mtime=mtime,
            )

            self.cache[name] = compiled
            Logger.debug(f"{log_prefix}Cached {name} ({len(compiled.fields)} fields)")
            return compiled

    def drop(self, name: str) -> None:
        """Remove a compiled entry from cache."""
        with self.lock:
            if name in self.cache:
                del self.cache[name]
                Logger.info(f"[watch] Dropped cache for {name}")

    def start_watcher(self) -> None:
        """Start watchdog watcher if available."""
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
