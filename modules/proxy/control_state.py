#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Thread-safe shared control state for the proxy."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import Optional, Set, Dict, Any

import yaml


@dataclass(frozen=True)
class ControlSnapshot:
    dump: bool
    focus: Optional[Set[str]]
    filters: Optional[Set[str]]
    ignore: Set[str]
    whitelist: Set[str]
    show_raw: bool
    show_debug: bool


class ControlState:
    """Mutable shared state guarded by a re-entrant lock."""

    def __init__(self, *, dump: bool = False, update: bool = False, focus: Optional[Set[str]] = None, persist_path: str = "etc/proxy-conf.yaml") -> None:
        self._lock = threading.RLock()
        self.persist_path = Path(persist_path)

        # defaults / base
        self._dump = bool(dump)
        # Update mode removed; keep flag for compatibility but force disabled
        self._update = False
        self._focus_enabled = focus is not None
        self._focus: Set[str] = set(focus or [])
        self._filters: Set[str] = set()
        self._ignore: Set[str] = set()
        self._whitelist: Set[str] = set()
        self._show_raw: bool = True
        self._show_debug: bool = True

        self._base = {
            "dump": self._dump,
            "focus_enabled": self._focus_enabled,
            "focus": set(self._focus),
            "filters": set(self._filters),
            "ignore": set(self._ignore),
            "whitelist": set(self._whitelist),
            "show_raw": self._show_raw,
            "show_debug": self._show_debug,
        }

        self._load_persisted()

    # ---------------------------- mutators ----------------------------
    def set_dump(self, value: bool) -> None:
        with self._lock:
            self._dump = bool(value)
            self._persist()

    def focus_on(self) -> None:
        with self._lock:
            self._focus_enabled = True
            self._persist()

    def focus_off(self) -> None:
        with self._lock:
            self._focus_enabled = False
            self._focus.clear()
            self._persist()

    def focus_add(self, opcode: str) -> None:
        with self._lock:
            self._focus_enabled = True
            self._focus.add(opcode)
            self._persist()

    def focus_rm(self, opcode: str) -> None:
        with self._lock:
            self._focus.discard(opcode)
            self._persist()

    def focus_clear(self) -> None:
        with self._lock:
            self._focus.clear()
            self._persist()

    def filter_add(self, pattern: str) -> None:
        with self._lock:
            self._filters.add(pattern)
            self._persist()

    def filter_remove(self, pattern: str) -> None:
        with self._lock:
            self._filters.discard(pattern)
            self._persist()

    def filter_clear(self) -> None:
        with self._lock:
            self._filters.clear()
            self._persist()

    def ignore_add(self, opcode: str) -> None:
        with self._lock:
            self._ignore.add(opcode)
            self._persist()

    def ignore_remove(self, opcode: str) -> None:
        with self._lock:
            self._ignore.discard(opcode)
            self._persist()

    def ignore_clear(self) -> None:
        with self._lock:
            self._ignore.clear()
            self._persist()

    def whitelist_add(self, opcode: str) -> None:
        with self._lock:
            self._whitelist.add(opcode)
            self._persist()

    def whitelist_remove(self, opcode: str) -> None:
        with self._lock:
            self._whitelist.discard(opcode)
            self._persist()

    def whitelist_clear(self) -> None:
        with self._lock:
            self._whitelist.clear()
            self._persist()

    def set_show_raw(self, value: bool) -> None:
        with self._lock:
            self._show_raw = bool(value)
            self._persist()

    def set_show_debug(self, value: bool) -> None:
        with self._lock:
            self._show_debug = bool(value)
            self._persist()

    def reset_defaults(self) -> None:
        """Restore initial constructor defaults and clear persisted file."""
        with self._lock:
            self._dump = self._base["dump"]
            self._focus_enabled = self._base["focus_enabled"]
            self._focus = set(self._base["focus"])
            self._filters = set(self._base["filters"])
            self._ignore = set(self._base["ignore"])
            self._whitelist = set(self._base["whitelist"])
            self._show_raw = self._base["show_raw"]
            self._show_debug = self._base.get("show_debug", True)
            try:
                if self.persist_path.exists():
                    self.persist_path.unlink()
            except Exception:
                pass
            self._persist()

    # ---------------------------- snapshots ----------------------------
    def snapshot(self) -> ControlSnapshot:
        with self._lock:
            focus = set(self._focus) if self._focus_enabled else None
            return ControlSnapshot(
                dump=self._dump,
                focus=focus,
                filters=set(self._filters) if self._filters else None,
                ignore=set(self._ignore),
                whitelist=set(self._whitelist),
                show_raw=self._show_raw,
                show_debug=self._show_debug,
            )

    def status_lines(self) -> list[str]:
        snap = self.snapshot()
        focus_desc = "off" if snap.focus is None else f"on ({', '.join(sorted(snap.focus)) or 'empty'})"
        filter_desc = "off" if not snap.filters else ", ".join(sorted(snap.filters))
        ignore_desc = ", ".join(sorted(snap.ignore)) if snap.ignore else "none"
        whitelist_desc = ", ".join(sorted(snap.whitelist)) if snap.whitelist else "inherit/config"
        return [
            f"dump: {'on' if snap.dump else 'off'}",
            f"focus: {focus_desc}",
            f"filter: {filter_desc}",
            f"ignore: {ignore_desc}",
            f"whitelist: {whitelist_desc}",
            f"raw: {'on' if snap.show_raw else 'off'}",
            f"debug: {'on' if snap.show_debug else 'off'}",
        ]

    # ---------------------------- helpers ----------------------------
    @staticmethod
    def matches_filters(name: str, filters: Optional[Set[str]]) -> bool:
        """
        Return True if name should be shown given filter patterns.
        If filters is None or empty → show all.
        Uses case-insensitive fnmatch-style patterns.
        """
        if not filters:
            return True
        name_up = str(name).upper()
        for pattern in filters:
            if fnmatch(name_up, pattern.upper()):
                return True
        return False

    # ---------------------------- persistence ----------------------------
    def _load_persisted(self) -> None:
        if not self.persist_path.exists():
            return
        try:
            data = yaml.safe_load(self.persist_path.read_text()) or {}
        except Exception:
            return
        with self._lock:
            self._dump = bool(data.get("dump", self._dump))
            focus = data.get("focus")
            self._focus_enabled = focus is not None
            self._focus = set(focus or [])
            self._filters = set(data.get("filters", []))
            self._ignore = set(data.get("ignore", []))
            self._whitelist = set(data.get("whitelist", []))
            self._show_raw = bool(data.get("show_raw", self._show_raw))
            self._show_debug = bool(data.get("show_debug", self._show_debug))

    def _persist(self) -> None:
        try:
            payload: Dict[str, Any] = {
                "dump": self._dump,
                "focus": list(self._focus) if self._focus_enabled else None,
                "filters": list(self._filters),
                "ignore": list(self._ignore),
                "whitelist": list(self._whitelist),
                "show_raw": self._show_raw,
                "show_debug": self._show_debug,
            }
            self.persist_path.parent.mkdir(parents=True, exist_ok=True)
            self.persist_path.write_text(yaml.safe_dump(payload, sort_keys=True))
        except Exception:
            # persistence is best-effort
            pass


__all__ = ["ControlState", "ControlSnapshot"]
