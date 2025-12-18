#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Thread-safe shared control state for the proxy."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from fnmatch import fnmatch
from typing import Optional, Set


@dataclass(frozen=True)
class ControlSnapshot:
    dump: bool
    update: bool
    focus: Optional[Set[str]]
    filters: Optional[Set[str]]


class ControlState:
    """Mutable shared state guarded by a re-entrant lock."""

    def __init__(self, *, dump: bool = False, update: bool = False, focus: Optional[Set[str]] = None) -> None:
        self._lock = threading.RLock()
        self._dump = bool(dump)
        self._update = bool(update)
        # focus_enabled distinguishes between "no focus filter" (None) and an empty list of allowed opcodes.
        self._focus_enabled = focus is not None
        self._focus: Set[str] = set(focus or [])
        self._filters: Set[str] = set()

    # ---------------------------- mutators ----------------------------
    def set_dump(self, value: bool) -> None:
        with self._lock:
            self._dump = bool(value)

    def set_update(self, value: bool) -> None:
        with self._lock:
            self._update = bool(value)

    def focus_on(self) -> None:
        with self._lock:
            self._focus_enabled = True

    def focus_off(self) -> None:
        with self._lock:
            self._focus_enabled = False
            self._focus.clear()

    def focus_add(self, opcode: str) -> None:
        with self._lock:
            self._focus_enabled = True
            self._focus.add(opcode)

    def focus_rm(self, opcode: str) -> None:
        with self._lock:
            self._focus.discard(opcode)

    def focus_clear(self) -> None:
        with self._lock:
            self._focus.clear()

    def filter_add(self, pattern: str) -> None:
        with self._lock:
            self._filters.add(pattern)

    def filter_remove(self, pattern: str) -> None:
        with self._lock:
            self._filters.discard(pattern)

    def filter_clear(self) -> None:
        with self._lock:
            self._filters.clear()

    # ---------------------------- snapshots ----------------------------
    def snapshot(self) -> ControlSnapshot:
        with self._lock:
            focus = set(self._focus) if self._focus_enabled else None
            return ControlSnapshot(
                dump=self._dump,
                update=self._update,
                focus=focus,
                filters=set(self._filters) if self._filters else None,
            )

    def status_lines(self) -> list[str]:
        snap = self.snapshot()
        focus_desc = "off" if snap.focus is None else f"on ({', '.join(sorted(snap.focus)) or 'empty'})"
        filter_desc = "off" if not snap.filters else ", ".join(sorted(snap.filters))
        return [
            f"dump: {'on' if snap.dump else 'off'}",
            f"update: {'on' if snap.update else 'off'}",
            f"focus: {focus_desc}",
            f"filter: {filter_desc}",
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


__all__ = ["ControlState", "ControlSnapshot"]
