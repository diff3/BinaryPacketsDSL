#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Promote captured packets into protocols/<program>/<version>."""

import os
import shutil
from pathlib import Path
from typing import List, Tuple

from utils.ConfigLoader import ConfigLoader

TEMPLATE_DEF = """endian: little
header:
data:
"""


def _base_paths(opcode: str):
    cfg = ConfigLoader.load_config()
    program = cfg["program"]
    version = cfg["version"]

    base = Path("protocols") / program / version

    live_json = base / "json" / f"{opcode}.json"
    live_dbg = base / "debug" / f"{opcode}.json"
    live_def = base / "def" / f"{opcode}.def"

    cap_dir = Path("misc/captures")
    src_json = cap_dir / "json" / f"{opcode}.json"
    src_dbg = cap_dir / "debug" / f"{opcode}.json"

    return live_json, live_dbg, live_def, src_json, src_dbg


def promote_opcode(opcode: str) -> List[str]:
    """Copy capture artifacts into protocols and create a def stub if missing."""
    live_json, live_dbg, live_def, src_json, src_dbg = _base_paths(opcode)

    lines: List[str] = []

    if not src_dbg.exists():
        return [f"missing capture: {src_dbg}"]

    for target in (live_json, live_dbg, live_def):
        target.parent.mkdir(parents=True, exist_ok=True)

    if src_json.exists():
        shutil.copy(src_json, live_json)
        lines.append(f"promoted json → {live_json}")
    else:
        lines.append(f"no json capture, skipped {live_json}")

    shutil.copy(src_dbg, live_dbg)
    lines.append(f"promoted debug → {live_dbg}")

    if not live_def.exists():
        live_def.write_text(TEMPLATE_DEF)
        lines.append(f"created def stub → {live_def}")
    else:
        lines.append(f"def exists, skipped {live_def}")

    return lines


def delete_opcode(opcode: str) -> List[str]:
    """Delete promoted artifacts for an opcode."""
    live_json, live_dbg, live_def, _, _ = _base_paths(opcode)
    removed = 0
    lines: List[str] = []
    for path in (live_json, live_dbg, live_def):
        if path.exists():
            path.unlink()
            removed += 1
            lines.append(f"removed {path}")
        else:
            lines.append(f"not found: {path}")
    if removed == 0:
        lines.append("no files removed")
    return lines


def sync_done() -> List[str]:
    """
    Remove capture files for opcodes whose DEF starts with 'done'
    (compat with tools/promote_capture.py --sync).
    """
    cfg = ConfigLoader.load_config()
    program = cfg["program"]
    version = cfg["version"]
    base = Path("protocols") / program / version
    def_dir = base / "def"
    if not def_dir.is_dir():
        return [f"def dir missing: {def_dir}"]

    done_ops = set()
    for path in def_dir.glob("*.def"):
        try:
            first = path.read_text(errors="ignore").splitlines()
        except OSError:
            continue
        if first and "done" in first[0].lower():
            done_ops.add(path.stem)

    if not done_ops:
        return ["no DEF files marked as done"]

    cap_dir = Path("misc/captures")
    removed = 0
    for opcode in sorted(done_ops):
        for rel in (f"json/{opcode}.json", f"debug/{opcode}.json", f"bin/{opcode}.bin"):
            p = cap_dir / rel
            if p.exists():
                p.unlink()
                removed += 1
    return [f"sync complete, removed {removed} capture files"] if removed else ["no capture files removed"]


def list_protocols(limit: int = 200, search: str | None = None) -> List[str]:
    """List promoted opcodes (DEF files) under protocols. Optional case-insensitive substring search."""
    cfg = ConfigLoader.load_config()
    base = Path("protocols") / cfg["program"] / cfg["version"] / "def"
    if not base.is_dir():
        return [f"def dir missing: {base}"]
    items = sorted(p.stem for p in base.glob("*.def"))
    if search:
        s = search.lower()
        items = [i for i in items if s in i.lower()]
    if not items:
        return ["no protocols found"]
    head = items[:limit]
    suffix = [] if len(items) <= limit else [f"... ({len(items) - limit} more)"]
    header = f"{len(items)} protocol(s)" + (f" matching '{search}'" if search else "") + ":"
    return [header] + [f" - {name}" for name in head] + suffix


def _artifact_path(kind: str, name: str) -> Tuple[Path, str]:
    cfg = ConfigLoader.load_config()
    base = Path("protocols") / cfg["program"] / cfg["version"]
    kind = kind.lower()
    if kind == "def":
        return base / "def" / f"{name}.def", "DEF"
    if kind == "debug":
        return base / "debug" / f"{name}.json", "debug JSON"
    if kind == "json":
        return base / "json" / f"{name}.json", "payload JSON"
    raise ValueError("kind must be def|debug|json")


def view_protocol(kind: str, name: str, max_bytes: int = 65536) -> List[str]:
    """Return file content for a specific artifact, truncated if large."""
    path, label = _artifact_path(kind, name)
    if not path.exists():
        return [f"not found: {path}"]
    size = path.stat().st_size
    if size > max_bytes:
        return [f"{label} too large to display ({size} bytes): {path}"]
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [f"error reading {path}: {exc}"]
    return [f"{label}: {path}", text]


__all__ = [
    "promote_opcode",
    "delete_opcode",
    "sync_done",
    "list_protocols",
    "view_protocol",
]
