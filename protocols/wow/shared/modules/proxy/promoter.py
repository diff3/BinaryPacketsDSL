#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Promote captured packets into protocols/<program>/<expansion>/<version>."""

import shutil
from pathlib import Path
from typing import List, Tuple

from utils.ConfigLoader import ConfigLoader
from utils.PathUtils import get_captures_root

TEMPLATE_DEF = """endian: little
header:
data:
"""


def _base_paths(opcode: str, cap_root: Path | str | None = None):
    cfg = ConfigLoader.load_config()
    program = cfg["program"]
    expansion = cfg.get("expansion")
    version = cfg["version"]

    base = Path("protocols") / program / expansion / version / "data"

    live_json = base / "json" / f"{opcode}.json"
    live_dbg = base / "debug" / f"{opcode}.json"
    live_def = base / "def" / f"{opcode}.def"

    cap_dir = Path(cap_root) if cap_root is not None else get_captures_root()
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


def promote_focus_opcode(opcode: str) -> List[str]:
    """Copy focus capture artifacts into protocols/data and create a def stub if missing."""

    src_opcode = opcode

    # Strip trailing _<digits> ONLY for destination
    parts = opcode.rsplit("_", 1)
    if len(parts) == 2 and parts[1].isdigit():
        dst_opcode = parts[0]
    else:
        dst_opcode = opcode

    live_json, live_dbg, live_def, _, _ = _base_paths(
        dst_opcode, cap_root=get_captures_root(focus=True)
    )

    _, src_dbg, _, src_json, _ = _base_paths(
        src_opcode, cap_root=get_captures_root(focus=True)
    )

    lines: List[str] = []

    if not src_dbg.exists():
        return [f"missing focus capture: {src_dbg}"]

    for target in (live_json, live_dbg, live_def):
        target.parent.mkdir(parents=True, exist_ok=True)

    if src_json.exists():
        shutil.copy(src_json, live_json)
        lines.append(f"promoted focus json → {live_json}")
    else:
        lines.append(f"no focus json, skipped {live_json}")

    shutil.copy(src_dbg, live_dbg)
    lines.append(f"promoted focus debug → {live_dbg}")

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
    expansion = cfg.get("expansion")
    version = cfg["version"]
    base = Path("protocols") / program / expansion / version
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

    cap_dir = get_captures_root()
    removed = 0
    for opcode in sorted(done_ops):
        for rel in (f"json/{opcode}.json", f"debug/{opcode}.json"):
            p = cap_dir / rel
            if p.exists():
                p.unlink()
                removed += 1
    return [f"sync complete, removed {removed} capture files"] if removed else ["no capture files removed"]


def sync_protocols_from_captures() -> List[str]:
    """
    For each protocol debug file, if a capture exists, copy capture debug/json into protocols.
    Intended to refresh expected results from latest captures.
    """
    lines: List[str] = []
    try:
        cfg = ConfigLoader.load_config()
        program = cfg["program"]
        expansion = cfg.get("expansion")
        version = cfg["version"]
    except Exception as exc:
        return [f"config error: {exc}"]

    base = Path("protocols") / program / expansion / version / "data"
    proto_debug = base / "debug"
    proto_json = base / "json"

    cap_debug = get_captures_root() / "debug"
    cap_json = get_captures_root() / "json"

    if not proto_debug.is_dir():
        return [f"protocol debug dir missing: {proto_debug}"]

    updated = 0
    for dbg_file in proto_debug.glob("*.json"):
        name = dbg_file.stem
        src_dbg = cap_debug / f"{name}.json"
        src_json = cap_json / f"{name}.json"

        if not src_dbg.exists():
            lines.append(f"[SKIP] no capture for {name}")
            continue

        try:
            dbg_file.write_bytes(src_dbg.read_bytes())
            updated += 1
            lines.append(f"[OK] synced debug for {name}")
        except Exception as exc:
            lines.append(f"[ERR] {name}: {exc}")
            continue

        if src_json.exists():
            try:
                (proto_json / f"{name}.json").write_bytes(src_json.read_bytes())
                lines.append(f"[OK] synced json for {name}")
            except Exception as exc:
                lines.append(f"[ERR] json {name}: {exc}")
        else:
            lines.append(f"[SKIP] no capture json for {name}")

    if updated == 0:
        lines.append("no protocol files were updated (no matching captures)")
    else:
        lines.append(f"sync complete, updated {updated} protocol debug file(s)")
    return lines


def delete_all_captures() -> List[str]:
    """
    Delete the protocol capture directory and recreate empty structure.
    """
    root = get_captures_root()
    if not root.exists():
        return [f"{root} not found"]

    try:
        import shutil

        shutil.rmtree(root)
    except Exception as exc:
        return [f"failed to remove {root}: {exc}"]

    try:
        for sub in ("debug", "json", "focus"):
            (root / sub).mkdir(parents=True, exist_ok=True)
        return [f"removed and recreated {root}"]
    except Exception as exc:
        return [f"removed {root} but failed to recreate structure: {exc}"]


def list_protocols(limit: int = 200, search: str | None = None) -> List[str]:
    """List promoted opcodes (DEF files) under protocols. Optional case-insensitive substring search."""
    cfg = ConfigLoader.load_config()
    base = Path("protocols") / cfg["program"] / cfg.get("expansion") / cfg["version"] / "data" / "def"
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
    base = Path("protocols") / cfg["program"] / cfg.get("expansion") / cfg["version"] / "data"
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
    "promote_focus_opcode",
    "delete_opcode",
    "sync_done",
    "sync_protocols_from_captures",
    "delete_all_captures",
    "list_protocols",
    "view_protocol",
]
