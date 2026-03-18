#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Packet definition loading helpers for the DSL runtime."""

from __future__ import annotations

import ast
import json
from typing import Any
from pathlib import Path

from DSL.modules.Session import get_session
from shared.FileUtils import FileHandler
from shared.Logger import Logger
from shared.PathUtils import get_debug_root, get_def_root, get_json_root


# ------------------------------------------------------------------
# PATH HELPERS (CONFIG-DRIVEN)
# ------------------------------------------------------------------

def _get_data_root() -> Path:
    return get_def_root().parent


def _get_def_path(case: str) -> Path:
    return get_def_root() / f"{case}.def"


def _get_json_path(case: str) -> Path:
    return get_json_root() / f"{case}.json"


def _get_debug_path(case: str) -> Path:
    return get_debug_root() / f"{case}.json"


# ------------------------------------------------------------------
# CORE LOADERS
# ------------------------------------------------------------------

def process_case(
    program: str,
    version: str,
    case: str,
    require_payload: bool = True,
    expansion: str | None = None,
) -> tuple[bool, list[str], bytes, dict[str, Any] | None, dict[str, Any] | None]:
    """
    Load and prepare a packet case.

    NOTE:
    - No directory creation here (read-only)
    - Paths are config-driven
    """
    try:
        session = get_session()

        def_path = _get_def_path(case)
        json_path = _get_json_path(case)
        debug_path = _get_debug_path(case)

        # ---- DEF ----------------------------------------------------
        if not def_path.exists():
            raise FileNotFoundError(def_path)

        definition = FileHandler.load_file(str(def_path))

        # ---- DEBUG --------------------------------------------------
        debug = {}
        if debug_path.exists():
            debug = FileHandler.load_json_file(str(debug_path))

        # ---- PAYLOAD + EXPECTED ------------------------------------
        binary_data = b""
        expected = {}

        if require_payload:
            try:
                binary_data = FileHandler.load_payload(
                    program,
                    version,
                    case,
                    expansion=expansion,
                )
            except FileNotFoundError:
                if json_path.exists():
                    expected = FileHandler.load_json_file(str(json_path))
                else:
                    binary_data = b""
            else:
                if json_path.exists():
                    expected = FileHandler.load_json_file(str(json_path))

        # ---- SESSION -----------------------------------------------
        session.version = version
        session.program = program
        session.expansion = expansion

        return True, definition, binary_data, expected, debug

    except Exception as e:
        Logger.error(f"[{case}] Failed to process: {e}")
        return False, [], b"", None, None


def load_case(
    program: str,
    version: str,
    case: str,
    require_payload: bool = True,
    expansion: str | None = None,
) -> tuple[str, list[str], bytes, dict[str, Any] | None, dict[str, Any] | None]:
    """Load a single case and raise if missing."""
    success, def_lines, binary_data, expected, debug = process_case(
        program,
        version,
        case,
        require_payload,
        expansion=expansion,
    )

    if not success:
        raise FileNotFoundError(f"Case {case} could not be loaded.")

    return case, def_lines, binary_data, expected, debug


# ------------------------------------------------------------------
# BULK LOADER (ALREADY CLEAN)
# ------------------------------------------------------------------

def load_all_cases(
    def_dir: Path | None = None,
    json_dir: Path | None = None,
    debug_dir: Path | None = None,
    respect_ignored: bool = True,
):
    """Load all cases from explicit directories."""

    def_dir = Path(def_dir) if def_dir is not None else get_def_root()
    json_dir = Path(json_dir) if json_dir is not None else get_json_root()
    debug_dir = Path(debug_dir) if debug_dir is not None else get_debug_root()

    loaded = []

    if not def_dir.exists():
        Logger.error(f"DEF dir not found: {def_dir}")
        return []

    cases = sorted(p.stem for p in def_dir.glob("*.def"))

    if not cases:
        Logger.error("No .def files found.")
        return []

    for case in cases:
        def_path = def_dir / f"{case}.def"
        json_path = json_dir / f"{case}.json"
        debug_path = debug_dir / f"{case}.json" if debug_dir else None

        try:
            def_lines = FileHandler.load_file(str(def_path))
        except Exception as exc:
            Logger.error(f"[DEF LOAD FAIL] {case}: {exc}")
            continue

        expected = {}
        if json_path.exists():
            try:
                expected = FileHandler.load_json_file(str(json_path))
            except Exception as exc:
                Logger.error(f"[JSON LOAD FAIL] {case}: {exc}")

        debug = None
        if debug_path and debug_path.exists():
            try:
                debug = FileHandler.load_json_file(str(debug_path))
            except Exception:
                pass

        loaded.append((case, def_lines, b"", expected, debug))

    Logger.to_log("")
    return loaded


# ------------------------------------------------------------------
# DEV TOOL (EXPLICIT FILE CREATION)
# ------------------------------------------------------------------

def handle_add(
    program: str,
    version: str,
    case: str,
    bin_data: str,
    expansion: str | None = None,
) -> bool:
    """
    Create new packet files.

    NOTE:
    - Only place where directories are created
    - Uses config paths
    """
    try:
        def_dir = get_def_root()
        json_dir = get_json_root()
        debug_dir = get_debug_root()

        # Explicit creation (safe)
        def_dir.mkdir(parents=True, exist_ok=True)
        json_dir.mkdir(parents=True, exist_ok=True)
        debug_dir.mkdir(parents=True, exist_ok=True)

        # ---- Parse payload ----------------------------------------
        bin_data = bin_data.strip()

        if bin_data.startswith(("b'", 'b"')):
            bin_bytes = ast.literal_eval(bin_data)
        elif Path(bin_data).exists():
            bin_bytes = Path(bin_data).read_bytes()
        else:
            raise ValueError("Invalid --bin input")

        # ---- Create files -----------------------------------------
        (def_dir / f"{case}.def").touch()

        (json_dir / f"{case}.json").write_text(
            json.dumps({}, indent=2),
            encoding="utf-8",
        )

        (debug_dir / f"{case}.json").write_text(
            json.dumps(
                {
                    "name": case,
                    "hex_compact": bin_bytes.hex().upper(),
                    "hex_spaced": " ".join(f"{b:02X}" for b in bin_bytes),
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        Logger.info(f"Created new packet files for {case}")
        return True

    except Exception as e:
        Logger.error(f"Failed to add new packet: {e}")
        return False
