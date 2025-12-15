#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ast
import json
import os
from modules.Session import get_session
from utils.ConfigLoader import ConfigLoader
from utils.FileUtils import FileHandler
from utils.Logger import Logger
from utils.OpcodesFilter import filter_opcode

# GLOBALS
config = ConfigLoader.load_config()

def process_case(program: str, version: str, case: str, require_payload: bool = True) -> tuple[bool, list[str], bytes, object, object]:
    """
    Load and prepare a packet case for parsing and validation.
    """
    try:
        session = get_session()

        base_path = f"protocols/{program}/{version}"
        def_path = f"{base_path}/def/{case}.def"
        json_path = f"{base_path}/json/{case}.json"
        debug_path = f"{base_path}/debug/{case}.json"

        definition = FileHandler.load_file(def_path)
        debug = FileHandler.load_json_file(debug_path)
        binary_data = b""
        expected = {}

        if require_payload:
            try:
                binary_data = FileHandler.load_payload(program, version, case)
            except FileNotFoundError:
                if os.path.exists(json_path):
                    expected = FileHandler.load_json_file(json_path)
                if not expected:
                    binary_data = b""
                else:
                    raise
            else:
                if os.path.exists(json_path):
                    expected = FileHandler.load_json_file(json_path)
                else:
                    expected = {}

        session.version = version
        session.program = program
        return True, definition, binary_data, expected, debug

    except Exception as e:
        Logger.error(f"[{case}] Failed to process: {e}")
        # FIX: return 5 values instead of 4
        return False, [], b"", None, None


def load_case(program: str, version: str, case: str, require_payload: bool = True) -> tuple[str, list[str], bytes, object, object]:
    success, def_lines, binary_data, expected, debug = process_case(program, version, case, require_payload)

    if not success:
        raise FileNotFoundError(f"Case {case} could not be loaded.")
    
    return case, def_lines, binary_data, expected, debug


def load_all_cases(program: str, version: str, respect_ignored: bool = True) -> list[tuple[str, list[str], bytes, object, object]]:
    cases = FileHandler.list_def_files(program, version)
    loaded = []

    if not cases:
        Logger.error("No .def files found.")
        return []

    for case in cases:
        success, def_lines, binary_data, expected, debug = process_case(program, version, case)

        if not success:
            Logger.error(f"Skipping: {case}")
            continue

        opcode_name = case
        opcode_int = None

        if not filter_opcode(opcode_name, opcode_int, config):
            continue

        loaded.append((case, def_lines, binary_data, expected, debug))

    Logger.to_log('')

    return loaded


def handle_add(program: str, version: str, case: str, bin_data: str) -> bool:
    try:
        base_path = f"protocols/{program}/{version}"
        os.makedirs(f"{base_path}/def", exist_ok=True)
        os.makedirs(f"{base_path}/json", exist_ok=True)
        os.makedirs(f"{base_path}/debug", exist_ok=True)

        bin_data = bin_data.strip()
        if bin_data.startswith("b'") or bin_data.startswith('b"'):
            bin_bytes = ast.literal_eval(bin_data)
        elif os.path.exists(bin_data):
            with open(bin_data, "rb") as f:
                bin_bytes = f.read()
        else:
            raise ValueError("Invalid --bin input: must be bytes literal or valid file path.")

        open(f"{base_path}/def/{case}.def", "w", encoding="utf-8").close()
        with open(f"{base_path}/json/{case}.json", "w", encoding="utf-8") as jf:
            json.dump({}, jf, indent=2)
        with open(f"{base_path}/debug/{case}.json", "w", encoding="utf-8") as dbg:
            json.dump(
                {
                    "name": case,
                    "hex_compact": bin_bytes.hex().upper(),
                    "hex_spaced": " ".join(f"{b:02X}" for b in bin_bytes),
                },
                dbg,
                indent=2,
            )

        Logger.info(f"Created new packet files for {case}")
        return True

    except Exception as e:
        Logger.error(f"Failed to add new packet: {e}")
        return False