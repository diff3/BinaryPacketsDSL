#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ast
import json
import os
from modules.Session import get_session
from utils.ConfigLoader import ConfigLoader
from utils.FileUtils import FileHandler
from utils.Logger import Logger

# GLOBALS
config = ConfigLoader.load_config()
ignored = config.get("IgnoredCases", [])



def process_case(program: str, version: str, case: str) -> tuple[bool, list[str], bytes, object]:
    """
    Load and prepare a packet case for parsing and validation.

    This function reads the .def, .bin, and .json files for the specified case,
    and stores binary data and metadata in the session. It returns the loaded
    definition, binary data, and expected result for further processing.

    Parameters:
        program (str): The short program identifier (e.g. 'mop')
        version (str): The version string (e.g. '18414')
        case (str): The case name (e.g. 'login')

    Returns:
        Tuple[bool, List[str], bytes, Any]: (success flag, .def lines, .bin data, .json expected result)
    """
    try:
        session = get_session()

        base_path = f"packets/{program}/{version}"
        def_path = f"{base_path}/def/{case}.def"
        bin_path = f"{base_path}/bin/{case}.bin"
        json_path = f"{base_path}/json/{case}.json"

        definition = FileHandler.load_file(def_path)
        binary_data = FileHandler.load_bin_file(bin_path)
        expected = FileHandler.load_json_file(json_path)

        # session.raw_data = binary_data
        session.version = version
        session.program = program
        return True, definition, binary_data, expected
    except Exception as e:
        Logger.error(f"[{case}] Failed to process: {e}")
        return False, [], b"", None

def load_case(program: str, version: str, case: str) -> tuple[str, list[str], bytes, object]:
    """
    Load a single packet case from .def, .bin, and .json files.

    Parameters:
        program (str): Program identifier (e.g., 'mop')
        version (str): Version string (e.g., '18414')
        case (str): Case name without file extension (e.g., 'SMSG_AUTH_CHALLENGE')

    Returns:
        Tuple[str, List[str], bytes, Any]: Case name, .def lines, binary data, expected JSON output

    Raises:
        FileNotFoundError: If the case could not be loaded
    """
    success, def_lines, binary_data, expected = process_case(program, version, case)

    if not success:
        raise FileNotFoundError(f"Case {case} could not be loaded.")
    
    return case, def_lines, binary_data, expected

def load_all_cases(program: str, version: str) -> list[tuple[str, list[str], bytes, object]]:
    """
    Load all available packet cases for the given program and version.

    Parameters:
        program (str): Program identifier (e.g., 'mop')
        version (str): Version string (e.g., '18414')

    Returns:
        List[Tuple[str, List[str], bytes, Any]]: A list of successfully loaded cases.
        Each entry contains: case name, .def lines, binary data, expected JSON output.
    """
    cases = FileHandler.list_def_files(program, version)
    loaded = []

    if not cases:
        Logger.error("No .def files found.")
        return []

    for case in cases:
        success, def_lines, binary_data, expected = process_case(program, version, case)

        if not success:
            Logger.error(f"Skipping: {case}")
            continue

        if case in ignored:
            Logger.warning(f"[{case.upper()}] Skipped (ignored in config)")
            continue

        loaded.append((case, def_lines, binary_data, expected))
    
    Logger.to_log('')

    return loaded

def handle_add(program: str, version: str, case: str, bin_data: str) -> bool:
    """
    Add a new packet definition set with given binary data.

    Parameters:
        program (str): Program identifier (e.g. 'mop')
        version (str): Version string (e.g. '18414')
        case (str): Packet case name
        bin_data (str): Binary data, either as b'...' string or path to file

    Returns:
        bool: True if creation succeeded, False otherwise
    """
    try:
        base_path = f"packets/{program}/{version}"
        os.makedirs(f"{base_path}/bin", exist_ok=True)
        os.makedirs(f"{base_path}/def", exist_ok=True)
        os.makedirs(f"{base_path}/json", exist_ok=True)

        # Försök tolka bin_data som bytes literal eller filepath
        bin_data = bin_data.strip()
        if bin_data.startswith("b'") or bin_data.startswith('b"'):
            bin_bytes = ast.literal_eval(bin_data)
        elif os.path.exists(bin_data):
            with open(bin_data, "rb") as f:
                bin_bytes = f.read()
        else:
            raise ValueError("Invalid --bin input: must be bytes literal or valid file path.")

        # Skriv binärfil
        with open(f"{base_path}/bin/{case}.bin", "wb") as bf:
            bf.write(bin_bytes)

        # Skapa tom .def och .json
        open(f"{base_path}/def/{case}.def", "w", encoding="utf-8").close()
        with open(f"{base_path}/json/{case}.json", "w", encoding="utf-8") as jf:
            json.dump({}, jf, indent=2)

        Logger.info(f"Created new packet files for {case}")
        return True

    except Exception as e:
        Logger.error(f"Failed to add new packet: {e}")
        return False

    