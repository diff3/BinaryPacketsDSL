#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os


class FileHandler():
    """
    Utility class for loading and listing packet-related files.

    Supports reading .def, .bin, and .json files, as well as listing available cases.
    Intended for use in both CLI and automated processing.
    """
    
    @staticmethod
    def load_file(file_path:str) -> str:
        with open(file_path, "r") as file:
            return file.readlines()

    @staticmethod
    def load_bin_file(file_path:str) -> str:
        with open(file_path, "rb") as file:
            return file.read()

    @staticmethod
    def load_json_file(file_path:str) -> dict:
        with open(file_path, "r") as file:
            return json.load(file)

    @staticmethod
    def load_payload(program: str, version: str, case: str) -> bytes:
        """
        Load payload bytes for a case.
        Requires debug json; raises if missing.
        """
        debug_path = f"protocols/{program}/{version}/debug/{case}.json"

        if os.path.exists(debug_path):
            data = FileHandler.load_json_file(debug_path)
            header_mode = data.get("header_mode")

            # Auth 1-byte headers: def förväntar opcode i payload, så använd full raw_data_hex om den finns.
            if header_mode == "auth1b":
                raw_full = data.get("raw_data_hex")
                if raw_full:
                    return bytes.fromhex(raw_full.replace(" ", ""))

                # Fallback: kombinera header + payload
                raw_header = data.get("raw_header_hex", "")
                payload_hex = data.get("hex_compact") or data.get("hex_spaced") or ""
                hex_full = raw_header.replace(" ", "") + payload_hex.replace(" ", "")
                if hex_full:
                    return bytes.fromhex(hex_full)

            hex_payload = data.get("hex_compact") or data.get("hex_spaced")
            if hex_payload:
                hex_payload = hex_payload.replace(" ", "")
                return bytes.fromhex(hex_payload)

        raise FileNotFoundError(f"Debug payload not found for {case}")

    @staticmethod
    def list_def_files(program: str, version: str) -> list[str]:
        folder = f"protocols/{program}/{version}/def"
        if not os.path.exists(folder):
            return []

        return sorted([
            f.replace(".def", "")
            for f in os.listdir(folder)
            if f.endswith(".def")
        ])
