#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
from utils.ConfigLoader import ConfigLoader
try:
    import argcomplete
except ImportError:
    argcomplete = None
from pathlib import Path

# GLOBALS
config = ConfigLoader.get_config()

class DefFileNameCompleter:
    def __call__(self, prefix, parsed_args, **kwargs):
        program = parsed_args.program or config.get("program")
        version = parsed_args.version or config.get("version")
        base_path = Path(f"protocols/{program}/{version}/def")
        if not base_path.is_dir():
            return []
        return [
            f.stem for f in base_path.glob(f"{prefix}*")
            if f.is_file()
        ]

def parse_args():
    parser = argparse.ArgumentParser(description="BinaryPacketsDSL CLI")
    parser.add_argument("-u", "--update", action="store_true", help="Update .json output from .bin + .def")
    parser.add_argument("-a", "--add", action="store_true", help="Create new empty packet definition set")
    parser.add_argument("-P", "--promote", action="store_true", help="In focus mode, promote decoded output into protocols expected JSON")
    parser.add_argument("-f", "--file", type=str, help="Specify the packet file name (without extension)").completer = DefFileNameCompleter()
    parser.add_argument("-p", "--program", type=str, help="Program name")
    parser.add_argument("-V", "--version", type=str, help="Program version")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging output")
    parser.add_argument("-b", "--bin", type=str, help="Path to binary file to add")
    parser.add_argument("-s", "--silent", action="store_true", help="Run silently (no logs)")
    parser.add_argument("--focus", action="store_true", help="Use focus captures (misc/captures/focus)")

    if argcomplete is not None:
        argcomplete.autocomplete(parser)
    return parser.parse_args()
