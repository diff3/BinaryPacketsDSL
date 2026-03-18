#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
from shared.ConfigLoader import ConfigLoader
from shared.PathUtils import get_def_root
try:
    import argcomplete
except ImportError:
    argcomplete = None

# GLOBALS
config = ConfigLoader.get_config()

class DefFileNameCompleter:
    def __call__(self, prefix, parsed_args, **kwargs):
        base_path = get_def_root()
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
    parser.add_argument("-P", "--promote", action="store_true", help="In focus mode, promote decoded output into runtime expected JSON")
    parser.add_argument(
        "-f",
        "--file",
        type=str,
        help="Specify the packet file name (without extension) or a focus capture .json filename",
    ).completer = DefFileNameCompleter()
    parser.add_argument("-p", "--program", type=str, help="Program/game name (e.g., wow)")
    parser.add_argument("-e", "--expansion", type=str, help="Expansion name (e.g., vanilla, mop)")
    parser.add_argument("-V", "--version", type=str, help="Expansion version (e.g., v1121, v18414)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging output")
    parser.add_argument("-b", "--bin", type=str, help="Path to binary file to add")
    parser.add_argument("-s", "--silent", action="store_true", help="Run silently (no logs)")
    parser.add_argument(
        "--focus",
        action="store_true",
        help="Use focus captures from the configured capture directory",
    )

    if argcomplete is not None:
        argcomplete.autocomplete(parser)
    return parser.parse_args()
