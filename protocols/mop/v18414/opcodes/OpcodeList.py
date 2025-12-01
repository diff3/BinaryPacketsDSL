#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import pathlib
import re

BASE = pathlib.Path(__file__).parent / "mop" / "18414"

def load_def_files():
    opcode_to_name = {}
    name_to_opcode = {}

    for f in BASE.glob("*.def"):
        text = f.read_text()

        # Extract fields inside the .def file
        op_match = re.search(r"opcode:\s*(0x[0-9A-Fa-f]+|\d+)", text)
        name_match = re.search(r"name:\s*([A-Za-z0-9_]+)", text)
        dir_match = re.search(r"direction:\s*(client|server)", text)

        if not op_match or not name_match or not dir_match:
            continue

        opcode_raw = op_match.group(1)
        opcode = int(opcode_raw, 16) if opcode_raw.startswith("0x") else int(opcode_raw)

        base_name = name_match.group(1)
        direction = dir_match.group(1)

        # Build final name
        suffix = "_C" if direction == "client" else "_S"
        full_name = f"{base_name}{suffix}"

        opcode_to_name[opcode] = full_name
        name_to_opcode[full_name] = opcode

    return opcode_to_name, name_to_opcode


OPCODE_TO_NAME, NAME_TO_OPCODE = load_def_files()