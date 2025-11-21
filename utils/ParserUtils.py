#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from modules.ModifierParser import ModifierUtils
from utils.Logger import Logger

class ParserUtils:

    @staticmethod
    def remove_comments_and_reserved(struct_definition: list[str]) -> list[str]:
        """
        Removes comments (single and multi-line) and reserved sections ('header:', 'data:') 
        from the provided structure definition.
        """
        new_list = []
        i = 0

        while i < len(struct_definition):
            line = struct_definition[i].strip()

            if line.startswith('#-'):
                while i < len(struct_definition) and not struct_definition[i].strip().endswith("-#"):
                    i += 1
                i += 1
                continue
            elif line.startswith('#'):
                i += 1
                continue
            elif '#' in line:
                line = line.split('#', 1)[0].strip()
                if line:
                    new_list.append(line)
                i += 1
                continue
            elif line.startswith("header:") or line.startswith("data:") or line.startswith("variables:") or not line:
                i += 1
                continue
            else:
                new_list.append(struct_definition[i])
                i += 1

        return new_list


    @staticmethod
    def count_size_of_block_structure(lines: list[str], i: int) -> list:
        """
        Given a list of lines and a starting index, this function returns the number of 
        indented lines and the list of those lines within the block.
        """
        block_lines = []
        leading_spaces = len(re.match(r"^\s*", lines[i])[0])

        i += 1
        ant = 0

        while i < len(lines):
            # line = lines[i]
            # line_content = line.strip()
            line_content = lines[i]


            if not line_content:
                break

            if len(re.match(r"^\s*", line_content)[0]) <= leading_spaces:
                break

            block_lines.append(line_content)
            ant += 1
            i += 1

        return [ant, block_lines]

    @staticmethod
    def split_field_definition(line: str) -> tuple[str, str, list] | None:
        """
        Smart splitting of a line into (name, format, modifiers).
        Supports ':' for struct fields and '=' for variable definitions.
        """
        try:
            if not isinstance(line, str):
                raise TypeError(f"Expected str for line, got {type(line)}")

            line = line.strip()

            if not line:
                raise ValueError("Cannot parse empty line.")

            if "bits" in line:
                # special bits field
                name, rest = [x.strip() for x in line.split(":", 1)]
                # plocka ut typen "bits"
                _, rest2 = rest.split("bits", 1)  # tar bort 'bits'
                rest2 = rest2.lstrip(" ,")        # tar bort komma/space

                fmt = "bits"
                mods = [m.strip() for m in rest2.split(",") if m.strip()]
                return name, fmt, mods
            elif ":" in line:
                # Normal struct field
                name, rest = [x.strip() for x in line.split(":", 1)]
            elif "=" in line:
                # Variable
                name, rest = [x.strip() for x in line.split("=", 1)]
            else:
                raise ValueError(f"Missing ':' or '=' in field definition: '{line}'")

            fmt, mods = ModifierUtils.parse_modifiers(rest)
            return name, fmt, mods

        except Exception as e:
            Logger.warning(f"Failed to parse line: '{line}' - {str(e)}")
            return None

    @staticmethod
    def check_ignore_and_rename(name: str, anon_counter: int) -> tuple[str, bool, int]:
        """
        Check if a field should be ignored (name begins with underscore) and rename if needed.

        Args:
            name (str): The original field name.
            anon_counter (int): The current counter for anonymous fields.

        Returns:
            tuple: (updated_name, ignore_flag, updated_anon_counter)
        """
        cleaned = name.strip()
        if cleaned == "_" or re.match(r"^_t\d*$", cleaned, re.IGNORECASE):
            new_name = f"__anon_{anon_counter}"
            return new_name, True, anon_counter + 1
        return name, False, anon_counter

    @staticmethod
    def is_ignored_field(name: str) -> bool:
        """
        Checks if a field should be ignored (fields starting with underscore).
        """
        return name.strip().startswith("_")
