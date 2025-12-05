#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from modules.Session import BaseNode, IfNode, VariableNode, LoopNode, BlockDefinition, RandSeqNode,  get_session, PaddingNode, SeekNode, BitmaskNode, UncompressNode, PackedGuidNode

from modules.ModifierParser import ModifierUtils
from utils.ParserUtils import ParserUtils
from utils.Logger import Logger

session = get_session()
parse_warnings = []


class NodeTreeParser:
    @staticmethod
    def parse(case: tuple) -> list:
        """
        Parses a list of lines into a list of BaseNode/LoopNode/etc.
        """

        lines = case[1]

        nodes = []
        session.fields = []
        session.blocks = {}
        session.variables = {}
        anon_counter = 0

        lines = ParserUtils.remove_comments_and_reserved(lines)
        i = 0

        while i < len(lines):
            line = lines[i]

            # --- Block ---
            if line.strip().startswith("block"):
                parsed_node, consumed = NodeTreeParser.parse_block(session, lines, i, anon_counter)

                if isinstance(parsed_node, VariableNode):
                    session.variables[parsed_node.name] = parsed_node
                else:
                    session.blocks[parsed_node.name] = parsed_node

                i += consumed
                continue

            # --- Loop ---
            if line.strip().startswith("loop"):
                parsed_node, consumed = NodeTreeParser.parse_loop(session, lines, i, anon_counter)

                if parsed_node:
                    if isinstance(parsed_node, VariableNode):
                        session.variables[parsed_node.name] = parsed_node
                    else:
                        nodes.append(parsed_node)
                    i += consumed
                    continue
            
            # --- Randseq bits ---
            if line.strip().startswith("randseq_bits"):
                parsed_node, consumed = NodeTreeParser.parse_randseq_bits(session, lines, i, anon_counter)
                if parsed_node:
                    nodes.append(parsed_node)
                i += consumed
                continue

            # --- Randseq ---
            if line.strip().startswith("randseq"):
                parsed_node, consumed = NodeTreeParser.parse_randseq(session, lines, i, anon_counter)
                if parsed_node:
                    nodes.append(parsed_node)
                i += consumed
                continue

            if line.strip().startswith("uncompress"):
                parsed_node, consumed = NodeTreeParser.parse_uncompress(lines, i, anon_counter)
                if parsed_node:
                    nodes.append(parsed_node)
                i += consumed
                continue

            # --- Bitmask ---
            if line.strip().startswith("bitmask"):
                parsed_node, consumed = NodeTreeParser.parse_bitmask(session, lines, i, anon_counter)
                
                if parsed_node:
                    nodes.append(parsed_node)
                i += consumed
                continue

            # --- If / Elif / Else ---
            if line.strip().startswith("if"):
                parsed_node, consumed = NodeTreeParser.parse_if(lines, i, anon_counter)
                if parsed_node:
                    if isinstance(parsed_node, VariableNode):
                        session.variables[parsed_node.name] = parsed_node
                    else:
                        nodes.append(parsed_node)
                
                i += consumed
                continue

            # --- Include ---
            if line.strip().startswith("include"):
                match = re.match(r"\s*include\s+(\w+):?", line)
                if match:
                    block_name = match.group(1)
                    if block_name in session.blocks:
                        Logger.debug(f"Including block: {block_name}")
                        for node in session.blocks[block_name].nodes:
                            nodes.append(node)
                    else:
                        Logger.error(f"Unknown block: include {block_name}")
                i += 1
                continue

            # --- Vanlig rad (BaseNode eller variabel) ---
            parsed_node = NodeTreeParser.parse_line_to_node(line, anon_counter)

            if parsed_node:
                if isinstance(parsed_node, VariableNode):
                    session.variables[parsed_node.name] = parsed_node
                else:
                    nodes.append(parsed_node)

            i += 1

        session.fields = nodes

        return nodes

    @staticmethod
    def parse_padding(line: str) -> tuple[PaddingNode, int]:
        parts = line.strip().split()
        if len(parts) == 1:
            # Alias without argument (e.g. flushbits) → just align to byte
            return PaddingNode(size=0, value=0)

        if len(parts) == 2 and parts[1].isdigit():
            size = int(parts[1])
            return PaddingNode(size=size, value=size)

        Logger.warning(f"Malformed padding line: {line}")
        return None

    @staticmethod
    def parse_seek(line: str) -> tuple[SeekNode, int]:
        parts = line.strip().split()
        if len(parts) == 2 and parts[1].isdigit():
            size = int(parts[1])
            return SeekNode(offset=size, value=size)
        else:
            Logger.warning(f"Malformed seek line: {line}")
            return None

    @staticmethod
    def parse_bitmask(session, lines: list, start_idx: int, anon_counter: int) -> tuple[BitmaskNode, int]:
        """
        Parses a bitmask structure starting from a given index.
        Returns the created BitmaskNode and number of lines consumed.
        """
        line = lines[start_idx].strip()

        match = re.match(r"bitmask\s+(\d+)", line)
        if not match:
            Logger.warning(f"Malformed bitmask: {line}")
            return None, 1

        size = int(match.group(1))

        # Samla blockets rader
        block_count, block_lines = ParserUtils.count_size_of_block_structure(lines, start_idx)

        children = []
        idx = 0
        while idx < len(block_lines):
            parsed_node = NodeTreeParser.parse_line_to_node(block_lines[idx].strip(), anon_counter)
            if parsed_node:
                children.append(parsed_node)
            idx += 1

        bitmask_node = BitmaskNode(
            name="_",
            size=size,
            children=children,
        )

        return bitmask_node, block_count + 1

    @staticmethod
    def parse_block(session, lines: list, start_idx: int, anon_counter: int) -> tuple[BlockDefinition, int]:
        line = lines[start_idx]
        match = re.match(r"block\s+(\w+):", line)
        if not match:
            Logger.warning(f"Malformed block: {line}")
            return None, 1

        block_name = match.group(1)
        count, block_lines = ParserUtils.count_size_of_block_structure(lines, start_idx)

        block_nodes = []
        idx = 0
        while idx < len(block_lines):
            block_line = block_lines[idx]
            block_line_strip = block_line.strip()

            if block_line_strip.startswith("if "):
                parsed_node, consumed = NodeTreeParser.parse_if(block_lines, idx, anon_counter)
            else:
                parsed_node = NodeTreeParser.parse_line_to_node(block_line_strip, anon_counter)
                consumed = 1

            if parsed_node:
                if isinstance(parsed_node, VariableNode):
                    session.variables[parsed_node.name] = parsed_node
                else:
                    block_nodes.append(parsed_node)
            idx += consumed

        return BlockDefinition(name=block_name, nodes=block_nodes), count + 1

    @staticmethod
    def parse_loop(session, lines: list, start_idx: int, anon_counter: int) -> tuple[LoopNode, int]:
        """
        Parses a loop structure starting from a given index.
        Returns the created LoopNode and number of lines consumed.
        """
        line = lines[start_idx]

        match = re.match(r"\s*loop\s+(.+?)\s+to\s+\€?(\w+):?", line)
        if not match:
            Logger.warning(f"Malformed loop: {line.strip()}")
            return None, 1

        count_from, target = match.groups()
        block_count, block_lines = ParserUtils.count_size_of_block_structure(lines, start_idx)

        children = []
        idx = 0
        while idx < len(block_lines):
            block_line = block_lines[idx].strip()

            if block_line.startswith("if "):
                # If-sats inuti loopen
                parsed_node, consumed = NodeTreeParser.parse_if(block_lines, idx, anon_counter)
            elif block_line.startswith("loop "):
                # Nästlad loop
                parsed_node, consumed = NodeTreeParser.parse_loop(session, block_lines, idx, anon_counter)
            elif block_line.startswith("randseq_bits"):
                parsed_node, consumed = NodeTreeParser.parse_randseq_bits(session, block_lines, idx, anon_counter)
            elif block_line.startswith("randseq"):
                parsed_node, consumed = NodeTreeParser.parse_randseq(session, block_lines, idx, anon_counter)
            else:
                # Vanlig nod
                parsed_node = NodeTreeParser.parse_line_to_node(block_line, anon_counter)
                consumed = 1

            if parsed_node:
                if isinstance(parsed_node, VariableNode):
                    session.variables[parsed_node.name] = parsed_node
                else:
                    children.append(parsed_node)

            idx += consumed

        loop_node = LoopNode(
            name=target,  # 👈 direkt namn (inte €target_loop)
            format="",
            interpreter="loop",
            count_from=count_from,
            target=target,
            dynamic="€" in count_from,  # 👈 markera om loopen är dynamisk
            children=children
        )

        return loop_node, block_count + 1

    @staticmethod
    def parse_randseq(session, lines: list, start_idx: int, anon_counter: int) -> tuple[RandSeqNode, int]:
        """
        Parses a randseq structure starting from a given index.
        Returns the created RandSeqNode and number of lines consumed.
        """
        line = lines[start_idx]

        # Matcha: tillåt siffror eller €variabel
        match = re.match(r"\s*randseq\s+(\d+|\€\w+)\s*:", line)
        if not match:
            Logger.warning(f"Malformed randseq: {line.strip()}")
            return None, 1

        raw_count_from = match.group(1)

        # Konvertera till int om det går, annars sträng
        try:
            count_from = int(raw_count_from)
        except ValueError:
            count_from = raw_count_from  # Antag €variabel

        block_count, block_lines = ParserUtils.count_size_of_block_structure(lines, start_idx)

        children = []
        for block_line in block_lines:
            parsed_node = NodeTreeParser.parse_line_to_node(block_line.strip(), anon_counter)
            if parsed_node:
                children.append(parsed_node)

        randseq_node = RandSeqNode(
            name=f"randseq {raw_count_from}",  # Obs! Använd raw här för korrekt namn
            format="",
            interpreter="randseq",
            count_from=count_from,
            children=children
        )

        return randseq_node, block_count + 1

    @staticmethod
    def parse_uncompress(lines: list, start_idx: int, anon_counter: int) -> tuple[UncompressNode, int]:
        """
        Parse an uncompress block:
            uncompress zlib <len_expr>:
                ...
        len_expr optional; if missing, consume remaining payload.
        """
        line = lines[start_idx].strip()
        match = re.match(r"\s*uncompress\s+(\w+)(?:\s+([^\s:]+))?:?", line)
        if not match:
            Logger.warning(f"Malformed uncompress: {line}")
            return None, 1

        algo = match.group(1)
        length_expr = match.group(2)

        block_count, block_lines = ParserUtils.count_size_of_block_structure(lines, start_idx)

        children = []
        for blk in block_lines:
            parsed = NodeTreeParser.parse_line_to_node(blk.strip(), anon_counter)
            if parsed:
                children.append(parsed)

        node = UncompressNode(
            name="uncompress",
            format="",
            interpreter="uncompress",
            algo=algo,
            length_expr=length_expr,
            children=children,
        )

        return node, block_count + 1

    @staticmethod
    def parse_randseq_bits(session, lines: list, start_idx: int, anon_counter: int) -> tuple[RandSeqNode, int]:
        """
        Parses a bit-based randseq structure with modifiers:
            randseq_bits 24:
            randseq_bits 24, M:
            randseq_bits 24 M8m:
            randseq_bits €var M 8m:

        Supported modifiers:
            M     = mirror whole block
            Xm    = mirror groups of X bits (e.g. 8m, 4m, 16m)
        """

        line = lines[start_idx]

        # Regex med stöd för t.ex:
        #   randseq_bits 24, M8m:
        #   randseq_bits €var M 8m:
        pattern = r"""
            \s*randseq_bits\s+
            (?:
                (?P<num>\d+)(?P<byte>B)?      # numeriskt värde eller X B
                | (?P<var>€\w+)               # eller variabel
            )
            \s*,?\s*                          # valfritt kommatecken
            (?P<mods>(?:[\w]+(?:\s+[\w]+)*)?) # valfria modifiers, t.ex. "M 8m"
            \s*:
        """

        match = re.match(pattern, line, re.VERBOSE)
        if not match:
            Logger.warning(f"Malformed randseq_bits: {line.strip()}")
            return None, 1

        # -------- BITCOUNT -------------------------------
        if match.group("var"):
            raw_count_from = match.group("var")
            count_from = raw_count_from
        else:
            num = int(match.group("num"))
            if match.group("byte"):
                raw_count_from = f"{num}B"
                count_from = num * 8
            else:
                raw_count_from = str(num)
                count_from = num

        # -------- MODIFIERS -------------------------------
        modifiers_raw = match.group("mods") or ""
        if modifiers_raw.strip():
            # Split on whitespace
            modifiers = modifiers_raw.split()
        else:
            modifiers = []

        # Nu är t.ex. "M8m" fortfarande en sträng.
        # Vi vill splittra den till ["M", "8m"].
        normalized_modifiers = []
        for m in modifiers:
            # Matcha M eller Xm i samma token
            submods = re.findall(r"(?:M|\d+m)", m)
            if submods:
                normalized_modifiers.extend(submods)
            else:
                normalized_modifiers.append(m)

        # -------- BARNNODER -------------------------------
        block_count, block_lines = ParserUtils.count_size_of_block_structure(lines, start_idx)

        children = []
        for block_line in block_lines:
            parsed_node = NodeTreeParser.parse_line_to_node(block_line.strip(), anon_counter)
            if parsed_node:
                children.append(parsed_node)

        # -------- NODE ------------------------------------
        randseq_node = RandSeqNode(
            name=f"randseq_bits {raw_count_from}",
            format="",
            interpreter="randseq_bits",
            modifiers=normalized_modifiers,  # ← KLART!
            count_from=count_from,
            children=children
        )

        return randseq_node, block_count + 1
    
    @staticmethod
    def parse_struct_or_if(lines: list, idx: int, anon_counter: int):
        """
        Parses either a struct field, an if/elif/else block, or special nodes like padding and bitmask.
        """
        line = lines[idx].strip()
        stripped = line.strip()

        if stripped.startswith("padding "):
            parsed_node = NodeTreeParser.parse_padding(line)
            return parsed_node
        if stripped.startswith("uncompress "):
            parsed_node, consumed = NodeTreeParser.parse_uncompress(lines, idx, anon_counter)
            return parsed_node, consumed

        # Alias: flushbit/flushbits → padding 0 (byte align)
        if stripped in ("flushbit", "flushbits"):
            parsed_node = NodeTreeParser.parse_padding("padding 0")
            return parsed_node

        if stripped.startswith("seek "):
            parsed_node = NodeTreeParser.parse_seek(line)
            return parsed_node

        if line.startswith("if "):
            parsed_node, consumed = NodeTreeParser.parse_if(lines, idx, anon_counter)
            return parsed_node, consumed

        parsed_node = NodeTreeParser.parse_line_to_node(line, anon_counter)
        return parsed_node, 1

    
    
    @staticmethod
    def count_size_of_block_structure(lines: list, start_idx: int) -> tuple[int, list[str]]:
        """
        Counts how many lines belong to the current block based on indentation.
        Returns (number of lines, list of block lines with original indentation preserved).
        """
        block_lines = []
        base_indent = len(re.match(r"^\s*", lines[start_idx])[0])
        i = start_idx + 1

        while i < len(lines):
            line = lines[i]
            if not line.strip():
                i += 1
                continue

            current_indent = len(re.match(r"^\s*", line)[0])

            if current_indent <= base_indent:
                break

            block_lines.append(line)  # BEHÅLL original (med whitespace!)
            i += 1

        return i - start_idx - 1, block_lines

    @staticmethod
    def parse_if(lines: list, start_idx: int, anon_counter: int):
        base_indent = len(re.match(r"^\s*", lines[start_idx])[0])
        line = lines[start_idx].strip()
        
        if not line.startswith("if "):
            Logger.warning(f"Expected 'if' statement at line {start_idx}: {line}")
            return None, 1

        condition = line[3:].rstrip(":").strip()
        true_branch = []
        false_branch = []
        elif_branches = []

        i = start_idx + 1
        current_branch = true_branch
        current_condition = condition
        seen_first = False

        while i < len(lines):
            raw_line = lines[i]
            line = raw_line.strip()

            if not line:
                i += 1
                continue

            indent = len(re.match(r"^\s*", raw_line)[0])

            if indent < base_indent:
                break
            elif indent == base_indent:
                if line.startswith("elif "):
                    if seen_first:
                        elif_branches.append((current_condition, current_branch))
                    else:
                        seen_first = True
                    current_condition = line[5:].rstrip(":").strip()
                    current_branch = []
                    i += 1
                    continue
                elif line.startswith("else"):
                    if seen_first:
                        elif_branches.append((current_condition, current_branch))
                    else:
                        seen_first = True
                    current_condition = "else"
                    current_branch = false_branch
                    i += 1
                    continue
                else:
                    break

            # --- Här byter vi till parse_struct_or_if ---
            parsed_node, consumed = NodeTreeParser.parse_struct_or_if(lines, i, anon_counter)
            if parsed_node:
                current_branch.append(parsed_node)
            i += consumed

        node = IfNode(
            name=f"if_{condition}",
            format="",
            interpreter="if",
            condition=condition,
            true_branch=true_branch,
            false_branch=false_branch if false_branch else None,
            elif_branches=elif_branches if elif_branches else None
        )

        consumed_lines = i - start_idx
        return node, consumed_lines

    @staticmethod
    def parse_line_to_node(line: str, anon_counter: int):
        """
        Parses a single line into a BaseNode or VariableNode.
        """
        
        # Special: Padding
        if line.strip().startswith("padding "):
            parsed_node = NodeTreeParser.parse_padding(line)
            return parsed_node

        if line.strip().startswith("seek "):
            parsed_node = NodeTreeParser.parse_seek(line)
            return parsed_node

        if "+=" in line:
            name, rest = [x.strip() for x in line.split("+=", 1)]
            fmt, mods, enc_mods = ModifierUtils.parse_modifiers(rest)
            name, ignore, anon_counter = ParserUtils.check_ignore_and_rename(name, anon_counter)

            return BaseNode(
                name=name,
                format=fmt,
                interpreter="append",
                modifiers=mods,
                encode_modifiers=enc_mods,
                depends_on=None,
                dynamic=False,
                ignore=ignore,
            )

        # Special: Variable assignment ("=")
        if "=" in line:
            name, rest = [x.strip() for x in line.split("=", 1)]
            fmt, mods, enc_mods = ModifierUtils.parse_modifiers(rest)
            name, ignore, anon_counter = ParserUtils.check_ignore_and_rename(name, anon_counter)

            # Slice-variabel
            if fmt.startswith("€") and "[" in fmt and ":" in fmt:
                depends_on = fmt.split("[")[0][1:]
                return VariableNode(
                    name=name,
                    raw_value=fmt,
                    format=fmt,
                    interpreter="slice",
                    modifiers=mods,
                    depends_on=depends_on,
                    dynamic=True,
                )
            else:
                # Literal variabel
                try:
                    int_val = int(fmt)
                    return VariableNode(
                        name=name,
                        raw_value=int_val,
                        format=None,
                        interpreter="literal",
                        modifiers=mods,
                        depends_on=None,
                        dynamic=False,
                    )
                except ValueError:
                    return VariableNode(
                        name=name,
                        raw_value=fmt,
                        format=None,
                        interpreter="literal",
                        modifiers=mods,
                        depends_on=None,
                        dynamic=False,
                    )

        # Annars normal parsing
        result = ParserUtils.split_field_definition(line)
        if not result:
            return None

        name, fmt, mods, enc_mods = result
        mods = NodeTreeParser.expand_combined_bit_modifiers(mods)
        name, ignore, anon_counter = ParserUtils.check_ignore_and_rename(name, anon_counter)

        # Special: Slice-fält i struct (ex: €name[1:4])
        if fmt.startswith("€") and "[" in fmt and ":" in fmt:
            depends_on = fmt.split("[")[0][1:]
            return BaseNode(
                name=name,
                format=fmt,
                interpreter="slice",
                modifiers=mods,
                encode_modifiers=enc_mods,
                depends_on=depends_on,
                dynamic=True,
                ignore=ignore
            )

        # Special: Bits-slice (ex: €len1's)
        if fmt.startswith("€") and fmt.endswith("'s"):
            depends_on = fmt[1:-2]  # Ta bort € och 's
            return BaseNode(
                name=name,
                format=fmt,
                interpreter="dynamic",
                modifiers=mods,
                encode_modifiers=enc_mods,
                depends_on=depends_on,
                dynamic=True,
                ignore=ignore
            )

        # Special: Variabel-referens (ex: €seed)
        if fmt.startswith("€"):
            return BaseNode(
                name=name,
                format=fmt,
                interpreter="var",
                modifiers=mods,
                encode_modifiers=enc_mods,
                depends_on=fmt[1:],
                dynamic=True,
                ignore=ignore
            )

        # Bitsfält (ex: 7B, B)
        if any(m.endswith("B") and (m[:-1].isdigit() or m[:-1] == "") for m in mods):
            return BaseNode(
                name=name,
                format=fmt,
                interpreter="bits",
                modifiers=mods,
                encode_modifiers=enc_mods,
                depends_on=None,
                dynamic=False,
                ignore=ignore
            )

        # Bitsfält (ex: 7b, b)
        if any(m.endswith("b") and (m[:-1].isdigit() or m[:-1] == "") for m in mods):
            return BaseNode(
                name=name,
                format=fmt,
                interpreter="bits",
                modifiers=mods,
                encode_modifiers=enc_mods,
                depends_on=None,
                dynamic=False,
                ignore=ignore
            )

        # Hantera 'bits' som format
        if fmt == "bits":
            return BaseNode(
                name=name,
                format=fmt,
                interpreter="bits",
                modifiers=mods, 
                encode_modifiers=enc_mods,
                depends_on=None,
                dynamic=False,
                ignore=ignore
            )

        # Standard struct
        if fmt == "packed_guid":
            return PackedGuidNode(
                name=name,
                format="",
                interpreter="packed_guid",
                modifiers=mods,
                encode_modifiers=enc_mods,
                ignore=ignore,
            )

        return BaseNode(
                name=name,
                format=fmt,
                interpreter="struct",
                modifiers=mods,
                encode_modifiers=enc_mods,
                ignore=ignore
            )

    @staticmethod
    def expand_combined_bit_modifiers(modifiers: list[str]) -> list[str]:
        """
        Split tokens such as '7BI' into ['7B', 'I'] so bit-length and
        post-modifiers can be processed separately downstream.
        """
        if not modifiers:
            return []

        expanded = []
        for mod in modifiers:
            if not isinstance(mod, str):
                expanded.append(mod)
                continue

            match = re.match(r"^(\d+)([Bb])(.*)$", mod)
            if match:
                expanded.append(f"{match.group(1)}{match.group(2)}")
                trailing = match.group(3)
                if trailing:
                    expanded.extend(list(trailing))
            else:
                expanded.append(mod)

        return expanded
