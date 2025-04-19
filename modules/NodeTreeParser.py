#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from modules.Session import PacketSession, BaseNode, IfNode, VariableNode, LoopNode, BlockDefinition, get_session
from utils.ParserUtils import ParserUtils
from utils.ModifierParser import ModifierUtils
from typing import List, Any
from utils.Logger import Logger


session = get_session()
parse_warnings = []

class NodeTreeParser:
    @staticmethod
    def parse(lines: list) -> list:
        """
        Parses a list of lines into a list of BaseNode/LoopNode/etc.
        """
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
                parsed_node, consumed = NodeTreeParser.parse_block(lines, i, anon_counter)

                if isinstance(parsed_node, VariableNode):
                    session.variables[parsed_node.name] = parsed_node
                else:
                    session.blocks[parsed_node.name] = parsed_node

                i += consumed
                continue

            # --- Loop ---
            if line.strip().startswith("loop"):
                #parsed_node, consumed = NodeTreeParser.parse_loop(lines, i, anon_counter)
                #if parsed_node:
                #o    nodes.append(parsed_node)  # <-- APPEND parsed_node direkt här
                parsed_node, consumed = NodeTreeParser.parse_loop(session, lines, i, anon_counter)
                if parsed_node:
                    if isinstance(parsed_node, VariableNode):
                        session.variables[parsed_node.name] = parsed_node
                    else:
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
                #if parsed_node:
                 #   nodes.append(parsed_node)
                i += consumed
                continue

            # --- Include ---
            if line.strip().startswith("include"):
                match = re.match(r"include\s+(\w+)", line)
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
            # parsed_node = NodeTreeParser.parse_line_to_node(line, anon_counter)
            # if parsed_node:
            #    nodes.append(parsed_node)

            parsed_node = NodeTreeParser.parse_line_to_node(line, anon_counter)

            if parsed_node:
                if isinstance(parsed_node, VariableNode):
                    session.variables[parsed_node.name] = parsed_node
                else:
                    nodes.append(parsed_node)

            i += 1

        # Slutgiltigt
        session.fields = nodes
        # Logger.debug(f"Parsed {len(nodes)} nodes")
        return nodes

    @staticmethod
    def parse_struct_or_if(lines: list, idx: int, anon_counter: int):
        """
        Parses either a regular struct field or an if/elif/else block.
        """
        line = lines[idx]

        if line.startswith("if "):
            parsed_node, consumed = NodeTreeParser.parse_if(lines, idx, anon_counter)
            return parsed_node, consumed

        parsed_node = NodeTreeParser.parse_line_to_node(line, anon_counter)
        return parsed_node, 1

    @staticmethod
    def parse_block(lines: list, start_idx: int, anon_counter: int) -> tuple[BlockDefinition, int]:
        """
        Parses a block structure starting from a given index.
        Returns the created BlockDefinition and number of lines consumed.
        """
        line = lines[start_idx]
        match = re.match(r"block\s+(\w+):", line)
        if not match:
            Logger.warning(f"Malformed block: {line}")
            return None, 1

        block_name = match.group(1)
        count, block_lines = ParserUtils.count_size_of_block_structure(lines, start_idx)

        block_nodes = []
        for block_line in block_lines:
            parsed_node = NodeTreeParser.parse_line_to_node(block_line, anon_counter)
            if parsed_node:
                if isinstance(parsed_node, VariableNode):
                    session.variables[parsed_node.name] = parsed_node
                else:
                    block_nodes.append(parsed_node)

        return BlockDefinition(name=block_name, nodes=block_nodes), count + 1

    @staticmethod
    def parse_loop(session, lines: list, start_idx: int, anon_counter: int) -> tuple[LoopNode, int]:
        """
        Parses a loop structure starting from a given index.
        Returns the created LoopNode and number of lines consumed.
        """
        line = lines[start_idx].strip()
        match = re.match(r"loop\s+(.+?)\s+to\s+\€?(\w+):?", line)
        if not match:
            Logger.warning(f"Malformed loop: {line}")
            return None, 1

        count_from, target = match.groups()
        block_count, block_lines = ParserUtils.count_size_of_block_structure(lines, start_idx)

        children = []
        idx = 0
        while idx < len(block_lines):
            parsed_node, consumed = NodeTreeParser.parse_struct_or_if(block_lines, idx, anon_counter)
            if parsed_node:
                if isinstance(parsed_node, VariableNode):
                    session.variables[parsed_node.name] = parsed_node
                else:
                    children.append(parsed_node)
            idx += consumed

        loop_node = LoopNode(
            name=f"€{target}_loop",
            format="",
            interpreter="loop",
            count_from=count_from,
            target=target,
            children=children
        )

        return loop_node, block_count + 1
    
    @staticmethod
    def parse_if(lines: list, start_idx: int, anon_counter: int) -> tuple[IfNode, int]:
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
        seen_first = False  # <- Ny!

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
                        seen_first = True  # <- markerar att första if är förbrukad
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

            parsed_node = NodeTreeParser.parse_line_to_node(line, anon_counter)
            if parsed_node:
                if isinstance(parsed_node, VariableNode):
                    session.variables[parsed_node.name] = parsed_node
                else:
                    current_branch.append(parsed_node)

            i += 1

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
    def parse_old(definition: str):
        session = get_session()
        lines = ParserUtils.remove_comments_and_reserved(definition)

        nodes = []
        i = 0
        anon_counter = 0

        while i < len(lines):
            line = lines[i].strip()

            if line.startswith("block"):
                match = re.match(r"block\s+(\w+):", line)
                if not match:
                    Logger.warning(f"Malformed block: {line}")
                    i += 1
                    continue

                block_name = match.group(1)
                count, block_lines = ParserUtils.count_size_of_block_structure(lines, i)
                block_nodes = []
                for block_line in block_lines:
                    parsed_node = NodeTreeParser.parse_line_to_node(block_line, anon_counter)
                    if parsed_node:
                        block_nodes.append(parsed_node)
                session.blocks[block_name] = BlockDefinition(name=block_name, nodes=block_nodes)
                i += count + 1
                continue

            if line.startswith("loop"):
                match = re.match(r"loop\s+(\S+)\s+to\s+(\S+):", line)
                if not match:
                    Logger.warning(f"Malformed loop: {line}")
                    i += 1
                    continue

                count_from, target = match.groups()
                count, loop_lines = ParserUtils.count_size_of_block_structure(lines, i)
                loop_nodes = []
                for loop_line in loop_lines:
                    parsed_node = NodeTreeParser.parse_line_to_node(loop_line, anon_counter)
                    if parsed_node:
                        loop_nodes.append(parsed_node)
                loop_node = LoopNode(name=f"{target}_loop", format="", interpreter="loop", count_from=count_from, target=target, children=loop_nodes)
                nodes.append(loop_node)
                i += count + 1
                continue

            if line.startswith("include"):
                match = re.match(r"include\s+(\w+)", line)
                if not match:
                    Logger.warning(f"Malformed include: {line}")
                    i += 1
                    continue

                block_name = match.group(1)
                if block_name not in session.blocks:
                    Logger.error(f"Unknown block: {block_name}")
                    i += 1
                    continue

                nodes.extend(session.blocks[block_name].nodes)
                i += 1
                continue
                    
            if line.startswith("if "):
                    match = re.match(r"if (.+):", line)
                    if not match:
                        Logger.warning(f"Malformed if: {line}")
                        i += 1
                        continue

                    condition = match.group(1)
                    count, true_block = ParserUtils.count_size_of_block_structure(lines, i)

                    true_branch = [NodeTreeParser.parse_line_to_node(l, anon_counter) for l in true_block]
                    elif_branches = []
                    else_branch = None

                    i += count + 1

                    # Hantera elif och else
                    while i < len(lines):
                        next_line = lines[i].strip()

                        if next_line.startswith("elif "):
                            match = re.match(r"elif (.+):", next_line)
                            if match:
                                elif_condition = match.group(1)
                                ecount, elif_block = ParserUtils.count_size_of_block_structure(lines, i)
                                elif_nodes = [NodeTreeParser.parse_line_to_node(l, anon_counter) for l in elif_block]
                                elif_branches.append((elif_condition, elif_nodes))
                                i += ecount + 1
                                continue
                            else:
                                Logger.warning(f"Malformed elif: {next_line}")
                                i += 1
                                continue

                        elif next_line.startswith("else:"):
                            ecount, else_block = ParserUtils.count_size_of_block_structure(lines, i)
                            else_branch = [NodeTreeParser.parse_line_to_node(l, anon_counter) for l in else_block]
                            i += ecount + 1
                            break

                        else:
                            break

                    # Lägg till
                    nodes.append(IfNode(
                        name=f"if_{condition}",
                        format="",
                        interpreter="if",
                        condition=condition,
                        true_branch=true_branch,
                        elif_branches=elif_branches,
                        false_branch=else_branch
                    ))

                    continue
            if '=' in line and ':' not in line:
                # Variabelrad
                try:
                    name, value = [x.strip() for x in line.split('=', 1)]
                    session.variables[name] = value  # Skapa en enkel variabel
                except Exception as e:
                    parse_warnings.append(f"Failed to parse variable line: '{line}' - {str(e)}")
                i += 1
                continue

            parsed_node = NodeTreeParser.parse_line_to_node(line, anon_counter)
            if parsed_node:
                nodes.append(parsed_node)

            i += 1

        session.fields = nodes
        if parse_warnings:
            print("\n=== Warnings ===")
            for w in parse_warnings:
                Logger.warning(w)

        return nodes

    @staticmethod
    def parse_line_to_node(line: str, anon_counter: int):
        """
        Parses a single line into a BaseNode or VariableNode.
        """

        if "=" in line:
                name, rest = [x.strip() for x in line.split("=", 1)]
                fmt, mods = ModifierUtils.parse_modifiers(rest)

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

        # Annars normal parsing (med split_field_definition)
        result = ParserUtils.split_field_definition(line)
        if not result:
            return None

        name, fmt, mods = result
        name, ignore, anon_counter = ParserUtils.check_ignore_and_rename(name, anon_counter)

        # Slice-fält i strukt
        if fmt.startswith("€") and "[" in fmt and ":" in fmt:
            depends_on = fmt.split("[")[0][1:]
            return BaseNode(
                name=name,
                format=fmt,
                interpreter="slice",
                modifiers=mods,
                depends_on=depends_on,
                dynamic=True,
                ignore=ignore
            )

        # Variabel-referens (t.ex. €seed)
        if fmt.startswith("€"):
            return BaseNode(
                name=name,
                format=fmt,
                interpreter="var",
                modifiers=mods,
                depends_on=fmt[1:],
                dynamic=True,
                ignore=ignore
            )

        # Bitsfält (t.ex. 7B, 3B)
        if any(m.endswith("B") and m[:-1].isdigit() for m in mods):
            return BaseNode(
                name=name,
                format=fmt,
                interpreter="bits",
                modifiers=mods,
                depends_on=None,
                dynamic=False,
                ignore=ignore
            )

        # Standard strukt
        return BaseNode(
            name=name,
            format=fmt,
            interpreter="struct",
            modifiers=mods,
            ignore=ignore
        )

    @staticmethod
    def parse_line_to_node_old(line: str, anon_counter: int):
        session = get_session()

        mods = []  # <-- Lägg till direkt

        if "=" in line:
            name, value = [x.strip() for x in line.split("=", 1)]

            if value.startswith("€") and "[" in value and ":" in value:
                depends_on = value.split("[")[0][1:]
                return VariableNode(
                    name=name,
                    raw_value=value,
                    format=value,
                    interpreter="slice",
                    depends_on=depends_on,
                    dynamic=True,
                    modifiers=mods
                )
            else:
                return VariableNode(
                    name=name,
                    raw_value=value,
                    format=None,
                    interpreter="literal",
                    depends_on=None,
                    dynamic=False,
                    modifiers=mods
                )

        # Splitta och ta ut mods
        result = ParserUtils.split_field_definition(line)
        if not result:
            return None

        name, fmt, mods = result
        ignore = ParserUtils.is_ignored_field(name)

        # Slice variabler
        if fmt.startswith("€") and "[" in fmt and ":" in fmt:
            match = re.match(r"\u20ac(\w+)\[([^\]:]*):([^\]:]*)\]", fmt)
            if match:
                depends_on, _, _ = match.groups()
                return BaseNode(name=name, format=fmt, interpreter="slice", modifiers=mods, depends_on=depends_on, dynamic=True, ignore=ignore)

        # Variabler
        if fmt.startswith("€") and "'" not in fmt:
            var_name = fmt[1:]
            return BaseNode(name=name, format=fmt, interpreter="var", modifiers=mods, depends_on=var_name, dynamic=True, ignore=ignore)

        # Dynamisk sträng t.ex. €len's eller €len'I
        if fmt.startswith("€") and fmt.endswith("'"):
            var_name = fmt[1:-2]
            return BaseNode(name=name, format=fmt, interpreter="struct", modifiers=mods, depends_on=var_name, dynamic=True, ignore=ignore)

        # Strukt/bit-modifierad
        if any(m.endswith("B") for m in mods):
            return BaseNode(name=name, format=fmt, interpreter="bits", modifiers=mods, ignore=ignore)

        # Vanlig strukt
        return BaseNode(name=name, format=fmt, interpreter="struct", modifiers=mods, ignore=ignore)
    
    @staticmethod
    def print_compact_variables(session):
        print("\n=== Compact Variables ===")
        if not session.variables:
            print("[empty]")
            return
        
        for idx, (name, var) in enumerate(session.variables.items(), start=1):
            display_name = name if name != "_" else "_"
            if hasattr(var, "modifiers"):
                mod_str = f" [{', '.join(var.modifiers)}]" if var.modifiers else ""
                interp = getattr(var, "interpreter", "literal")
                value = getattr(var, "raw_value", var)
                print(f"[{idx}] {display_name} = {value} ({interp}){mod_str}")
            else:
                print(f"[{idx}] {display_name} = {var} (literal)")

    @staticmethod
    def print_compact_blocks(session):
        print("\n=== Compact Blocks ===")
        if not session.blocks:
            print("[empty]")
            return
        
        for bidx, (block_name, block) in enumerate(session.blocks.items(), start=1):
            print(f"[{bidx}] Block: {block_name}")
            for i, node in enumerate(block.nodes, start=1):
                name = node.name if not getattr(node, "ignore", False) else "_"
                mod_str = f" [{', '.join(node.modifiers)}]" if node.modifiers else ""
                print(f"     [{i}] {name} : {node.format} ({node.interpreter}){mod_str}")

    @staticmethod
    def print_compact_nodes(session):
        print("\n=== Compact Nodes ===")
        if not session.fields:
            print("[empty]")
            return

        for idx, node in enumerate(session.fields, start=1):
            name = node.name if not getattr(node, "ignore", False) else "_"
            mod_str = f" [{', '.join(node.modifiers)}]" if node.modifiers else ""

            print(f"[{idx}] {name} : {node.format} ({node.interpreter}){mod_str}")

            if isinstance(node, LoopNode):
                for cidx, child in enumerate(node.children, start=1):
                    cname = child.name if not getattr(child, "ignore", False) else "_"
                    cmod = f" [{', '.join(child.modifiers)}]" if child.modifiers else ""
                    print(f"     [{cidx}] {cname} : {child.format} ({child.interpreter}){cmod}")

            elif isinstance(node, IfNode):
                NodeTreeParser._print_compact_ifnode(node)

    @staticmethod
    def _print_compact_ifnode(ifnode):
        print("     [True branch]")
        for cidx, child in enumerate(ifnode.true_branch, start=1):
            name = child.name if not getattr(child, "ignore", False) else "_"
            mod_str = f" [{', '.join(child.modifiers)}]" if child.modifiers else ""
            print(f"         [{cidx}] {name} : {child.format} ({child.interpreter}){mod_str}")

        if ifnode.elif_branches:
            for eidx, (condition, branch) in enumerate(ifnode.elif_branches, start=1):
                print(f"     [Elif branch {eidx}: {condition}]")
                for cidx, child in enumerate(branch, start=1):
                    name = child.name if not getattr(child, "ignore", False) else "_"
                    mod_str = f" [{', '.join(child.modifiers)}]" if child.modifiers else ""
                    print(f"         [{cidx}] {name} : {child.format} ({child.interpreter}){mod_str}")

        if ifnode.false_branch:
            print("     [False branch]")
            for cidx, child in enumerate(ifnode.false_branch, start=1):
                name = child.name if not getattr(child, "ignore", False) else "_"
                mod_str = f" [{', '.join(child.modifiers)}]" if child.modifiers else ""
                print(f"         [{cidx}] {name} : {child.format} ({child.interpreter}){mod_str}")

    @staticmethod
    def pretty_print_compact_all(session):
        NodeTreeParser.print_compact_variables(session)
        NodeTreeParser.print_compact_blocks(session)
        NodeTreeParser.print_compact_nodes(session)