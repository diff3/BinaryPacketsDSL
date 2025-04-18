#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from modules.Session import PacketSession, BaseNode, VariableNode, LoopNode, BlockDefinition, get_session
from utils.ParserUtils import ParserUtils
from utils.ModifierParser import ModifierUtils
from typing import List, Any
from utils.Logger import Logger


session = get_session()

class NodeTreeParser:
    @staticmethod
    def parse(definition: str):
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

            parsed_node = NodeTreeParser.parse_line_to_node(line, anon_counter)
            if parsed_node:
                nodes.append(parsed_node)

            i += 1

        session.fields = nodes
        return nodes

    @staticmethod
    def parse_line_to_node(line: str, anon_counter: int):
        session = get_session()

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
        if fmt == "B" and any(m.endswith("B") for m in mods):
            return BaseNode(name=name, format=fmt, interpreter="bits", modifiers=mods, ignore=ignore)

        # Vanlig strukt
        return BaseNode(name=name, format=fmt, interpreter="struct", modifiers=mods, ignore=ignore)
    
    def pretty_print_nodes(nodes: list) -> None:
        print("\n=== Nodes ===")
        for idx, node in enumerate(nodes, 1):
            if isinstance(node, LoopNode):
                print(f"[{idx}] {node.name} ({len(node.children)} children)")
            else:
                print(f"[{idx}] {node.name}")
            print(f"     format      : {node.format}")
            print(f"     interpreter : {node.interpreter}")
            print(f"     modifiers   : {node.modifiers}")
            print(f"     depends_on  : {node.depends_on}")
            print(f"     dynamic     : {node.dynamic}")
            if hasattr(node, "ignore"):
                print(f"     ignore      : {node.ignore}")

            # Visa loop children om node är LoopNode
            if isinstance(node, LoopNode):
                print(f"     count_from  : {node.count_from}")
                print(f"     target      : {node.target}")
                print("     children:")
                for cidx, child in enumerate(node.children, start=1):
                    print(f"        [{cidx}] {child.name}")
                    print(f"            format      : {child.format}")
                    print(f"            interpreter : {child.interpreter}")
                    print(f"            modifiers   : {child.modifiers}")
                    print(f"            depends_on  : {child.depends_on}")
                    print(f"            dynamic     : {child.dynamic}")
                    if hasattr(child, "ignore"):
                        print(f"            ignore      : {child.ignore}")
                    print()
            print()

    @staticmethod
    def pretty_print_compact_all(session: PacketSession) -> None:
        """
        Prints a compact overview of Variables, Blocks, and Nodes.
        """

        print("\n=== Compact Variables ===")
        if not session.variables:
            # print("[empty]\n")
            pass
        else:
            for idx, (name, var) in enumerate(session.variables.items(), 1):
                if hasattr(var, "interpreter"):
                    mods = f" [{', '.join(var.modifiers)}]" if var.modifiers else ""
                    print(f"[{idx}] {name} = {var.format} ({var.interpreter}){mods}")
                else:
                    print(f"[{idx}] {name} = {repr(var)} (literal)")

        print("\n=== Compact Blocks ===")
        if not session.blocks:
            # print("[empty]\n")
            pass  
        else:
            for idx, (block_name, block_def) in enumerate(session.blocks.items(), 1):
                print(f"[{idx}] Block: {block_name}")
                for cidx, child in enumerate(block_def.nodes, 1):
                    mods = f" [{', '.join(child.modifiers)}]" if child.modifiers else ""
                    print(f"    [{cidx}] {child.name} : {child.format} ({child.interpreter}){mods}")

        print("\n=== Compact Nodes ===")
        if not session.fields:
            # print("[empty]\n")
            pass
        else:
            for idx, node in enumerate(session.fields, 1):
                if isinstance(node, LoopNode):
                    print(f"[{idx}] {node.name} (loop {len(node.children)} children)")
                    for cidx, child in enumerate(node.children, 1):
                        mods = f" [{', '.join(child.modifiers)}]" if child.modifiers else ""
                        print(f"    [{cidx}] {child.name} : {child.format} ({child.interpreter}){mods}")
                else:
                    mods = f" [{', '.join(node.modifiers)}]" if node.modifiers else ""
                    print(f"[{idx}] {node.name} : {node.format} ({node.interpreter}){mods}")

    def pretty_print_variables(variables: dict[str, Any]) -> None:
        print("\n=== Variables ===")
        for idx, var in enumerate(variables.values(), 1):
            if isinstance(var, VariableNode):
                print(f"[{idx}] {var.name}")
                print(f"     raw_value   : {var.raw_value}")
                print(f"     value       : {var.value}")
                print(f"     format      : {var.format}")
                print(f"     interpreter : {var.interpreter}")
                print(f"     modifiers   : {var.modifiers}")
                print(f"     depends_on  : {var.depends_on}")
                print(f"     dynamic     : {var.dynamic}")
            else:
                print(f"[{idx}] {var} (simple literal)")
        print()

    def pretty_print_blocks(blocks: dict[str, BlockDefinition]) -> None:
        print("\n=== Blocks ===")
        for idx, (block_name, block_def) in enumerate(blocks.items(), 1):
            print(f"[{idx}] Block: {block_name}")
            for node in block_def.nodes:
                print(f"     - {node.name}")
                print(f"         format      : {node.format}")
                print(f"         interpreter : {node.interpreter}")
                print(f"         modifiers   : {node.modifiers}")
                print(f"         depends_on  : {node.depends_on}")
                print(f"         dynamic     : {node.dynamic}")
        print()