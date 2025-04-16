#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from modules.Session import BaseNode, VariableNode, LoopNode, BlockDefinition, get_session
from utils.ParserUtils import ParserUtils
from typing import List, Any
from utils.Logger import Logger


session = get_session()

class NodeTreeParser:
    @staticmethod
    def parse(def_lines: List[str]) -> List[BaseNode]:
        """
        Parses a list of .def lines into BaseNode objects.

        Parameters:
            def_lines (List[str]): Raw definition lines

        Returns:
            List[BaseNode]: Parsed node structure (no data extraction)
        """
         
        # TODO: add regex expression support (e.g. €text~m/abc/)
        # TODO: Bit parser
        # TODO: randseq

        lines = ParserUtils.remove_comments_and_reserved(def_lines)
        nodes = []

        anon_counter = 1

        # for i, line in enumerate(lines):
        i = 0
        while i < len(lines): 
            line = lines[i]
            
            if line.strip().startswith("block"):
                match = re.match(r"block\s+(\w+):", line)
                if not match:
                    Logger.warning(f"Malformed block: {line}")
                    i += 1
                    continue

                block_name = match.group(1)
                count, block_lines = ParserUtils.count_size_of_block_structure(lines, i)

                block_nodes = []
                for block_line in block_lines:
                    if "=" in block_line:
                        var_name, var_value = [x.strip() for x in block_line.split("=", 1)]

                        try:
                            value = int(var_value)
                        except ValueError:
                            value = var_value

                        node = VariableNode(
                            name=var_name,
                            raw_value=var_value,
                            value=value,
                            format=None,
                            interpreter="literal",
                            modifiers=[],
                            depends_on=None,
                            dynamic=False
                        )
                        session.variables[var_name] = node
                        i += 1
                        continue

                    if ":" not in block_line:
                        i += 1
                        continue

                    parts = [x.strip() for x in block_line.split(",", 1)]
                    left = parts[0]
                    mods = list(parts[1]) if len(parts) > 1 else []

                    name, right = [x.strip() for x in left.split(":", 1)]
                       # Ignorerat fält
                    
                    if block_line.strip().startswith("_"):
                        ignore = True
                    else:
                        ignore = False


                    if right.startswith("€") and "[" in right and ":" in right:
                        match = re.match(r"€(\w+)\[([^\]:]*):([^\]:]*)(?::([^\]]+))?\]", right)
                        if match:
                            depends_on, *_ = match.groups()
                            node = BaseNode(
                                name=name,
                                format=right,
                                interpreter="slice",
                                modifiers=mods,
                                depends_on=depends_on,
                                dynamic=True,
                                ignore=ignore
                            )
                            block_nodes.append(node)
                            i += 1
                            continue

                    if right.startswith("€"):
                        node = BaseNode(
                            name=name,
                            format=right,
                            interpreter="var",
                            modifiers=mods,
                            depends_on=right[1:],
                            dynamic=True,
                             ignore=ignore
                        )
                        block_nodes.append(node)
                        i += 1
                        continue

                    # standardfält
                    node = BaseNode(
                        name=name,
                        format=right,
                        interpreter="struct",
                        modifiers=mods,
                        ignore=ignore
                    )
                    block_nodes.append(node)

                session.blocks[block_name] = BlockDefinition(name=block_name, nodes=block_nodes)
                i += count + 1
                continue

            if line.strip().startswith("include "):
                _, block_name = line.strip().split(" ", 1)
                block_name = block_name.strip()

               

                if block_name not in session.blocks:
                    Logger.error(f"Unknown block: {block_name}")
                    continue

            
                Logger.debug(f"Including block: {block_name}")
                for node in session.blocks[block_name].nodes:
                    nodes.append(
                        BaseNode(
                            name=node.name,
                            format=node.format,
                            interpreter=node.interpreter,
                            modifiers=node.modifiers[:],
                            depends_on=node.depends_on,
                            dynamic=node.dynamic,
                            ignore=node.ignore
                        )
                    )
                
                print( session.fields)
                i += 1
                continue

            if line.strip().startswith("loop "):
                match = re.match(r"loop\s+(.+?)\s+to\s+€(\w+):", line.strip())
                if not match:
                    Logger.error(f"Malformed loop: {line.strip()}")
                    i += 1
                    continue

                count_from, target = match.groups()
                count_from = count_from.strip()
                target = target.strip()

                count, loop_lines = ParserUtils.count_size_of_block_structure(lines, i)
                loop_children = []

                for loop_line in loop_lines:
                    if ":" not in loop_line:
                        i += 1
                        continue

                    # Modifier-extraktion
                    mods = []
                    if "," in loop_line:
                        loop_line, mod_str = [x.strip() for x in loop_line.split(",", 1)]
                        mods = list(mod_str)

                    # Vanlig parsing av name: format
                    name, rest = [x.strip() for x in loop_line.split(":", 1)]
                    fmt = rest

                    ignore = False
                    if name == "_":
                        name = f"__anon_{anon_counter}"
                        ignore = True
                        anon_counter += 1

                    child_node = BaseNode(
                        name=name,
                        format=fmt,
                        interpreter="struct",
                        modifiers=mods,
                        ignore=ignore
                    )
                    loop_children.append(child_node)

                nodes.append(
                    LoopNode(
                        name=f"{target}_loop",
                        format="",
                        interpreter="loop",
                        count_from=count_from,
                        target=target,
                        children=loop_children,
                        loop_line_count=len(loop_lines)
                    )
                )

                Logger.debug(f"Parsed loop: {target}_loop with {len(loop_children)} fields (from {count_from})")

                i += count + 1
                continue

            if "," in line:
                parts = [x.strip() for x in line.split(",", 1)]
                line = parts[0]
                mods = list(parts[1]) if len(parts) > 1 else []
            else:
                mods = []

            if line.strip().startswith("_"):
                ignore = True
            else:
                ignore = False


            if "=" in line:
                name, value = [x.strip() for x in line.split("=", 1)]

                # slice detection
                if "[" in value and value.startswith("€") and ":" in value:
                    match = re.match(r"€(\w+)\[([^\]:]*):([^\]:]*)(?::([^\]]+))?\]", value)
                    if match:
                        depends_on, start, stop, step = match.groups()
                        session.variables[name] = VariableNode(
                            name=name,
                            raw_value=value,
                            format=value,
                            interpreter="slice",
                            modifiers=mods,
                            depends_on=depends_on,
                            dynamic=True
                        )
                        i += 1
                        continue

                # vanlig €variabel
                elif value.startswith("€"):
                    session.variables[name] = VariableNode(
                        name=name,
                        raw_value=value,
                        format=value,
                        interpreter="var",
                        modifiers=mods,
                        depends_on=value[1:],
                        dynamic=True
                    )
                    i += 1
                    continue

                # fallback: int eller str
                try:
                    literal_value = int(value)
                except ValueError:
                    literal_value = value  # fallback som string

                session.variables[name] = VariableNode(
                    name=name,
                    raw_value=value,
                    value=literal_value,
                    format=None,
                    interpreter="literal",
                    modifiers=mods,
                    ignore=ignore
                )
                i += 1
                continue

            if ':' in line:
                name, right = [x.strip() for x in line.split(":", 1)]
                fmt = right  # Inga fler modifierare här

                  # Check for slicing syntax
                slice_match = re.match(r"€(\w+)\[([^\]:]*):([^\]:]*)(?::([^\]]+))?\]$", fmt)
                if slice_match:
                    var_name, start, stop, step = slice_match.groups()
                    node = BaseNode(
                        name=name,
                        format=fmt,
                        interpreter="slice",
                        depends_on=var_name,
                        dynamic=True,
                        modifiers=mods,
                        raw_offset=None,
                        raw_length=None,
                        raw_data=None,
                        value=None,
                        ignore=ignore
                    )
                    # Optional: attach raw slice data
                    node.slice_raw = {
                        "start": start if start else None,
                        "stop": stop if stop else None,
                        "step": step if step else None
                    }
                    nodes.append(node)
                    i += 1
                    continue

                # Variabelreferens med dynamisk längd (ex: €len's)
                match = re.match(r"€(\w+)'([a-zA-Z])", fmt)
                if match:
                    var_name, struct_fmt = match.groups()
                    node = BaseNode(
                        name=name,
                        format=fmt,
                        interpreter="struct",
                        depends_on=var_name,
                        dynamic=True,
                        modifiers=mods,
                        ignore=ignore
                    )
                    nodes.append(node)
                    i += 1
                    continue

                # Vanlig variabelreferens (ex: €seed)
                elif fmt.startswith("€"):
                    var_name = fmt[1:]
                    node = BaseNode(
                        name=name,
                        format=fmt,
                        interpreter="var",
                        depends_on=var_name,
                        modifiers=mods,
                        ignore=ignore
                    )
                    nodes.append(node)
                    i += 1
                    continue

                # Annars vanlig struktdefinition (ex: cmd: B)
                node = BaseNode(
                    name=name,
                    format=fmt,
                    interpreter="struct",
                    modifiers=mods,
                    ignore=ignore
                )
                nodes.append(node)
                i += 1
                continue
            
            i += 1

        session.fields = nodes
        return nodes
    
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

    def pretty_print_compact_all(session):
        print("\n=== Compact Variables ===")
        for idx, (name, var) in enumerate(session.variables.items(), start=1):
            display_name = name if name != "_" else "_"
            mod_str = f" [{', '.join(var.modifiers)}]" if hasattr(var, "modifiers") and var.modifiers else ""
            interp = getattr(var, "interpreter", "literal")
            value = getattr(var, "raw_value", var)
            print(f"[{idx}] {display_name} = {value} ({interp}){mod_str}")

        print("\n=== Compact Blocks ===")
        for bidx, (block_name, block) in enumerate(session.blocks.items(), start=1):
            print(f"[{bidx}] Block: {block_name}")
            for i, node in enumerate(block.nodes, start=1):
                name = node.name if not getattr(node, "ignore", False) else "_"
                mod_str = f" [{', '.join(node.modifiers)}]" if node.modifiers else ""
                print(f"     [{i}] {name} : {node.format} ({node.interpreter}){mod_str}")

        print("\n=== Compact Nodes ===")
        for idx, node in enumerate(session.fields, start=1):
            name = node.name if not getattr(node, "ignore", False) else "_"
            mod_str = f" [{', '.join(node.modifiers)}]" if node.modifiers else ""
            print(f"[{idx}] {name} : {node.format} ({node.interpreter}){mod_str}")

            if isinstance(node, LoopNode):
                for cidx, child in enumerate(node.children, start=1):
                    cname = child.name if not getattr(child, "ignore", False) else "_"
                    cmod = f" [{', '.join(child.modifiers)}]" if child.modifiers else ""
                    print(f"     [{cidx}] {cname} : {child.format} ({child.interpreter}){cmod}")

    def pretty_print_list_variables(variables: dict):
        print("=== Variables ===")
        if not variables:
            print("  (none)")
        for i, (key, value) in enumerate(variables.items(), 1):
            print(f"[{i}] {key} = {value}")
        print()

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