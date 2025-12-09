#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from modules.Session import (
    PacketSession, BaseNode, IfNode, VariableNode, LoopNode,
    BlockDefinition, get_session, RandSeqNode, BitmaskNode
)
from utils.Logger import Logger


class SessionPrint:

    @staticmethod
    def pretty_print_compact_all(session: PacketSession):
        SessionPrint.print_compact_variables(session)
        SessionPrint.print_compact_blocks(session)
        SessionPrint.print_compact_nodes(session)

    # ---------------------------------------------------------
    # VARIABLES  (reads from session.scope)
    # ---------------------------------------------------------
    @staticmethod
    def print_compact_variables(session: PacketSession):
        Logger.to_log("\n=== Compact Variables ===")

        scope_vars = {}

        # Global variables
        for k, v in session.scope.global_vars.items():
            scope_vars[k] = v

        # Local scopes (inner → outer)
        for scope in session.scope.scope_stack:
            for k, v in scope.items():
                scope_vars[k] = v

        if not scope_vars:
            Logger.to_log("[empty]")
            return

        for idx, (name, value) in enumerate(scope_vars.items(), start=1):
            Logger.to_log(f"[{idx}] {name} = {value}")

    # ---------------------------------------------------------
    # BLOCKS
    # ---------------------------------------------------------
    @staticmethod
    def print_compact_blocks(session: PacketSession):
        Logger.to_log("\n=== Compact Blocks ===")
        if not session.blocks:
            Logger.to_log("[empty]")
            return

        for bidx, (block_name, block) in enumerate(session.blocks.items(), start=1):
            Logger.to_log(f"[{bidx}] Block: {block_name}")
            for idx, node in enumerate(block.nodes, start=1):
                SessionPrint._print_node(node, idx, indent=1)

    # ---------------------------------------------------------
    # NODES
    # ---------------------------------------------------------
    @staticmethod
    def print_compact_nodes(session: PacketSession):
        Logger.to_log("\n=== Compact Nodes ===")
        if not session.fields:
            Logger.to_log("[empty]")
            return

        for idx, node in enumerate(session.fields, start=1):
            SessionPrint._print_node(node, idx, indent=0)

    # ---------------------------------------------------------
    # NODE PRINTING
    # ---------------------------------------------------------
    @staticmethod
    def _print_node(node, idx, indent=0):
        prefix = "    " * indent

        if node is None:
            Logger.to_log(f"{prefix}[{idx}] [None node]")
            return

        # tuple → unwrap (t.ex. efter EncoderHandler.cleanup)
        if isinstance(node, tuple):
            node = node[0]

        interpreter = getattr(node, "interpreter", None)
        name = getattr(node, "name", "_")
        fmt = getattr(node, "format", None)
        fmt_text = fmt if fmt is not None else "?"

        # common debug-info (value + raw span om de finns)
        value = getattr(node, "value", None)
        raw_off = getattr(node, "raw_offset", None)
        raw_len = getattr(node, "raw_length", None)

        span = ""
        if raw_off is not None and raw_len is not None:
            span = f" @[{raw_off}+{raw_len}]"

        mod_str = ""
        if hasattr(node, "modifiers") and node.modifiers:
            mod_str = " [" + ", ".join(node.modifiers) + "]"

        # -----------------------
        # PADDING
        # -----------------------
        if interpreter == "padding":
            # format är oftast str(N) eller "", fallback till value
            size = fmt if fmt not in (None, "") else getattr(node, "value", 0)
            Logger.to_log(f"{prefix}[{idx}] padding ({size} bytes){span}")
            return

        # -----------------------
        # SEEK
        # -----------------------
        if interpreter == "seek":
            off = fmt if fmt is not None else getattr(node, "value", None)
            Logger.to_log(f"{prefix}[{idx}] seek (to {off}){span}")
            return

        # -----------------------
        # STANDARD NODE HEADER
        # -----------------------
        Logger.to_log(
            f"{prefix}[{idx}] {name} : {fmt_text} ({interpreter}){mod_str}{span} value={value}"
        )

        # -----------------------
        # CHILDREN
        # -----------------------

        # IF node
        if isinstance(node, IfNode):
            SessionPrint._print_ifnode(node, indent + 1)
            return

        # LOOP node
        if isinstance(node, LoopNode):
            Logger.to_log(f"{prefix}    (Loop count_expr={node.count_from}, target='{node.target}')")
            for cidx, child in enumerate(node.children, start=1):
                SessionPrint._print_node(child, cidx, indent + 1)
            return

        # BlockDefinition
        if isinstance(node, BlockDefinition):
            for cidx, child in enumerate(node.nodes, start=1):
                SessionPrint._print_node(child, cidx, indent + 1)
            return

        # RandSeqNode
        if isinstance(node, RandSeqNode):
            Logger.to_log(f"{prefix}    (RandSeq count={node.count_from})")
            for cidx, child in enumerate(node.children, start=1):
                SessionPrint._print_node(child, cidx, indent + 1)
            return

        # BitmaskNode
        if isinstance(node, BitmaskNode):
            Logger.to_log(f"{prefix}    (Bitmask {node.size} bits)")
            for cidx, child in enumerate(node.children, start=1):
                SessionPrint._print_node(child, cidx, indent + 1)
            return

    # ---------------------------------------------------------
    # IF NODE PRINTING
    # ---------------------------------------------------------
    @staticmethod
    def _print_ifnode(ifnode: IfNode, indent=0):
        prefix = "    " * indent

        Logger.to_log(f"{prefix}[IF condition: {ifnode.condition}]")
        Logger.to_log(f"{prefix}[True branch]")
        for cidx, child in enumerate(ifnode.true_branch, start=1):
            SessionPrint._print_node(child, cidx, indent + 1)

        if ifnode.elif_branches:
            for eidx, (condition, branch) in enumerate(ifnode.elif_branches, start=1):
                Logger.to_log(f"{prefix}[Elif {eidx}: {condition}]")
                for cidx, child in enumerate(branch, start=1):
                    SessionPrint._print_node(child, cidx, indent + 1)

        if ifnode.false_branch:
            Logger.to_log(f"{prefix}[False branch]")
            for cidx, child in enumerate(ifnode.false_branch, start=1):
                SessionPrint._print_node(child, cidx, indent + 1)

    @staticmethod
    def count_size_of_block_structure(lines: list[str], i: int) -> list:
        """
        Robust block extractor:
        - Detekterar indent (tabs/spaces)
        - Tar med alla rader med större indent än parent
        - Tomrader räknas som barn (behövs för DSL)
        """
        block_lines = []

        parent_indent = len(lines[i]) - len(lines[i].lstrip())
        i += 1

        while i < len(lines):
            raw = lines[i]
            stripped = raw.strip()

            indent = len(raw) - len(raw.lstrip())

            # block slut?
            if stripped and indent <= parent_indent:
                break

            block_lines.append(raw)
            i += 1

        return [len(block_lines), block_lines]