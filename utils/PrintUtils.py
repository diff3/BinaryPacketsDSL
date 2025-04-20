#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from modules.Session import PacketSession, BaseNode, IfNode, VariableNode, LoopNode, BlockDefinition, get_session, RandSeqNode
from utils.Logger import Logger


class SessionPrint():
    @staticmethod
    def pretty_print_compact_all(session: PacketSession):
        SessionPrint.print_compact_variables(session)
        SessionPrint.print_compact_blocks(session)
        SessionPrint.print_compact_nodes(session)

    @staticmethod
    def print_compact_variables(session: PacketSession):
        Logger.to_log("\n=== Compact Variables ===")
        if not session.variables:
            Logger.to_log("[empty]")
            return

        for idx, (name, var) in enumerate(session.variables.items(), start=1):
            display_name = name if name != "_" else "_"
            mod_str = f" [{', '.join(var.modifiers)}]" if hasattr(var, "modifiers") and var.modifiers else ""
            interp = getattr(var, "interpreter", "literal")
            value = getattr(var, "raw_value", var)
            Logger.to_log(f"[{idx}] {display_name} = {value} ({interp}){mod_str}")

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


    @staticmethod
    def print_compact_nodes(session: PacketSession):
        Logger.to_log("\n=== Compact Nodes ===")
        if not session.fields:
            Logger.to_log("[empty]")
            return

        for idx, node in enumerate(session.fields, start=1):
            SessionPrint._print_node(node, idx, indent=0)

    @staticmethod
    def _print_node(node, idx, indent=0):
        prefix = "    " * indent
        name = node.name if not getattr(node, "ignore", False) else "_"
        mod_str = f" [{', '.join(node.modifiers)}]" if hasattr(node, "modifiers") and node.modifiers else ""
        fmt = getattr(node, "format", "unknown")
        interpreter = getattr(node, "interpreter", "unknown")

        Logger.to_log(f"{prefix}[{idx}] {name} : {fmt} ({interpreter}){mod_str}")

        # Hantera speciella noder
        if isinstance(node, IfNode):
            SessionPrint._print_ifnode(node, indent + 1)
        elif isinstance(node, LoopNode):
            for cidx, child in enumerate(node.children, start=1):
                SessionPrint._print_node(child, cidx, indent + 1)
        elif isinstance(node, BlockDefinition):
            for cidx, child in enumerate(node.nodes, start=1):
                SessionPrint._print_node(child, cidx, indent + 1)
        elif isinstance(node, RandSeqNode):   # <-- Lägg till denna!
            for cidx, child in enumerate(node.children, start=1):
                SessionPrint._print_node(child, cidx, indent + 1)

    @staticmethod
    def _print_ifnode(ifnode: IfNode, indent=0):
        prefix = "    " * indent

        Logger.to_log(f"{prefix}[True branch]")
        for cidx, child in enumerate(ifnode.true_branch, start=1):
            SessionPrint._print_node(child, cidx, indent + 1)

        if ifnode.elif_branches:
            for eidx, (condition, branch) in enumerate(ifnode.elif_branches, start=1):
                Logger.to_log(f"{prefix}[Elif branch {eidx}: {condition}]")
                for cidx, child in enumerate(branch, start=1):
                    SessionPrint._print_node(child, cidx, indent + 1)

        if ifnode.false_branch:
            Logger.to_log(f"{prefix}[False branch]")
            for cidx, child in enumerate(ifnode.false_branch, start=1):
                SessionPrint._print_node(child, cidx, indent + 1)