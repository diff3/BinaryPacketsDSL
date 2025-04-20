#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from modules.Session import PacketSession, BaseNode, IfNode, VariableNode, LoopNode, BlockDefinition, get_session
from utils.Logger import Logger


class SessionPrint():
    @staticmethod
    def print_compact_variables(session):
        Logger.to_log("\n=== Compact Variables ===")
        if not session.variables:
            # print("[empty]")
            return
        
        for idx, (name, var) in enumerate(session.variables.items(), start=1):
            display_name = name if name != "_" else "_"
            if hasattr(var, "modifiers"):
                mod_str = f" [{', '.join(var.modifiers)}]" if var.modifiers else ""
                interp = getattr(var, "interpreter", "literal")
                value = getattr(var, "raw_value", var)
                Logger.to_log(f"[{idx}] {display_name} = {value} ({interp}){mod_str}")
            else:
                Logger.to_log(f"[{idx}] {display_name} = {var} (literal)")

    @staticmethod
    def print_compact_blocks(session):
        Logger.to_log("\n=== Compact Blocks ===")
        if not session.blocks:
            Logger.debug("[empty]")
            return
        
        for bidx, (block_name, block) in enumerate(session.blocks.items(), start=1):
            Logger.to_log(f"[{bidx}] Block: {block_name}")
            for i, node in enumerate(block.nodes, start=1):
                name = node.name if not getattr(node, "ignore", False) else "_"
                mod_str = f" [{', '.join(node.modifiers)}]" if node.modifiers else ""
                Logger.to_log(f"     [{i}] {name} : {node.format} ({node.interpreter}){mod_str}")

    @staticmethod
    def print_compact_nodes(session):
        Logger.to_log("\n=== Compact Nodes ===")
        if not session.fields:
            Logger.debug("[empty]")
            return

        for idx, node in enumerate(session.fields, start=1):
            name = node.name if not getattr(node, "ignore", False) else "_"
            mod_str = f" [{', '.join(node.modifiers)}]" if node.modifiers else ""

            Logger.to_log(f"[{idx}] {name} : {node.format} ({node.interpreter}){mod_str}")

            if isinstance(node, LoopNode):
                for cidx, child in enumerate(node.children, start=1):
                    cname = child.name if not getattr(child, "ignore", False) else "_"
                    cmod = f" [{', '.join(child.modifiers)}]" if child.modifiers else ""
                    Logger.to_log(f"     [{cidx}] {cname} : {child.format} ({child.interpreter}){cmod}")

            elif isinstance(node, IfNode):
                SessionPrint._print_compact_ifnode(node)

    @staticmethod
    def _print_compact_ifnode(ifnode):
        Logger.to_log("     [True branch]")
        for cidx, child in enumerate(ifnode.true_branch, start=1):
            name = child.name if not getattr(child, "ignore", False) else "_"
            mod_str = f" [{', '.join(child.modifiers)}]" if child.modifiers else ""
            Logger.to_log(f"         [{cidx}] {name} : {child.format} ({child.interpreter}){mod_str}")

        if ifnode.elif_branches:
            for eidx, (condition, branch) in enumerate(ifnode.elif_branches, start=1):
                Logger.to_log(f"     [Elif branch {eidx}: {condition}]")
                for cidx, child in enumerate(branch, start=1):
                    name = child.name if not getattr(child, "ignore", False) else "_"
                    mod_str = f" [{', '.join(child.modifiers)}]" if child.modifiers else ""
                    Logger.to_log(f"         [{cidx}] {name} : {child.format} ({child.interpreter}){mod_str}")

        if ifnode.false_branch:
            Logger.to_log("     [False branch]")
            for cidx, child in enumerate(ifnode.false_branch, start=1):
                name = child.name if not getattr(child, "ignore", False) else "_"
                mod_str = f" [{', '.join(child.modifiers)}]" if child.modifiers else ""
                Logger.to_log(f"         [{cidx}] {name} : {child.format} ({child.interpreter}){mod_str}")

    @staticmethod
    def pretty_print_compact_all(session):
        SessionPrint.print_compact_variables(session)
        SessionPrint.print_compact_blocks(session)
        SessionPrint.print_compact_nodes(session)