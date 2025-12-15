#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NodeTreeParser

Parses the DSL .def files into an AST of nodes (BaseNode, LoopNode, IfNode, etc).
Backwards compatible with the current system (DecoderHandler, DslRuntime).
Prepared for future DSL changes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Any

from modules.Session import (
    BaseNode,
    IfNode,
    VariableNode,
    LoopNode,
    BlockDefinition,
    BitmaskNode,
    UncompressNode,
    PackedGuidNode,
    SliceNode,
    get_session,
)
from modules.ModifierParser import ModifierUtils
from utils.ParserUtils import ParserUtils
from utils.Logger import Logger

session = get_session()


# =====================================================================
# PARSE CONTEXT
# =====================================================================

@dataclass
class ParseContext:
    """Holds parsing-time state separate from the global session."""
    variables: Dict[str, VariableNode] = field(default_factory=dict)
    blocks: Dict[str, BlockDefinition] = field(default_factory=dict)
    anon_counter: int = 0


# =====================================================================
# MAIN PARSER
# =====================================================================

class NodeTreeParser:

    @staticmethod
    def parse(case: tuple) -> List[Any]:
        """
        case → (name, lines, raw_bytes, expected)
        Returns parsed top-level nodes.
        """

        name, lines, *_ = case

        ctx = ParseContext()
        nodes: List[Any] = []

        # Reset session state for new parse
        session.fields = []
        session.blocks = {}
        session.variables = {}

        # Remove comments, strip reserved keywords
        lines = ParserUtils.remove_comments_and_reserved(lines)

        total = len(lines)
        i = 0

        while i < total:
            raw = lines[i]
            stripped = raw.strip()

            if not stripped:
                i += 1
                continue


            # ----------- variable assignment ------------
            eq_pos = stripped.find("=")
            colon_pos = stripped.find(":")
            if eq_pos != -1 and not stripped.startswith("if ") and (colon_pos == -1 or eq_pos < colon_pos):
                parsed = NodeTreeParser.parse_variable(stripped, ctx)
                ctx.variables[parsed.name] = parsed
                nodes.append(parsed)
                i += 1
                continue

            # ----------------- block -----------------
            if stripped.startswith("block "):
                parsed, consumed = NodeTreeParser.parse_block(lines, i, ctx)
                if parsed:
                    ctx.blocks[parsed.name] = parsed
                i += consumed
                continue

            # ----------------- loop ------------------
            if stripped.startswith("loop "):
                parsed, consumed = NodeTreeParser.parse_loop(lines, i, ctx)
                if parsed:
                    nodes.append(parsed)
                i += consumed
                continue

            # ---------------- uncompress -------------
            if stripped.startswith("uncompress "):
                parsed, consumed = NodeTreeParser.parse_uncompress(lines, i, ctx)
                if parsed:
                    nodes.append(parsed)
                i += consumed
                continue

            # ---------------- bitmask ----------------
            if stripped.startswith("bitmask "):
                parsed, consumed = NodeTreeParser.parse_bitmask(lines, i, ctx)
                if parsed:
                    nodes.append(parsed)
                i += consumed
                continue

            # ---------------- if ---------------------
            if stripped.startswith("if "):
                parsed, consumed = NodeTreeParser.parse_if(lines, i, ctx)
                if parsed:
                    nodes.append(parsed)
                i += consumed
                continue

            # ---------------- include ----------------
            if stripped.startswith("include "):
                NodeTreeParser._handle_include(stripped, nodes, ctx)
                i += 1
                continue

            # ------------- normal field --------------
            parsed = NodeTreeParser.parse_line_to_node(raw, ctx)

            # Variabler hanteras numera av parse_variable() högre upp
            # så här ska vi *inte* fånga dem längre.
            if parsed:
                nodes.append(parsed)

            i += 1
            continue

        # ---------------------------------------------------
        # IMPORTANT FIX:
        # Reset processed-flaggan på alla noder
        # ---------------------------------------------------
        for n in nodes:
            if hasattr(n, "processed"):
                n.processed = False

            # även barnnoder i strukturer måste nollställas
            if hasattr(n, "children") and n.children:
                for c in n.children:
                    if hasattr(c, "processed"):
                        c.processed = False

        # Push into session for DecoderHandler
        session.fields = nodes
        session.blocks = ctx.blocks
        session.variables = ctx.variables

        return nodes

    # =====================================================================
    # VISIBILITY PREFIX
    # =====================================================================
    @staticmethod
    def _parse_visibility(raw_name: str):
        """
        Extract visibility prefix ('-' internal, '+' explicit) and return
        (clean_name, visible, payload, prefix).
        """
        name = raw_name.strip()
        prefix = None
        visible = True
        payload = True

        if name.startswith("-"):
            prefix = "-"
            visible = False
            payload = False
            name = name[1:].strip()
        elif name.startswith("+"):
            prefix = "+"
            visible = True
            payload = True
            name = name[1:].strip()

        return name, visible, payload, prefix

    # =====================================================================
    # INCLUDE
    # =====================================================================

    @staticmethod
    def _handle_include(stripped: str, target_list: List[Any], ctx: ParseContext):
        match = re.match(r"include\s+(\w+):?", stripped)
        if not match:
            Logger.warning(f"Malformed include '{stripped}'")
            return

        block_name = match.group(1)
        block = ctx.blocks.get(block_name)

        if not block:
            Logger.error(f"Include: Unknown block '{block_name}'")
            return

        for n in block.nodes:
            target_list.append(n)

    # =====================================================================
    # PADDING
    # =====================================================================

    @staticmethod
    def parse_padding(line: str) -> Optional[BaseNode]:
        parts = line.strip().split()

        # padding → zero-length padding
        if len(parts) == 1:
            node = BaseNode(
                name="_",
                format="0",
                interpreter="padding",
                modifiers=[],
                encode_modifiers=[],
                depends_on=None,
                dynamic=False,
                ignore=False,
            )
            node.size = 0
            node.value = 0
            return node

        # padding N
        if len(parts) == 2 and parts[1].isdigit():
            N = int(parts[1])
            node = BaseNode(
                name="_",
                format=str(N),
                interpreter="padding",
                modifiers=[],
                encode_modifiers=[],
                depends_on=None,
                dynamic=False,
                ignore=False,
            )
            node.size = N
            node.value = N
            return node

        Logger.warning(f"Malformed padding '{line}'")
        return None

    # =====================================================================
    # SEEK
    # =====================================================================

    @staticmethod
    def parse_seek(line: str) -> Optional[BaseNode]:
        parts = line.strip().split()
        if len(parts) == 2 and parts[1].isdigit():
            return BaseNode(
                name="seek",
                format=parts[1],
                interpreter="seek",
                modifiers=[],
                encode_modifiers=[],
                depends_on=None,
                dynamic=False,
                ignore=False,
            )

        Logger.warning(f"Malformed seek '{line}'")
        return None

    # =====================================================================
    # BITMASK BLOCK
    # =====================================================================

    @staticmethod
    def parse_bitmask(lines: List[str], start_idx: int, ctx: ParseContext) -> Tuple[Optional[BitmaskNode], int]:
        line = lines[start_idx].strip()
        match = re.match(r"bitmask\s+(\d+)", line)
        if not match:
            Logger.warning(f"Malformed bitmask: {line}")
            return None, 1

        size = int(match.group(1))

        block_count, block_lines = ParserUtils.count_size_of_block_structure(lines, start_idx)

        children: List[Any] = []
        for blk in block_lines:
            parsed = NodeTreeParser.parse_line_to_node(blk.strip(), ctx)
            if parsed:
                children.append(parsed)

        node = BitmaskNode(
            name="_",
            size=size,
            children=children
        )

        return node, block_count + 1

    # =====================================================================
    # BLOCK
    # =====================================================================

    @staticmethod
    def parse_block(lines: List[str], start_idx: int, ctx: ParseContext) -> Tuple[Optional[BlockDefinition], int]:
        line = lines[start_idx]
        match = re.match(r"block\s+(\w+):", line)
        if not match:
            Logger.warning(f"Malformed block: {line.strip()}")
            return None, 1

        block_name = match.group(1)
        block_count, block_lines = ParserUtils.count_size_of_block_structure(lines, start_idx)

        block_nodes: List[Any] = []
        i = 0

        while i < len(block_lines):
            raw = block_lines[i].strip()
            if not raw:
                i += 1
                continue

            if raw.startswith("if "):
                parsed, consumed = NodeTreeParser.parse_if(block_lines, i, ctx)
            elif raw.startswith("loop "):
                parsed, consumed = NodeTreeParser.parse_loop(block_lines, i, ctx)
            elif raw.startswith("uncompress "):
                parsed, consumed = NodeTreeParser.parse_uncompress(block_lines, i, ctx)
            elif raw.startswith("bitmask "):
                parsed, consumed = NodeTreeParser.parse_bitmask(block_lines, i, ctx)
            elif raw.startswith("include "):
                tmp: List[Any] = []
                NodeTreeParser._handle_include(raw, tmp, ctx)
                for n in tmp:
                    block_nodes.append(n)
                i += 1
                continue
            else:
                parsed = NodeTreeParser.parse_line_to_node(block_lines[i], ctx)
                consumed = 1

            if "=" in raw and not raw.startswith("if "):
                parsed = NodeTreeParser.parse_variable(raw, ctx)
                ctx.variables[parsed.name] = parsed
                block_nodes.append(parsed)
                i += 1
                continue
            else:
                if parsed:
                    block_nodes.append(parsed)

            i += consumed

        node = BlockDefinition(name=block_name, nodes=block_nodes)
        return node, block_count + 1

    # =====================================================================
    # LOOP
    # =====================================================================

    @staticmethod
    def parse_loop(lines: List[str], start_idx: int, ctx: ParseContext) -> Tuple[Optional[LoopNode], int]:
        line = lines[start_idx]
        match = re.match(r"\s*loop\s+(.+?)\s+to\s+€?(\w+):?", line)
        if not match:
            Logger.warning(f"Malformed loop: {line.strip()}")
            return None, 1

        count_expr, target = match.groups()

        block_count, block_lines = ParserUtils.count_size_of_block_structure(lines, start_idx)

        children: List[Any] = []
        i = 0

        while i < len(block_lines):
            raw = block_lines[i].strip()
            if not raw:
                i += 1
                continue

            if raw.startswith("if "):
                parsed, consumed = NodeTreeParser.parse_if(block_lines, i, ctx)
            elif raw.startswith("loop "):
                parsed, consumed = NodeTreeParser.parse_loop(block_lines, i, ctx)
            elif raw.startswith("uncompress "):
                parsed, consumed = NodeTreeParser.parse_uncompress(block_lines, i, ctx)
            elif raw.startswith("bitmask "):
                parsed, consumed = NodeTreeParser.parse_bitmask(block_lines, i, ctx)
            elif raw.startswith("include "):
                tmp: List[Any] = []
                NodeTreeParser._handle_include(raw, tmp, ctx)
                for n in tmp:
                    children.append(n)
                i += 1
                continue
            else:
                parsed = NodeTreeParser.parse_line_to_node(block_lines[i], ctx)
                consumed = 1

            if "=" in raw and not raw.startswith("if "):
                parsed = NodeTreeParser.parse_variable(raw, ctx)
                ctx.variables[parsed.name] = parsed
                children.append(parsed)
                i += 1
                continue
            else:
                if parsed:
                    children.append(parsed)

            i += consumed

        node = LoopNode(
            name=target,
            format="",
            interpreter="loop",
            count_from=count_expr,
            target=target,
            dynamic=("€" in count_expr),
            children=children
        )

        return node, block_count + 1

    # =====================================================================
    # UNCOMPRESS
    # =====================================================================

    @staticmethod
    def parse_uncompress(lines: List[str], start_idx: int, ctx: ParseContext) -> Tuple[Optional[UncompressNode], int]:
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
            parsed = NodeTreeParser.parse_line_to_node(blk.strip(), ctx)
            if parsed:
                children.append(parsed)

        node = UncompressNode(
            name="uncompress",
            format="",
            interpreter="uncompress",
            algo=algo,
            length_expr=length_expr,
            children=children
        )

        return node, block_count + 1

    # =====================================================================
    # STRUCT OR IF (used inside if-blocks)
    # =====================================================================

    @staticmethod
    def parse_struct_or_if(lines: List[str], idx: int, ctx: ParseContext):
        raw = lines[idx]
        stripped = raw.strip()

        # Vars
        eq_pos = stripped.find("=")
        colon_pos = stripped.find(":")
        if eq_pos != -1 and not stripped.startswith("if ") and (colon_pos == -1 or eq_pos < colon_pos):
            parsed = NodeTreeParser.parse_variable(stripped, ctx)
            ctx.variables[parsed.name] = parsed
            return parsed, 1
        # padding
        if stripped.startswith("padding"):
            return NodeTreeParser.parse_padding(raw), 1

        # flushbit alias
        if stripped in ("flushbit", "flushbits"):
            return NodeTreeParser.parse_padding("padding 0"), 1

        # seek
        if stripped.startswith("seek "):
            return NodeTreeParser.parse_seek(raw), 1

        # uncompress
        if stripped.startswith("uncompress "):
            return NodeTreeParser.parse_uncompress(lines, idx, ctx)

        # bitmask
        if stripped.startswith("bitmask "):
            return NodeTreeParser.parse_bitmask(lines, idx, ctx)

        # loop
        if stripped.startswith("loop "):
            return NodeTreeParser.parse_loop(lines, idx, ctx)

        # nested if
        if stripped.startswith("if "):
            return NodeTreeParser.parse_if(lines, idx, ctx)

        # normal struct
        return NodeTreeParser.parse_line_to_node(raw, ctx), 1

    # =====================================================================
    # IF / ELIF / ELSE
    # =====================================================================

    @staticmethod
    def parse_if(lines, start_idx, ctx):
        base_indent = len(re.match(r"^\s*", lines[start_idx])[0])
        header = lines[start_idx].strip()

        condition = header[3:].rstrip(":").strip()

        true_branch = []
        false_branch = []
        elif_branches = []

        current_branch = true_branch
        current_condition = condition

        i = start_idx + 1
        total = len(lines)

        while i < total:
            raw = lines[i]
            stripped = raw.strip()

            if not stripped:
                i += 1
                continue

            indent = len(re.match(r"^\s*", raw)[0])

            # ---------- FIX: only deeper indent belongs to IF block ----------
            if indent <= base_indent:
                break

            # ---------- elif ----------
            if stripped.startswith("elif ") and indent == base_indent:
                current_branch = []
                current_condition = stripped[5:].rstrip(":").strip()
                elif_branches.append((current_condition, current_branch))
                i += 1
                continue

            # ---------- else ----------
            if stripped.startswith("else") and indent == base_indent:
                current_condition = "else"
                current_branch = false_branch
                i += 1
                continue

            # ---------- child inside IF ----------
            eq_pos = stripped.find("=")
            colon_pos = stripped.find(":")
            if eq_pos != -1 and not stripped.startswith("if ") and (colon_pos == -1 or eq_pos < colon_pos):
                parsed = NodeTreeParser.parse_variable(stripped, ctx)
                ctx.variables[parsed.name] = parsed
                current_branch.append(parsed)
                i += 1
                continue

            parsed, consumed = NodeTreeParser.parse_struct_or_if(lines, i, ctx)
            if parsed:
                current_branch.append(parsed)

            i += consumed

        node = IfNode(
            name=f"if_{condition}",
            format="",
            interpreter="if",
            condition=condition,
            true_branch=true_branch,
            false_branch=false_branch or None,
            elif_branches=elif_branches or None,
        )

        return node, i - start_idx

    # =====================================================================
    # SINGLE-LINE FIELD → NODE
    # =====================================================================

    @staticmethod
    def parse_line_to_node(line: str, ctx: ParseContext):
        stripped = line.strip()
        if not stripped:
            return None

        # ------------------------------------------------------------
        # combine syntax:  foo: combine seed
        # ------------------------------------------------------------
        if ":" in stripped and "combine" in stripped:
            left, rhs = [x.strip() for x in stripped.split(":", 1)]
            parts = rhs.split()

            if len(parts) >= 2 and parts[0] == "combine":
                left, visible, payload, prefix = NodeTreeParser._parse_visibility(left)
                left, ignore, ctx.anon_counter = ParserUtils.check_ignore_and_rename(
                    left, ctx.anon_counter
                )

                node = BaseNode()
                node.name = left
                node.format = parts[1]
                node.interpreter = "combine"
                node.modifiers = []
                node.encode_modifiers = []
                node.value = None
                node.ignore = ignore
                node.visible = visible
                node.payload = payload
                node.visibility_prefix = prefix
                node.has_io = False
                return node

        # ------------------------------------------------------------
        # padding / seek / flushbit
        # ------------------------------------------------------------
        if stripped.startswith("padding"):
            return NodeTreeParser.parse_padding(line)

        if stripped.startswith("seek "):
            return NodeTreeParser.parse_seek(line)

        if stripped in ("flushbit", "flushbits"):
            return NodeTreeParser.parse_padding("padding 0")

        # ------------------------------------------------------------
        # "+=" append
        # ------------------------------------------------------------
        if "+=" in stripped:
            name, rest = [x.strip() for x in stripped.split("+=", 1)]
            fmt, mods, enc_mods = ModifierUtils.parse_modifiers(rest)

            name, visible, payload, prefix = NodeTreeParser._parse_visibility(name)
            name, ignore, ctx.anon_counter = ParserUtils.check_ignore_and_rename(
                name, ctx.anon_counter
            )

            node = BaseNode()
            node.name = name
            node.format = fmt
            node.interpreter = "append"
            node.modifiers = mods
            node.encode_modifiers = enc_mods
            node.value = None
            node.ignore = ignore
            node.visible = visible
            node.payload = payload
            node.visibility_prefix = prefix
            node.has_io = True
            return node
        
        # ------------------------------------------------------------
        # Buffer assignment: foo[3] <- B
        # ------------------------------------------------------------
        if "<-" in stripped:
            left, right = [x.strip() for x in stripped.split("<-", 1)]
            fmt, mods, enc_mods = ModifierUtils.parse_modifiers(right)

            left, visible, payload, prefix = NodeTreeParser._parse_visibility(left)
            buf_assign = re.fullmatch(r"(\w+)\[(\d+)(?:-(\d+))?\]", left)
            if buf_assign:
                buf_name, start_idx, end_idx = buf_assign.group(1), int(buf_assign.group(2)), buf_assign.group(3)
                buf_name, ignore, ctx.anon_counter = ParserUtils.check_ignore_and_rename(
                    buf_name, ctx.anon_counter
                )
                end_val = int(end_idx) if end_idx is not None else start_idx
                span_label = f"{start_idx}-{end_val}" if end_idx is not None else f"{start_idx}"

                node = BaseNode(
                    name=f"{buf_name}[{span_label}]",
                    format=fmt,
                    interpreter="buffer_assign",
                    modifiers=mods,
                    encode_modifiers=enc_mods,
                )
                node.buffer_name = buf_name
                node.index_start = start_idx
                node.index_end = end_val
                node.io_size_expr = fmt
                node.ignore = ignore
                node.visible = visible if prefix is not None else False
                node.payload = payload
                node.has_io = True
                node.visibility_prefix = prefix
                return node

        # ======================================================================
        # FIELD DEFINITIONS  (name: format modifiers?)
        # ======================================================================
        parsed = ParserUtils.split_field_definition(line)
        if not parsed:
            return None

        # ParserUtils har redan kört ModifierUtils.parse_modifiers
        if len(parsed) == 5:
            name, fmt, mods, enc_mods, default_val = parsed
        else:
            name, fmt, mods, enc_mods = parsed
            default_val = None

        # Visibility prefix (+/-)
        name, visible, payload, prefix = NodeTreeParser._parse_visibility(name)

        # Name → apply ignore + auto-numbering
        name, ignore, ctx.anon_counter = ParserUtils.check_ignore_and_rename(
            name, ctx.anon_counter
        )

        # =====================================================
        # MODIFIER-PARSNING (via ParserUtils/ModifierUtils)
        # =====================================================
        decoder_mods = mods or []
        encode_mods = enc_mods or []

        # För bits-fält: expandera t.ex. 7BI → ["7B","I"]
        decoder_mods = NodeTreeParser.expand_combined_bit_modifiers(decoder_mods)

        mods = decoder_mods
        enc_mods = encode_mods

        def finalize_node(node, *, has_io=True):
            node.ignore = ignore or getattr(node, "ignore", False)
            node.visible = visible
            node.payload = payload
            node.has_io = has_io
            node.visibility_prefix = prefix
            if default_val is not None:
                node.value = default_val
            return node



        # =====================================================
        # Specialformat
        # =====================================================

        # Buffer allocation: foo[]: 20B
        buf_alloc = re.fullmatch(r"(\w+)\[\]", name)
        if buf_alloc:
            size_expr = (fmt or "").strip()
            count_expr = size_expr[:-1] if size_expr.endswith("B") else size_expr
            node = BaseNode(
                name=buf_alloc.group(1),
                format=size_expr,
                interpreter="buffer_alloc",
                modifiers=mods,
                encode_modifiers=enc_mods,
            )
            node = finalize_node(node, has_io=False)
            setattr(node, "alloc_size_expr", count_expr)
            return node

        # Buffer IO: foo[3]: B   or foo[0-4]: 4B
        buf_io = re.fullmatch(r"(\w+)\[(\d+)(?:-(\d+))?\]", name)
        if buf_io:
            buf_name, start_idx, end_idx = buf_io.group(1), int(buf_io.group(2)), buf_io.group(3)
            end_val = int(end_idx) if end_idx is not None else start_idx
            span_label = f"{start_idx}-{end_val}" if end_idx is not None else f"{start_idx}"

            node = BaseNode(
                name=f"{buf_name}[{span_label}]",
                format=fmt,
                interpreter="buffer_io",
                modifiers=mods,
                encode_modifiers=enc_mods,
            )
            node.buffer_name = buf_name
            node.index_start = start_idx
            node.index_end = end_val
            node.io_size_expr = fmt
            node = finalize_node(node, has_io=True)
            # Default: IO ops are hidden unless explicitly prefixed
            if prefix is None:
                node.visible = False
            return node

        # Slice: foo: €var[x:y]
        if fmt.startswith("€") and "[" in fmt and ":" in fmt:
            inner = fmt[fmt.index("[")+1 : fmt.rindex("]")]
            node = SliceNode(name=name, slice_expr=inner)
            return finalize_node(node)

        # Dynamic string: foo: €len's
        if fmt.startswith("€") and fmt.endswith("'s"):
            node = BaseNode()
            node.name = name
            node.format = fmt
            node.interpreter = "dynamic"
            node.modifiers = mods
            node.encode_modifiers = enc_mods
            node.depends_on = fmt[1:-2]
            node.value = None
            return finalize_node(node)

        # Var reference: foo: €seed
        if fmt.startswith("€"):
            node = BaseNode()
            node.name = name
            node.format = fmt
            node.interpreter = "var"
            node.modifiers = mods
            node.encode_modifiers = enc_mods
            node.depends_on = fmt[1:]
            node.value = None
            return finalize_node(node, has_io=False)

        # packed_guid (supports mask=<val> or mask:<val> in modifiers)
        if fmt == "packed_guid":
            mask_override = None
            cleaned_mods = []
            for m in mods:
                if isinstance(m, str) and m.lower().startswith("mask") and ("=" in m or ":" in m):
                    try:
                        mask_override = int(re.split(r'[:=]', m, maxsplit=1)[1], 0)
                    except Exception:
                        mask_override = None
                    continue
                cleaned_mods.append(m)
            mods = cleaned_mods
            node = PackedGuidNode(
                name=name,
                format="packed_guid",
                interpreter="packed_guid",
                modifiers=mods,
                encode_modifiers=enc_mods,
                ignore=ignore
            )
            if mask_override is not None:
                setattr(node, "mask", mask_override)
            return finalize_node(node)

        # Bitsfält: identifieras av mod-listan
        if any(m.endswith("B") or m.endswith("b") for m in mods):
            node = BaseNode()
            node.name = name
            node.format = fmt
            node.interpreter = "bits"
            node.modifiers = mods
            node.encode_modifiers = enc_mods
            node.value = None
            return finalize_node(node)

        # Old-style: foo: bits
        if fmt == "bits":
            node = BaseNode()
            node.name = name
            node.format = fmt
            node.interpreter = "bits"
            node.modifiers = mods
            node.encode_modifiers = enc_mods
            node.value = None
            return finalize_node(node)


        # =====================================================
        # DEFAULT STRUCT FIELD
        # =====================================================
        node = BaseNode()
        node.name = name
        node.format = fmt
        node.interpreter = "struct"
        node.modifiers = mods
        node.encode_modifiers = enc_mods
        node.value = None
        return finalize_node(node)
        
    
    @staticmethod
    def parse_variable(line: str, ctx: ParseContext):
        name, expr = [x.strip() for x in line.split("=", 1)]

        name, visible, payload, prefix = NodeTreeParser._parse_visibility(name)
        name, ignore, ctx.anon_counter = ParserUtils.check_ignore_and_rename(
            name, ctx.anon_counter
        )

        # slice-variant: foo = slice[...]
        if expr.startswith("slice[") and expr.endswith("]"):
            inner = expr[len("slice["):-1].strip()
            node = SliceNode(name=name, slice_expr=inner)
            node.visible = visible
            node.payload = payload
            node.visibility_prefix = prefix
            node.ignore = ignore
            node.has_io = True
            return node

        # annars vanlig variabel
        node = VariableNode(
            name=name,
            raw_value=expr,
            value=None,
            interpreter="expr",
        )
        node.visible = visible
        node.payload = payload
        node.visibility_prefix = prefix
        node.ignore = ignore
        node.has_io = False
        return node

    # =====================================================================
    # BIT MODIFIER EXPANSION (e.g. "7BI" → ["7B","I"])
    # =====================================================================

    @staticmethod
    def expand_combined_bit_modifiers(mods):
        if not mods:
            return []

        out = []
        for m in mods:
            if not isinstance(m, str):
                out.append(m)
                continue

            match = re.match(r"^(\d+)([Bb])(.*)$", m)
            if match:
                out.append(f"{match.group(1)}{match.group(2)}")
                tail = match.group(3)
                if tail:
                    out.extend(list(tail))
                continue

            out.append(m)

        return out
    
    # =====================================================================
    # EXTERNAL COMPATIBILITY WRAPPER
    # =====================================================================

    @staticmethod
    def count_size_of_block_structure(lines, start_idx):
        """
        Compatibility wrapper.

        Some older parts of the system may call:

            NodeTreeParser.count_size_of_block_structure(...)

        This now simply forwards to ParserUtils.count_size_of_block_structure.
        """
        return ParserUtils.count_size_of_block_structure(lines, start_idx)


# ========================================================================
# EXPORTS
# ========================================================================

__all__ = [
    "NodeTreeParser",
    "ParseContext",
]
