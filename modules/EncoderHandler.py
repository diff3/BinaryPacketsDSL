#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct
from utils.Logger import Logger
from modules.Session import BaseNode, LoopNode, IfNode, RandSeqNode, PaddingNode, SeekNode, BitmaskNode


# =====================================================================
#   BitWriter – korrekt bit-buffer som matchar decode
# =====================================================================

class BitWriter:
    def __init__(self):
        self.buffer = bytearray()
        self.bit_pos = 0   # next bit pos 0..7

    def align_byte(self):
        """Align to next byte: if mid-byte → append padding byte."""
        if self.bit_pos != 0:
            self.buffer.append(0)
            self.bit_pos = 0

    def write_bit(self, bit: int):
        bit = 1 if bit else 0

        if self.bit_pos == 0:
            self.buffer.append(0)

        idx = len(self.buffer) - 1
        self.buffer[idx] |= (bit << self.bit_pos)

        self.bit_pos += 1
        if self.bit_pos >= 8:
            self.bit_pos = 0

    def write_bits(self, bits):
        for b in bits:
            self.write_bit(int(b))


# =====================================================================
#                          EncoderHandler
# =====================================================================

class EncoderHandler:
    """
    Full DSL encoder, speglar DecoderHandler.
    """

    # -------------------------------------------------------------
    #       PUBLIC ENTRY (used by dsl_encode)
    # -------------------------------------------------------------
    @staticmethod
    def encode_payload(case_name: str, values: dict, session=None) -> bytes:
        if session is None:
            raise RuntimeError("Encode called without an encode-session")

        definition = session.get("definition")
        if not definition:
            raise RuntimeError("Encode session missing 'definition'")

        nodes = definition.get("data")
        if not nodes:
            raise RuntimeError("Encode definition missing node list")

        bw = BitWriter()
        endian = "<"

        try:
            new_endian = EncoderHandler._encode_nodes(nodes, values, bw, endian)
            if new_endian is not None:
                endian = new_endian
        except Exception as e:
            Logger.error(f"Encode error for {case_name}: {e}")
            raise

        bw.align_byte()
        return bytes(bw.buffer)

    # -------------------------------------------------------------
    #   OPTIONAL PUBLIC CALL (parallell med gamla API)
    # -------------------------------------------------------------
    @staticmethod
    def encode_from_session(case_name: str, payload_dict: dict, session):
        bw = BitWriter()
        endian = "<"

        nodes = session.fields
        for node in nodes:
            res = EncoderHandler._encode_node(node, payload_dict, bw, endian)
            if res is not None:
                endian = res

        bw.align_byte()
        return bytes(bw.buffer)

    # =================================================================
    #                         Node dispatch
    # =================================================================

    @staticmethod
    def _encode_nodes(nodes, payload, bw: BitWriter, endian):
        """
        Iterate node list and allow endian to propagate.
        """
        for node in nodes:
            new_endian = EncoderHandler._encode_node(node, payload, bw, endian)
            if new_endian is not None:
                endian = new_endian
        return endian

    @staticmethod
    def _encode_node(node, payload, bw: BitWriter, endian):
        it = getattr(node, "interpreter", "struct")

        # --------------------------------------
        # endian-node (only updates state)
        # --------------------------------------
        if node.name == "endian":
            fmt = node.format
            if fmt == "little":
                return "<"
            else:
                return ">"

        # --------------------------------------
        if it == "padding":
            EncoderHandler._encode_padding(node, bw)
            return None

        if it == "seek":
            EncoderHandler._encode_seek(node, bw)
            return None

        if it == "bits":
            EncoderHandler._encode_bits(node, payload, bw)
            return None

        if it == "bitmask":
            EncoderHandler._encode_bitmask(node, payload, bw)
            return None

        if it == "loop":
            EncoderHandler._encode_loop(node, payload, bw, endian)
            return None

        if it == "randseq":
            EncoderHandler._encode_randseq(node, payload, bw, endian)
            return None

        if isinstance(node, IfNode):
            EncoderHandler._encode_if(node, payload, bw, endian)
            return None

        if it in ("var", "dynamic", "slice", "append", "struct"):
            val = EncoderHandler._resolve_value(node, payload)
            EncoderHandler._encode_struct_value(node, val, bw, endian)
            return None

        raise RuntimeError(f"Unsupported interpreter '{it}' in encode")

    # =================================================================
    #                           Field encoders
    # =================================================================

    @staticmethod
    def _encode_padding(node, bw: BitWriter):
        bw.align_byte()
        size = int(node.value)
        for _ in range(size):
            bw.buffer.append(0)

    @staticmethod
    def _encode_seek(node, bw: BitWriter):
        target = node.offset
        bw.align_byte()
        while len(bw.buffer) < target:
            bw.buffer.append(0)

    @staticmethod
    def _encode_bits(node, payload, bw: BitWriter):
        bits = EncoderHandler._resolve_value(node, payload)
        if not isinstance(bits, (list, tuple)):
            raise RuntimeError(f"Bits-field {node.name} must be list/tuple")
        for b in bits:
            bw.write_bit(int(b))

    @staticmethod
    def _encode_bitmask(node, payload, bw: BitWriter):
        bw.align_byte()
        for child in node.children:
            bits = EncoderHandler._resolve_value(child, payload)
            if not isinstance(bits, (list, tuple)):
                raise RuntimeError(f"Bitmask child {child.name} must be bit-list")
            for b in bits:
                bw.write_bit(int(b))

    @staticmethod
    def _encode_loop(node: LoopNode, payload, bw: BitWriter, endian):
        count = EncoderHandler._resolve_value_raw(node.count_from, payload)
        if count is None:
            raise RuntimeError(f"Loop count unresolved for {node.name}")

        for _ in range(count):
            for child in node.children:
                EncoderHandler._encode_node(child, payload, bw, endian)

    @staticmethod
    def _encode_randseq(node: RandSeqNode, payload, bw: BitWriter, endian):
        for child in node.children:
            EncoderHandler._encode_node(child, payload, bw, endian)

    @staticmethod
    def _encode_if(node: IfNode, payload, bw: BitWriter, endian):
        if EncoderHandler._eval_condition(node.condition, payload):
            for n in node.true_branch:
                EncoderHandler._encode_node(n, payload, bw, endian)
        else:
            handled = False

            if node.elif_branches:
                for cond, branch in node.elif_branches:
                    if EncoderHandler._eval_condition(cond, payload):
                        for n in branch:
                            EncoderHandler._encode_node(n, payload, bw, endian)
                        handled = True
                        break

            if not handled and node.false_branch:
                for n in node.false_branch:
                    EncoderHandler._encode_node(n, payload, bw, endian)

    # =================================================================
    #                        Struct encoding
    # =================================================================

    @staticmethod
    def _encode_struct_value(node, value, bw: BitWriter, endian):
        bw.align_byte()
        fmt = node.format

        if not fmt:
            raise RuntimeError(f"Node '{node.name}' missing format for encode")

        # fixed-size: 32s
        if fmt.endswith("s") and fmt[:-1].isdigit():
            size = int(fmt[:-1])
            raw = value if isinstance(value, (bytes, bytearray)) else str(value).encode()
            raw = raw[:size].ljust(size, b"\x00")
            bw.buffer.extend(raw)
            return

        if fmt == "B":
            bw.buffer.append(int(value) & 0xFF)
            return

        if fmt == "H":
            bw.buffer.extend(int(value).to_bytes(2, byteorder="little" if endian == "<" else "big"))
            return

        if fmt == "I":
            bw.buffer.extend(int(value).to_bytes(4, byteorder="little" if endian == "<" else "big"))
            return

        if fmt == "sM":
            raw = value.encode() if isinstance(value, str) else value
            bw.buffer.extend(raw)
            bw.buffer.append(0)
            return

        if fmt == "sMU":
            raw = value if isinstance(value, (bytes, bytearray)) else value.encode()
            bw.buffer.extend(raw)
            return

        # fallback to struct.pack
        try:
            packfmt = endian + fmt
            packed = struct.pack(packfmt, value)
            bw.buffer.extend(packed)
        except Exception as e:
            raise RuntimeError(f"Struct encode failed for {node.name} (fmt={fmt}): {e}")

    # =================================================================
    #                     Value resolution helpers
    # =================================================================

    @staticmethod
    def _resolve_value(node, payload):
        if node.name in payload:
            return payload[node.name]
        return EncoderHandler._resolve_value_raw(node.format, payload)

    @staticmethod
    def _resolve_value_raw(expr, payload):
        if isinstance(expr, int):
            return expr
        if isinstance(expr, str):
            if expr.startswith("€"):
                return payload.get(expr[1:])
            if expr.isdigit():
                return int(expr)
        return None

    # =================================================================
    #                       Condition evaluator
    # =================================================================

    @staticmethod
    def _eval_condition(cond: str, payload):
        cond = cond.strip()
        if cond.startswith("€") and "==" in cond:
            left, right = [x.strip() for x in cond.split("==")]
            return str(payload.get(left[1:], None)) == right
        return False
