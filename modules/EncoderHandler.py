#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct
from utils.Logger import Logger
from modules.Session import BaseNode, LoopNode, IfNode, RandSeqNode, PaddingNode, SeekNode, BitmaskNode


# =====================================================================
#   BitWriter – korrekt bit-buffer som matchar bit-handlingen i decode
# =====================================================================

class BitWriter:
    def __init__(self):
        self.buffer = bytearray()
        self.bit_pos = 0   # next bit index in current byte (0..7)

    def align_byte(self):
        """Move to next byte boundary WITHOUT inserting bytes."""
        if self.bit_pos != 0:
            self.bit_pos = 0

    def write_bit(self, bit: int):
        """LSB-first bit packing – matches decoder behavior."""
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
#                              EncoderHandler
# =====================================================================

class EncoderHandler:
    """
    Full DSL encoder, parallel med DecoderHandler men i motsatt riktning.
    Session kommer från dsl_encode(), och innehåller:
      session["definition"]["data"]  → DSL-noder
      session["values"]              → payload dict
    """

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

        try:
            EncoderHandler._encode_nodes(nodes, values, bw, endian="<")
        except Exception as e:
            Logger.error(f"Encode error for {case_name}: {e}")
            raise

        # avsluta byte-align
        bw.align_byte()
        return bytes(bw.buffer)

    # =================================================================
    #                         Node dispatch
    # =================================================================

    @staticmethod
    def _encode_nodes(nodes, payload, bw: BitWriter, endian):
        for node in nodes:
            EncoderHandler._encode_node(node, payload, bw, endian)

    @staticmethod
    def _encode_node(node, payload, bw: BitWriter, endian):
        it = getattr(node, "interpreter", "struct")

        if node.name == "endian":
        # Update endian mode but DO NOT write anything
            if node.format == "little":
                endian = "<"
            else:
                endian = ">"
            return


        # --- padding ---
        if it == "padding":
            EncoderHandler._encode_padding(node, bw)
            return

        # --- seek ---
        if it == "seek":
            EncoderHandler._encode_seek(node, bw)
            return

        # --- bits ---
        if it == "bits":
            EncoderHandler._encode_bits(node, payload, bw)
            return

        # --- bitmask ---
        if it == "bitmask":
            EncoderHandler._encode_bitmask(node, payload, bw)
            return

        # --- loop ---
        if it == "loop":
            EncoderHandler._encode_loop(node, payload, bw, endian)
            return

        # --- randseq ---
        if it == "randseq":
            EncoderHandler._encode_randseq(node, payload, bw, endian)
            return

        # --- if/elif/else ---
        if isinstance(node, IfNode):
            EncoderHandler._encode_if(node, payload, bw, endian)
            return

        # --- dynamic/var/slice ---
        if it in ("var", "dynamic", "slice"):
            val = EncoderHandler._resolve_value(node, payload)
            EncoderHandler._encode_struct_value(node, val, bw, endian)
            return

        # --- append (treat like struct) ---
        if it == "append":
            val = EncoderHandler._resolve_value(node, payload)
            EncoderHandler._encode_struct_value(node, val, bw, endian)
            return

        # --- struct (default) ---
        if it == "struct":
            val = EncoderHandler._resolve_value(node, payload)
            EncoderHandler._encode_struct_value(node, val, bw, endian)
            return

        raise RuntimeError(f"Unsupported interpreter '{it}' in encode")

    # =================================================================
    #                           Field encoders
    # =================================================================

    @staticmethod
    def _encode_padding(node, bw: BitWriter):
        size = int(node.value)
        bw.align_byte()
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
                raise RuntimeError(f"Bitmask child {child.name} must be list of bits")
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

        if fmt is None or fmt == "":
            raise RuntimeError(f"Node {node.name} missing format in encode")

        # fixed-size "32s"
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
            bw.buffer.extend(int(value).to_bytes(2, "little"))
            return

        if fmt == "I":
            bw.buffer.extend(int(value).to_bytes(4, "little"))
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

        # fall-back to struct.pack
        try:
            packed = struct.pack("<" + fmt, value)
            bw.buffer.extend(packed)
        except Exception as e:
            raise RuntimeError(f"Struct encode failed for {node.name} (fmt={fmt}): {e}")

    # =================================================================
    #                     Value resolution helper
    # =================================================================

    @staticmethod
    def _resolve_value(node, payload):
        if node.name in payload:
            return payload[node.name]

        # fallback: variable expression (€var)
        return EncoderHandler._resolve_value_raw(node.format, payload)

    @staticmethod
    def _resolve_value_raw(expr, payload):
        if isinstance(expr, int):
            return expr

        if isinstance(expr, str):
            if expr.startswith("€"):
                key = expr[1:]
                return payload.get(key)
            if expr.isdigit():
                return int(expr)

        return None

    # =================================================================
    #                       IF condition evaluator
    # =================================================================

    @staticmethod
    def _eval_condition(cond: str, payload):
        cond = cond.strip()

        # Format: €name == value
        if cond.startswith("€") and "==" in cond:
            left, right = [x.strip() for x in cond.split("==")]
            left = left[1:]
            return str(payload.get(left)) == right

        return False
