#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for DecoderBitHandlers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import unittest
from unittest.mock import patch

from modules.dsl.Session import BaseNode, BitmaskNode
from modules.dsl.bitsHandler import BitState
from modules.dsl.decoder.DecoderBitHandlers import decode_bits_field, handle_bitmask


@dataclass
class DummyDecodeState:
    """Minimal decode state for bit handler tests."""

    all: dict[str, Any]
    public: dict[str, Any]

    def set_field(self, field: Any, value: Any, *, public_value: Any | None = None) -> None:
        """Store a field result for tests."""
        name = getattr(field, "name", None)
        if not name:
            return
        self.all[name] = value
        if public_value is None:
            self.public[name] = value
        else:
            self.public[name] = public_value


class DecoderBitHandlersTest(unittest.TestCase):
    """Tests for DecoderBitHandlers."""

    def test_decode_bits_field_reads_msb(self) -> None:
        """Decodes MSB-first bits using the B modifier."""
        field = BaseNode(name="flags", format="bits", interpreter="bits")
        field.modifiers = ["3B"]
        bitstate = BitState()
        raw_data = bytes([0b10110000])

        result = decode_bits_field(field, raw_data, bitstate)

        self.assertEqual(result.value, [1, 0, 1])
        self.assertEqual(bitstate.offset, 0)
        self.assertEqual(bitstate.bit_pos, 3)
        self.assertEqual(result.raw_offset, 0)
        self.assertEqual(result.raw_length, 1)

    def test_decode_bits_field_applies_int_modifier(self) -> None:
        """Applies the I modifier to convert bits to int."""
        field = BaseNode(name="flags", format="bits", interpreter="bits")
        field.modifiers = ["3B", "I"]
        bitstate = BitState()
        raw_data = bytes([0b10100000])

        result = decode_bits_field(field, raw_data, bitstate)

        self.assertEqual(result.value, 5)
        self.assertEqual(bitstate.bit_pos, 3)

    def test_decode_bits_field_reads_lsb(self) -> None:
        """Decodes LSB-first bits using the b modifier."""
        field = BaseNode(name="flags", format="bits", interpreter="bits")
        field.modifiers = ["3b"]
        bitstate = BitState()
        raw_data = bytes([0b00000110])

        result = decode_bits_field(field, raw_data, bitstate)

        self.assertEqual(result.value, [1, 1, 0])
        self.assertEqual(bitstate.bit_pos, 3)

    def test_handle_bitmask_sets_public_values(self) -> None:
        """Collects child fields into the bitmask public result."""
        children = [BaseNode(name="bit_one"), BaseNode(name="bit_two")]
        field = BitmaskNode(name="mask", size=2, children=children)
        bitstate = BitState()
        raw_data = bytes([0b11000000])
        state = DummyDecodeState(all={}, public={})

        def process_field(child: Any, raw: bytes, bit: Any, endian: str, child_state: DummyDecodeState) -> tuple[Any, bool, str]:
            child.value = f"value_{child.name}"
            child_state.set_field(child, child.value)
            return child, True, endian

        with patch("utils.DebugHelper.DebugHelper.trace_field", return_value=None):
            handle_bitmask(
                field,
                raw_data,
                bitstate,
                "<",
                state,
                process_field=process_field,
                state_factory=lambda: DummyDecodeState(all={}, public={}),
            )

        self.assertEqual(bitstate.offset, 0)
        self.assertEqual(bitstate.bit_pos, 2)
        self.assertEqual(field.raw_length, 1)
        self.assertEqual(state.public.get("mask"), {"bit_one": "value_bit_one", "bit_two": "value_bit_two"})


if __name__ == "__main__":
    unittest.main()
