#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for DecoderPacketHandlers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import unittest
from unittest.mock import patch
import zlib

from modules.dsl.Session import BaseNode, get_session
from modules.dsl.bitsHandler import BitState
from modules.dsl.decoder.DecoderPacketHandlers import (
    combine_guid,
    handle_packed_guid,
    handle_uncompress,
)


@dataclass
class DummyDecodeState:
    """Minimal decode state for packet handler tests."""

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


class DecoderPacketHandlersTest(unittest.TestCase):
    """Tests for DecoderPacketHandlers."""

    def setUp(self) -> None:
        """Reset global scope before each test."""
        session = get_session()
        session.scope.reset()

    def test_combine_guid_from_meta(self) -> None:
        """Combines GUID bytes based on meta mask fields."""
        session = get_session()
        session.scope.set("i", 0)

        result = {
            "chars_meta": [
                {
                    "guid_0_mask": 1,
                    "guid_1_mask": 0,
                }
            ]
        }
        values = {"guid_0": 0xAA}

        combined = combine_guid("guid", mask=None, values=values, result=result)

        self.assertEqual(combined, 0xAA)

    def test_handle_packed_guid(self) -> None:
        """Decodes a packed GUID with a single byte."""
        field = BaseNode(name="guid", format="", interpreter="packed_guid")
        raw_data = bytes([0x01, 0xAA])
        bitstate = BitState()
        state = DummyDecodeState(all={}, public={})

        handle_packed_guid(field, raw_data, bitstate, state)

        self.assertEqual(field.value, 0xAA)
        self.assertEqual(bitstate.offset, 2)
        self.assertEqual(state.all.get("guid"), 0xAA)
        self.assertEqual(state.all.get("guid_mask"), 0x01)

    def test_handle_uncompress_zlib(self) -> None:
        """Inflates zlib payload and processes child fields."""
        field = BaseNode(name="uncompress", format="", interpreter="uncompress")
        field.algo = "zlib"
        field.length_expr = None
        field.children = [BaseNode(name="child")]

        inflated = b"\x10\x20"
        compressed = zlib.compress(inflated)
        raw_data = compressed
        bitstate = BitState()
        state = DummyDecodeState(all={}, public={})

        def process_field(child: Any, raw: bytes, bit: BitState, endian: str, state_obj: DummyDecodeState) -> tuple[Any, bool, str]:
            child.value = raw[0]
            state_obj.set_field(child, child.value)
            return child, True, endian

        with patch("utils.DebugHelper.DebugHelper.trace_field", return_value=None):
            handle_uncompress(
                field,
                raw_data,
                bitstate,
                "<",
                state,
                process_field=process_field,
                resolve_variable=lambda key, scope: None,
            )

        self.assertEqual(bitstate.offset, len(compressed))
        self.assertEqual(field.value, inflated)
        self.assertEqual(state.all.get("child"), inflated[0])


if __name__ == "__main__":
    unittest.main()
