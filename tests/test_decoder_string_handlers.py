#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for DecoderStringHandlers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import unittest

from modules.dsl.Session import BaseNode
from modules.dsl.decoder.DecoderStringHandlers import handle_read_rest, resolve_string_format


@dataclass
class DummyBitState:
    """Minimal bitstate for string handler tests."""

    offset: int = 0


class DecoderStringHandlersTest(unittest.TestCase):
    """Tests for DecoderStringHandlers."""

    def test_resolve_string_format_ascii(self) -> None:
        """Decodes ASCII strings and updates struct metadata."""
        field = BaseNode(name="name", format="S", interpreter="struct")
        raw_data = b"hello\x00rest"

        result = resolve_string_format(field, raw_data, 0)

        self.assertEqual(result.value, "hello")
        self.assertEqual(result.format, "6s")
        self.assertEqual(result.raw_length, 6)
        self.assertEqual(result.interpreter, "struct")

    def test_resolve_string_format_non_ascii(self) -> None:
        """Falls back to hex when decoding non-ASCII data."""
        field = BaseNode(name="name", format="S", interpreter="struct")
        raw_data = b"\xff\xfe\x00"

        result = resolve_string_format(field, raw_data, 0)

        self.assertEqual(result.value, "fffe")
        self.assertEqual(result.format, "3s")
        self.assertEqual(result.raw_length, 3)

    def test_handle_read_rest_updates_offset(self) -> None:
        """Reads the remaining payload and advances offset."""
        field = BaseNode(name="payload", format="R", interpreter="raw")
        raw_data = b"\x01\x02\x03"
        bitstate = DummyBitState(offset=1)

        result = handle_read_rest(field, raw_data, bitstate)

        self.assertEqual(result.value, "\x02\x03")
        self.assertEqual(result.raw_length, 2)
        self.assertEqual(bitstate.offset, 3)
        self.assertEqual(result.format, "2s")


if __name__ == "__main__":
    unittest.main()
