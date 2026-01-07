#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for ModifierMapping helpers."""

from __future__ import annotations

import struct
import unittest

from modules.dsl.ModifierMapping import ModifierInterPreter


class ModifierMappingTest(unittest.TestCase):
    """Tests for ModifierInterPreter modifiers."""

    def test_combine_data(self) -> None:
        """Combine sums the input list."""
        self.assertEqual(ModifierInterPreter.combine_data([1, 2, 3]), 6)

    def test_to_capitalized(self) -> None:
        """Capitalizes strings and leaves other types unchanged."""
        self.assertEqual(ModifierInterPreter.to_capitalized("hello"), "Hello")
        self.assertEqual(ModifierInterPreter.to_capitalized(10), 10)

    def test_to_int(self) -> None:
        """Converts bit lists and bytes to integers."""
        self.assertEqual(ModifierInterPreter.to_int([1, 0, 1]), 5)
        self.assertEqual(ModifierInterPreter.to_int(b"\x10"), 16)

    def test_to_hex(self) -> None:
        """Converts ints and strings to hex representations."""
        self.assertEqual(ModifierInterPreter.to_hex(255), "0xff")
        self.assertEqual(ModifierInterPreter.to_hex("Hi"), "4869")

    def test_to_mirror(self) -> None:
        """Mirrors strings, bytes, and lists."""
        self.assertEqual(ModifierInterPreter.to_mirror("abc"), "cba")
        self.assertEqual(ModifierInterPreter.to_mirror(b"\x01\x02"), b"\x02\x01")
        self.assertEqual(ModifierInterPreter.to_mirror([1, 2, 3]), [3, 2, 1])

    def test_to_lower_upper(self) -> None:
        """Lowercases and uppercases strings."""
        self.assertEqual(ModifierInterPreter.to_lower("TeSt"), "test")
        self.assertEqual(ModifierInterPreter.to_upper("TeSt"), "TEST")

    def test_to_bytes(self) -> None:
        """Encodes strings to UTF-8 bytes."""
        self.assertEqual(ModifierInterPreter.to_bytes("hi"), b"hi")
        self.assertEqual(ModifierInterPreter.to_bytes(b"hi"), b"hi")

    def test_to_rotate_tail_front(self) -> None:
        """Moves the tail element to the front."""
        self.assertEqual(ModifierInterPreter.to_rotate_tail_front([1, 2, 3]), [3, 1, 2])
        self.assertEqual(ModifierInterPreter.to_rotate_tail_front([]), [])

    def test_to_join(self) -> None:
        """Joins lists or bytes into a string."""
        self.assertEqual(ModifierInterPreter.to_join([6, 5, 6, 7]), "6567")
        self.assertEqual(ModifierInterPreter.to_join(b"\x01\x02"), "0102")
        self.assertEqual(ModifierInterPreter.to_join(None), "")

    def test_to_null_terminated(self) -> None:
        """Ensures the value ends with a NUL byte."""
        self.assertEqual(ModifierInterPreter.to_null_terminated("hi"), b"hi\x00")
        self.assertEqual(ModifierInterPreter.to_null_terminated(b"hi\x00"), b"hi\x00")
        self.assertEqual(ModifierInterPreter.to_null_terminated(65), b"A\x00")

    def test_to_guid(self) -> None:
        """Converts byte-like sequences to GUID ints."""
        self.assertEqual(ModifierInterPreter.to_guid([1, 0, 0, 0]), 1)
        self.assertEqual(ModifierInterPreter.to_guid(b"\x02\x00"), 2)

    def test_to_ip_address(self) -> None:
        """Normalizes IP inputs into dotted decimal."""
        self.assertEqual(ModifierInterPreter.to_ip_address(b"\x7f\x00\x00\x01"), "127.0.0.1")
        self.assertEqual(ModifierInterPreter.to_ip_address([127, 0, 0, 1]), "127.0.0.1")
        self.assertEqual(ModifierInterPreter.to_ip_address("127.0.0.1"), "127.0.0.1")
        self.assertEqual(
            ModifierInterPreter.to_ip_address("\\x7f\\x00\\x00\\x01"), "127.0.0.1"
        )
        self.assertEqual(ModifierInterPreter.to_ip_address("7F000001"), "127.0.0.1")
        self.assertIsNone(ModifierInterPreter.to_ip_address("nope"))

    def test_to_trimmed(self) -> None:
        """Trims whitespace from strings."""
        self.assertEqual(ModifierInterPreter.to_trimmed("  hi "), "hi")

    def test_to_string(self) -> None:
        """Converts ints or bytes to string output."""
        self.assertEqual(ModifierInterPreter.to_string(42), "42")
        self.assertEqual(ModifierInterPreter.to_string(b"hi\x00"), "hi")
        self.assertEqual(ModifierInterPreter.to_string(b"\xff"), "ff")

    def test_to_big_endian(self) -> None:
        """Packs values into big-endian bytes."""
        self.assertEqual(ModifierInterPreter.to_big_endian(0x1234, "H"), struct.pack(">H", 0x1234))

    def test_to_rawstring(self) -> None:
        """Decodes bytes into a raw string."""
        self.assertEqual(ModifierInterPreter.to_rawstring(b"hi\x00"), "hi")
        self.assertEqual(ModifierInterPreter.to_rawstring("hi"), "hi")

    def test_to_clean_text(self) -> None:
        """Strips formatting and control characters from text."""
        raw = b"|cff00FF00Hello|r\x01World"
        self.assertEqual(ModifierInterPreter.to_clean_text(raw), "HelloWorld")


if __name__ == "__main__":
    unittest.main()
