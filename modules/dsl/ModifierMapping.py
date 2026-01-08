#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Modifier helpers used by the DSL encoder and decoder."""

from __future__ import annotations

import re
import struct
from typing import Any, Optional

from modules.dsl.bitsHandler import BitInterPreter


class ModifierInterPreter:
    """Static helpers that transform decoded or encoded values."""

    @staticmethod
    def combine_data(field_value: list[int]) -> int:
        """Combine a list of integer values by summing them."""
        combined = 0
        for value in field_value:
            combined += value
        return combined

    @staticmethod
    def to_capitalized(value: Any) -> Any:
        """Return the string with the first character capitalized."""
        if isinstance(value, str):
            return value.capitalize()
        return value

    @staticmethod
    def to_int(field_value: Any, byteorder: str = "little") -> Any:
        """Convert a list of bits or raw bytes into an integer."""
        if isinstance(field_value, list):
            return int("".join(str(v) for v in field_value), 2)
        if isinstance(field_value, bytes):
            return int.from_bytes(field_value, byteorder=byteorder)
        return field_value

    @staticmethod
    def to_hex(field_value: Any) -> Any:
        """Convert integers or strings into a hex representation."""
        if isinstance(field_value, int):
            return hex(field_value)
        if isinstance(field_value, str):
            return field_value.encode("utf-8").hex()
        return field_value

    @staticmethod
    def to_mirror(field_value: Any) -> Any:
        """Reverse strings, lists, and byte sequences."""
        if isinstance(field_value, str):
            return field_value[::-1]

        if isinstance(field_value, (bytes, bytearray)):
            return field_value[::-1]

        if isinstance(field_value, list):
            return list(reversed(field_value))

        return field_value

    @staticmethod
    def to_lower(field_value: Any) -> Any:
        """Lowercase strings."""
        if isinstance(field_value, str):
            return field_value.lower()
        return field_value

    @staticmethod
    def to_bytes(field_value: Any) -> Any:
        """Encode strings into UTF-8 bytes."""
        if isinstance(field_value, str):
            return field_value.encode("utf-8")
        return field_value

    @staticmethod
    def to_rotate_tail_front(field_value: Any) -> Any:
        """Move the last element of a sequence to the front."""
        if isinstance(field_value, (list, tuple)) and field_value:
            seq = list(field_value)
            return [seq[-1]] + seq[:-1]
        return field_value

    @staticmethod
    def to_join(field_value: Any) -> str:
        """Join a sequence into a single string without separators."""
        if field_value is None:
            return ""
        if isinstance(field_value, (list, tuple)):
            try:
                return "".join(str(x) for x in field_value)
            except Exception:
                return "".join(map(str, field_value))
        if isinstance(field_value, (bytes, bytearray)):
            return field_value.hex()
        return str(field_value)

    @staticmethod
    def to_null_terminated(field_value: Any) -> bytes:
        """Ensure a value ends with a single NUL byte."""
        if isinstance(field_value, str):
            data = field_value.encode("utf-8")
        else:
            if isinstance(field_value, (bytes, bytearray)):
                data = bytes(field_value)
            else:
                data = bytes([field_value])
        if not data.endswith(b"\x00"):
            data += b"\x00"
        return data

    @staticmethod
    def to_guid(value: Any) -> Any:
        """Convert a list/bytes value into a little-endian GUID integer."""
        if isinstance(value, list):
            return int.from_bytes(bytes(value), "little")
        if isinstance(value, bytes):
            return int.from_bytes(value, "little")
        return value

    @staticmethod
    def to_upper(field_value: Any) -> Any:
        """Uppercase strings."""
        if isinstance(field_value, str):
            return field_value.upper()
        return field_value

    @staticmethod
    def to_ip_address(field_value: Any) -> Optional[str]:
        """Normalize various IP representations into dotted decimal."""
        if isinstance(field_value, (bytes, bytearray)):
            return ".".join(str(b) for b in field_value)

        if isinstance(field_value, list) and all(isinstance(b, int) for b in field_value):
            try:
                return ".".join(str(int(b) & 0xFF) for b in field_value)
            except Exception:
                return None

        if isinstance(field_value, str) and field_value.count(".") == 3:
            return field_value

        if isinstance(field_value, str) and "\\x" in field_value:
            try:
                decoded = field_value.encode("latin1").decode("unicode_escape").encode("latin1")
                return ".".join(str(x) for x in decoded)
            except Exception:
                return None

        if isinstance(field_value, str):
            cleaned = field_value.replace(" ", "")
            if len(cleaned) % 2 == 0:
                try:
                    decoded = bytes.fromhex(cleaned)
                    return ".".join(str(x) for x in decoded)
                except Exception:
                    return None

        return None

    @staticmethod
    def to_trimmed(value: Any) -> Any:
        """Trim surrounding whitespace from strings."""
        if isinstance(value, str):
            return value.strip()
        return value

    @staticmethod
    def to_string(field_value: Any) -> Any:
        """Convert ints or bytes to string representations."""
        if isinstance(field_value, int):
            return str(field_value)
        if isinstance(field_value, bytes):
            try:
                return field_value.decode("utf-8").strip("\x00")
            except UnicodeDecodeError:
                return field_value.hex()
        return field_value

    @staticmethod
    def to_big_endian(value: Any, fmt: str) -> bytes:
        """Pack a value using a big-endian struct format."""
        return struct.pack(">" + fmt, value)

    @staticmethod
    def to_rawstring(field_value: Any) -> Any:
        """Decode bytes into a raw string without strict validation."""
        if isinstance(field_value, bytes):
            try:
                return field_value.decode("utf-8", errors="ignore").rstrip("\x00")
            except Exception:
                return field_value.hex()
        return field_value

    @staticmethod
    def to_clean_text(field_value: Any) -> Any:
        """Strip WoW formatting codes and control characters from text."""
        if not isinstance(field_value, (bytes, bytearray, str)):
            return field_value

        if isinstance(field_value, (bytes, bytearray)):
            try:
                text = field_value.decode("utf-8", errors="replace")
            except Exception:
                return field_value.hex()
        else:
            text = field_value

        text = re.sub(r"\|c[0-9A-Fa-f]{8}", "", text)
        text = re.sub(r"\|c[0-9A-Fa-f]{6}", "", text)
        text = text.replace("|r", "")
        text = re.sub(r"\|H.*?\|h", "", text)

        cleaned = "".join(
            ch for ch in text
            if ch in ("\n", "\t") or 0x20 <= ord(ch) <= 0x7E
        )

        return cleaned
    
    @staticmethod
    def to_byte_seq(field_value: Any) -> Any:
        """Apply WriteByteSeq semantics: XOR each byte with 1."""
        if isinstance(field_value, (bytes, bytearray)):
            return bytes((b ^ 0x01) for b in field_value)

        if isinstance(field_value, list) and all(isinstance(b, int) for b in field_value):
            return [((b ^ 0x01) & 0xFF) for b in field_value]

        return field_value

modifiers_operation_mapping: dict[str, Any] = {
    "B": BitInterPreter.from_bits,
    "b": BitInterPreter.from_bits_le,
    "C": ModifierInterPreter.combine_data,
    "G": ModifierInterPreter.to_guid,
    "H": ModifierInterPreter.to_hex,
    "I": ModifierInterPreter.to_int,
    "M": ModifierInterPreter.to_mirror,
    "N": ModifierInterPreter.to_capitalized,
    "U": ModifierInterPreter.to_upper,
    "W": ModifierInterPreter.to_ip_address,
    "s": ModifierInterPreter.to_string,
    "t": ModifierInterPreter.to_trimmed,
    "u": ModifierInterPreter.to_lower,
    "Q": ModifierInterPreter.to_bytes,
    "X": ModifierInterPreter.to_rotate_tail_front,
    "J": ModifierInterPreter.to_join,
    "0": ModifierInterPreter.to_null_terminated,
    "E": ModifierInterPreter.to_big_endian,
    "r": ModifierInterPreter.to_rawstring,
    "T": ModifierInterPreter.to_clean_text,
    "Y": ModifierInterPreter.to_byte_seq,
}
