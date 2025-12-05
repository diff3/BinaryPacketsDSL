#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct
from modules.bitsHandler import BitInterPreter
from modules.Session import get_session
import re

session = get_session()


class ModifierInterPreter:
    @staticmethod
    def combine_data(field_value):
        combined = 0
        for value in field_value:
            combined += value
        return combined

    @staticmethod
    def to_capitalized(value):
        if isinstance(value, str):
            return value.capitalize()
        return value

    @staticmethod
    def to_int(field_value, byteorder='little'):

        if isinstance(field_value, list):
            # Antas vara en lista av 0/1 som strängar eller int
            return int(''.join(str(v) for v in field_value), 2)
        elif isinstance(field_value, bytes):
            return int.from_bytes(field_value, byteorder=byteorder)
        return field_value

    @staticmethod
    def to_hex(field_value):
        if isinstance(field_value, int):
            return hex(field_value)
        elif isinstance(field_value, str):
            return field_value.encode('utf-8').hex()
        return field_value

    @staticmethod
    def to_mirror(field_value):
        if isinstance(field_value, str):
            return field_value[::-1]
        return field_value


    @staticmethod
    def to_lower(field_value):
        if isinstance(field_value, str): 
            return field_value.lower()
        return field_value
    
    @staticmethod
    def to_bytes(field_value):
        if isinstance(field_value, str):
            return field_value.encode("utf-8")
        return field_value
    
    @staticmethod
    def to_null_terminated(field_value):
        """
        Ensure value ends with a single NUL byte. Useful for C-strings on encode side.
        """
        if isinstance(field_value, str):
            data = field_value.encode("utf-8")
        else:
            data = field_value if isinstance(field_value, (bytes, bytearray)) else bytes([field_value])
        if not data.endswith(b"\x00"):
            data += b"\x00"
        return data

    @staticmethod
    def to_guid(value):
        if isinstance(value, list):
            return int.from_bytes(bytes(value), "little")
        if isinstance(value, bytes):
            return int.from_bytes(value, "little")
        return value

    @staticmethod
    def to_upper(field_value):
        if isinstance(field_value, str): 
            return field_value.upper()
        return field_value

    @staticmethod
    def to_ip_address(field_value):
        if isinstance(field_value, bytes):
            return ".".join(str(b) for b in field_value)
        elif isinstance(field_value, str):
            try:
                byte_data = bytes.fromhex(field_value)
                return ".".join(str(b) for b in byte_data)
            except ValueError:
                return None
        return field_value

    @staticmethod
    def to_trimmed(value):
        if isinstance(value, str):
            return value.strip()
        return value

    @staticmethod
    def to_string(field_value):
        if isinstance(field_value, bytes):
            try:
                return field_value.decode("utf-8").strip("\x00")
            except UnicodeDecodeError:
                return field_value.hex()
        return field_value

    @staticmethod
    def to_big_endian(value, fmt):
        print(f"value: {value}")
        print(f"fmt: {fmt}")

        # fmt är t.ex. "I", "H", "f", "B"
        return struct.pack(">" + fmt, value)

    @staticmethod
    def to_rawstring(field_value):
        if isinstance(field_value, bytes):
            try:
                return field_value.decode("utf-8", errors="ignore").rstrip("\x00")
            except Exception:
                return field_value.hex()
        return field_value
    
    @staticmethod
    def to_clean_text(field_value):
        if not isinstance(field_value, (bytes, bytearray, str)):
            return field_value

        # 1) Försök tolka som text
        if isinstance(field_value, (bytes, bytearray)):
            try:
                text = field_value.decode("utf-8", errors="replace")
            except Exception:
                return field_value.hex()
        else:
            text = field_value

        # 2) Ta bort WoW färgtaggar och länkar
        # |cffRRGGBB
        text = re.sub(r"\|c[0-9A-Fa-f]{8}", "", text)
        text = re.sub(r"\|c[0-9A-Fa-f]{6}", "", text)
        # |r
        text = text.replace("|r", "")
        # |Hxxxx|h ... |h
        text = re.sub(r"\|H.*?\|h", "", text)

        # 3) Ta bort kontrolltecken och icke-ASCII (utom \n och \t)
        cleaned = "".join(
            ch for ch in text
            if ch in ("\n", "\t") or 0x20 <= ord(ch) <= 0x7E
        )

        return cleaned

modifiers_operation_mapping = {
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
    "0": ModifierInterPreter.to_null_terminated,
    "E": ModifierInterPreter.to_big_endian,
    "r": ModifierInterPreter.to_rawstring,
    "T": ModifierInterPreter.to_clean_text,
}
