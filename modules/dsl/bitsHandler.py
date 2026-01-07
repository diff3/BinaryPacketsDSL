#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Bit-level read/write helpers for the DSL runtime.

This module centralizes MSB/LSB bit decoding and a shared cursor state so
decoder and encoder code can stay consistent. It also provides a small bit
writer that mirrors the decoder semantics.
"""

from __future__ import annotations

from utils.Logger import Logger


class BitInterPreter:
    """Read bits from a byte array using MSB or LSB semantics."""

    @staticmethod
    def from_bits(
        data: bytes,
        byte_pos: int,
        bit_pos: int,
        num_bits: int,
    ) -> tuple[list[int], int, int]:
        """Read MSB-first bits and return them as a list with updated positions.

        Args:
            data (bytes): Input data.
            byte_pos (int): Current byte offset.
            bit_pos (int): Current bit position within the byte.
            num_bits (int): Number of bits to read.

        Returns:
            tuple[list[int], int, int]: (bits, byte_pos, bit_pos).
        """
        value, byte_pos, bit_pos = BitInterPreter.read_bits(data, byte_pos, bit_pos, num_bits)
        bits = [(value >> i) & 1 for i in reversed(range(num_bits))]
        return bits, byte_pos, bit_pos
    
    @staticmethod
    def from_bits_le(
        data: bytes,
        byte_pos: int,
        bit_pos: int,
        num_bits: int,
    ) -> tuple[list[int], int, int]:
        """Read LSB-first bits and return them as a list with updated positions.

        Args:
            data (bytes): Input data.
            byte_pos (int): Current byte offset.
            bit_pos (int): Current bit position within the byte.
            num_bits (int): Number of bits to read.

        Returns:
            tuple[list[int], int, int]: (bits, byte_pos, bit_pos).
        """
        value, byte_pos, bit_pos = BitInterPreter.read_bits_le(data, byte_pos, bit_pos, num_bits)
        bits = [(value >> i) & 1 for i in reversed(range(num_bits))]

        return bits, byte_pos, bit_pos

    @staticmethod
    def read_bit(
        data: bytes,
        byte_pos: int,
        bit_pos: int,
    ) -> tuple[int, int, int]:
        """Read a single MSB-first bit from the current byte.

        Returns:
            tuple[int, int, int]: (bit, byte_pos, bit_pos).
        """
        bit = (data[byte_pos] >> (7 - bit_pos)) & 1
        bit_pos += 1
        if bit_pos > 7:
            bit_pos = 0
            byte_pos += 1
        return bit, byte_pos, bit_pos

    @staticmethod
    def read_bit_le(
        data: bytes,
        byte_pos: int,
        bit_pos: int,
    ) -> tuple[int, int, int]:
        """Read a single LSB-first bit from the current byte.

        Returns:
            tuple[int, int, int]: (bit, byte_pos, bit_pos).
        """
        bit = (data[byte_pos] >> bit_pos) & 1
        bit_pos += 1
        if bit_pos > 7:
            bit_pos = 0
            byte_pos += 1
        return bit, byte_pos, bit_pos

    @staticmethod
    def read_bits(
        data: bytes,
        byte_pos: int,
        bit_pos: int,
        num_bits: int,
    ) -> tuple[int, int, int]:
        """Read multiple MSB-first bits and assemble a value.

        Returns:
            tuple[int, int, int]: (value, byte_pos, bit_pos).
        """
        value = 0
        for _ in range(num_bits):
            bit, byte_pos, bit_pos = BitInterPreter.read_bit(data, byte_pos, bit_pos)
            value = (value << 1) | bit
        return value, byte_pos, bit_pos
    
    @staticmethod
    def read_bits_tc(
        data: bytes,
        byte_pos: int,
        bit_pos: int,
        num_bits: int,
    ) -> tuple[int, int, int]:
        """Read MSB-first bits (alias for Trinity/SkyFire naming)."""
        return BitInterPreter.read_bits(data, byte_pos, bit_pos, num_bits)

    @staticmethod
    def read_bits_le(
        data: bytes,
        byte_pos: int,
        bit_pos: int,
        num_bits: int,
    ) -> tuple[int, int, int]:
        """Read multiple LSB-first bits and assemble a value.

        Returns:
            tuple[int, int, int]: (value, byte_pos, bit_pos).
        """
        value = 0
        shift = 0
        for _ in range(num_bits):
            bit, byte_pos, bit_pos = BitInterPreter.read_bit_le(data, byte_pos, bit_pos)
            value |= (bit << shift)
            shift += 1
        return value, byte_pos, bit_pos


class BitState:
    """Track the current byte/bit position during bit-level decoding."""

    def __init__(self) -> None:
        self.offset: int = 0
        self.bit_pos: int = 0

    def align_to_byte(self) -> None:
        """Advance to the next byte boundary if needed."""
        if self.bit_pos != 0:
            self.offset += 1
            self.bit_pos = 0

    def advance_to(self, offset: int, bit_pos: int) -> None:
        """Set both offset and bit_pos explicitly."""
        self.offset = offset
        self.bit_pos = bit_pos

    def advance_bits(self, byte_delta: int, new_bit_pos: int) -> None:
        """Increment offset by N bytes and update bit position."""
        self.offset += byte_delta
        self.bit_pos = new_bit_pos

    def debug(self, label: str = "") -> None:
        Logger.debug(f"[BitState] {label} → offset={self.offset}, bit_pos={self.bit_pos}")


class BitWriter:
    """Continuous bitstream writer compatible with the decoder semantics.

    Writing with write_bits or write_bits_le produces bytes that the matching
    BitInterPreter readers will reconstruct into the same integer values.
    """

    def __init__(self) -> None:
        self.buffer: bytearray = bytearray()
        self.current: int = 0
        self.bit_pos: int = 0

    def write_bits(self, value: int, nbits: int) -> None:
        """Write MSB-first bits (inverse of BitInterPreter.read_bits)."""
        for i in reversed(range(nbits)):
            bit = (value >> i) & 1
            self.current |= (bit << (7 - self.bit_pos))
            self.bit_pos += 1

            if self.bit_pos == 8:
                self.buffer.append(self.current)
                self.current = 0
                self.bit_pos = 0

    def write_bits_le(self, value: int, nbits: int) -> None:
        """Write LSB-first bits (inverse of BitInterPreter.read_bits_le)."""
        for i in range(nbits):
            bit = (value >> i) & 1
            self.current |= (bit << self.bit_pos)
            self.bit_pos += 1

            if self.bit_pos == 8:
                self.buffer.append(self.current)
                self.current = 0
                self.bit_pos = 0

    def flush_to_byte(self) -> None:
        """Flush a partial byte if any bits were written."""
        if self.bit_pos > 0:
            self.buffer.append(self.current)
            self.current = 0
            self.bit_pos = 0

    def getvalue(self) -> bytes:
        """Return the written buffer as bytes."""
        self.flush_to_byte()
        return bytes(self.buffer)
