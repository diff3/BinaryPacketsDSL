#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from utils.Logger import Logger


class BitInterPreter:
    """
    Class to read bits from a byte array.
    """

    @staticmethod
    def from_bits(data: bytes, byte_pos: int, bit_pos: int, num_bits: int) -> tuple:
        """
        Reads bits and returns a list of individual bits (MSB → LSB), plus updated positions.
        """
        value, byte_pos, bit_pos = BitInterPreter.read_bits(data, byte_pos, bit_pos, num_bits)

        # Convert to list of bits
        bits = [(value >> i) & 1 for i in reversed(range(num_bits))]
        return bits, byte_pos, bit_pos
    
    @staticmethod
    def from_bits_le(data: bytes, byte_pos: int, bit_pos: int, num_bits: int) -> tuple:
        """
        Reads bits in LSB-first order and returns a list of bits (MSB → LSB), plus updated positions.
        """
        value, byte_pos, bit_pos = BitInterPreter.read_bits_le(data, byte_pos, bit_pos, num_bits)

        # Convert to MSB→LSB bit list (for consistency with `from_bits`)
        bits = [(value >> i) & 1 for i in reversed(range(num_bits))]

        return bits, byte_pos, bit_pos

    @staticmethod
    def read_bit(data: bytes, byte_pos: int, bit_pos: int) -> tuple:
        """
        MSB-first: reads a single bit (bit 7 → 0) from current byte.
        """
        bit = (data[byte_pos] >> (7 - bit_pos)) & 1
        bit_pos += 1
        if bit_pos > 7:
            bit_pos = 0
            byte_pos += 1
        return bit, byte_pos, bit_pos

    @staticmethod
    def read_bit_le(data: bytes, byte_pos: int, bit_pos: int) -> tuple:
        """
        LSB-first: reads a single bit (bit 0 → 7) from current byte.
        """
        bit = (data[byte_pos] >> bit_pos) & 1
        bit_pos += 1
        if bit_pos > 7:
            bit_pos = 0
            byte_pos += 1
        return bit, byte_pos, bit_pos

    @staticmethod
    def read_bits(data: bytes, byte_pos: int, bit_pos: int, num_bits: int) -> tuple:
        """
        MSB-first: reads multiple bits and assembles a value from high to low bits.
        """
        value = 0
        for _ in range(num_bits):
            bit, byte_pos, bit_pos = BitInterPreter.read_bit(data, byte_pos, bit_pos)
            value = (value << 1) | bit
        return value, byte_pos, bit_pos
    
    @staticmethod
    def read_bits_tc(data: bytes, byte_pos: int, bit_pos: int, num_bits: int):
        """
        Trinity/SkyFire WriteBits → MSB-first.
        Equivalent to read_bits() but exists for clarity.
        """
        return BitInterPreter.read_bits(data, byte_pos, bit_pos, num_bits)

    @staticmethod
    def read_bits_le(data: bytes, byte_pos: int, bit_pos: int, num_bits: int) -> tuple:
        """
        LSB-first: reads multiple bits and assembles a value from low to high bits.
        """
        value = 0
        shift = 0
        for _ in range(num_bits):
            bit, byte_pos, bit_pos = BitInterPreter.read_bit_le(data, byte_pos, bit_pos)
            value |= (bit << shift)
            shift += 1
        return value, byte_pos, bit_pos


class BitState:
    """
    Tracks current offset and bit position during bit-level decoding.
    Used to persist decoding state across bit fields and loops.
    """

    def __init__(self):
        self.offset = 0
        self.bit_pos = 0

    def align_to_byte(self):
        if self.bit_pos != 0:
           #  Logger.debug(f"[BitState] Aligning to byte → offset {self.offset} → {self.offset+1}")
            self.offset += 1
            self.bit_pos = 0

    def advance_to(self, offset, bit_pos):
        """Set both offset and bit_pos explicitly."""
        self.offset = offset
        self.bit_pos = bit_pos

    def advance_bits(self, byte_delta, new_bit_pos):
        """Increment offset by N bytes and update bit position."""
        self.offset += byte_delta
        self.bit_pos = new_bit_pos

    def debug(self, label=""):
        Logger.debug(f"[BitState] {label} → offset={self.offset}, bit_pos={self.bit_pos}")