# guid_helper.py
#
# World of Warcraft MoP / SkyFire GUID utilities
# Supports:
#  - Player / Creature / GameObject GUIDs
#  - uint64 build + decode
#  - Little-endian wire format
#  - Packed GUID (network format)
#
# Layout:
#   uint64 GUID = [ high:16 | realm:16 | low:32 ]

import struct
from dataclasses import dataclass


# ------------------------------------------------------------
# High GUID values (MoP / SkyFire)
# ------------------------------------------------------------

class HighGuid:
    PLAYER     = 0x0003
    UNIT       = 0x000F      # Creature / NPC
    GAMEOBJECT = 0x0013
    PET        = 0x0009
    DYNAMIC    = 0x0006


# ------------------------------------------------------------
# Decoded GUID container
# ------------------------------------------------------------

@dataclass
class DecodedGuid:
    high: int
    realm: int
    low: int

    def __str__(self) -> str:
        return f"HIGH=0x{self.high:04X} REALM={self.realm} LOW={self.low}"


# ------------------------------------------------------------
# Core GUID helper
# ------------------------------------------------------------

class GuidHelper:
    @staticmethod
    def make(high: int, realm: int, low: int) -> int:
        """
        Build uint64 GUID from components.
        """
        return (
            ((high  & 0xFFFF) << 48) |
            ((realm & 0xFFFF) << 32) |
            (low & 0xFFFFFFFF)
        )

    @staticmethod
    def decode(guid: int) -> DecodedGuid:
        """
        Decode uint64 GUID into (high, realm, low).
        """
        if not (0 <= guid <= 0xFFFFFFFFFFFFFFFF):
            raise ValueError("guid must fit in uint64")
        high  = (guid >> 48) & 0xFFFF
        realm = (guid >> 32) & 0xFFFF
        low   = guid & 0xFFFFFFFF
        return DecodedGuid(high, realm, low)

    @staticmethod
    def to_le_bytes(guid: int) -> bytes:
        """
        uint64 → little-endian bytes (unpacked wire format).
        """
        if not (0 <= guid <= 0xFFFFFFFFFFFFFFFF):
            raise ValueError("guid must fit in uint64")
        return struct.pack("<Q", guid)

    @staticmethod
    def from_le_bytes(data: bytes) -> int:
        """
        little-endian bytes → uint64 GUID.
        """
        if len(data) != 8:
            raise ValueError("packed GUID must be exactly 8 bytes")
        return struct.unpack("<Q", data)[0]

    # --------------------------------------------------------
    # Packed GUID (network format)
    # --------------------------------------------------------

    @staticmethod
    def pack(guid: int) -> bytes:
        """
        Encode GUID into packed GUID format.
        """
        if not (0 <= guid <= 0xFFFFFFFFFFFFFFFF):
            raise ValueError("guid must fit in uint64")
        raw = GuidHelper.to_le_bytes(guid)
        mask = 0
        out = bytearray()

        for i in range(8):
            if raw[i] != 0:
                mask |= (1 << i)
                out.append(raw[i])

        return bytes([mask]) + bytes(out)

    @staticmethod
    def unpack(data: bytes) -> int:
        """
        Decode packed GUID into uint64.
        """
        if not data:
            raise ValueError("packed GUID buffer is empty")
        mask = data[0]
        idx = 1
        raw = bytearray(8)

        needed = bin(mask).count("1")
        if len(data) - 1 < needed:
            raise ValueError("packed GUID buffer too short for mask")

        for i in range(8):
            if mask & (1 << i):
                if idx >= len(data):
                    raise ValueError("packed GUID buffer ended unexpectedly")
                raw[i] = data[idx]
                idx += 1

        return GuidHelper.from_le_bytes(bytes(raw))


# ------------------------------------------------------------
# Typed helpers
# ------------------------------------------------------------

class PlayerGuid:
    @staticmethod
    def from_db_guid(db_guid: int, realm: int) -> int:
        return GuidHelper.make(HighGuid.PLAYER, realm, db_guid)


class CreatureGuid:
    @staticmethod
    def from_spawn_guid(spawn_guid: int, realm: int) -> int:
        return GuidHelper.make(HighGuid.UNIT, realm, spawn_guid)


class GameObjectGuid:
    @staticmethod
    def from_spawn_guid(spawn_guid: int, realm: int) -> int:
        return GuidHelper.make(HighGuid.GAMEOBJECT, realm, spawn_guid)
