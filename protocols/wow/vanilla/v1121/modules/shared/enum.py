# enums.py
# General enums used across world, movement, maps and UI (MoP 5.4.8)

from enum import IntEnum


# =========================
# CHARACTER / PLAYER
# =========================

class Race(IntEnum):
    HUMAN = 1
    ORC = 2
    DWARF = 3
    NIGHT_ELF = 4
    UNDEAD = 5
    TAUREN = 6
    GNOME = 7
    TROLL = 8
    GOBLIN = 9
    BLOOD_ELF = 10
    DRAENEI = 11
    PANDAREN_NEUTRAL = 24
    PANDAREN_ALLIANCE = 25
    PANDAREN_HORDE = 26


class Class(IntEnum):
    WARRIOR = 1
    PALADIN = 2
    HUNTER = 3
    ROGUE = 4
    PRIEST = 5
    DEATH_KNIGHT = 6
    SHAMAN = 7
    MAGE = 8
    WARLOCK = 9
    MONK = 10
    DRUID = 11


class Gender(IntEnum):
    MALE = 0
    FEMALE = 1


# =========================
# MAP / WORLD
# =========================

class MapID(IntEnum):
    EASTERN_KINGDOMS = 0
    KALIMDOR = 1
    OUTLAND = 530
    NORTHREND = 571
    PANDARIA = 870


class MapType(IntEnum):
    WORLD = 0
    DUNGEON = 1
    RAID = 2
    BATTLEGROUND = 3
    ARENA = 4


# =========================
# WEATHER
# =========================

class WeatherType(IntEnum):
    FINE = 0
    RAIN = 1
    SNOW = 2
    STORM = 3
    THUNDERSTORM = 4
    BLACKRAIN = 90


# =========================
# HELPERS
# =========================

def enum_name(enum_cls, value: int) -> str:
    try:
        return enum_cls(value).name
    except ValueError:
        return f"UNKNOWN_{enum_cls.__name__}_{value}"