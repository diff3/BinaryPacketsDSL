#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Packet builders for the World Login flow.

These functions:
- build logical packet data (dict)
- hand it to the DSL encoder
- return raw bytes

They do NOT:
- manage sockets
- manage ordering
- contain protocol knowledge beyond field names
"""
from pathlib import Path
from typing import Dict, Any, Optional
import time
import json
import struct
from modules.dsl.EncoderHandler import EncoderHandler
from modules.dsl.bitsHandler import BitWriter
from utils.Logger import Logger

from .constants import RACES_MOP, CLASSES_MOP
from utils.PathUtils import get_captures_root, get_protocol_root
from protocols.wow.mop.v18414.modules.database.DatabaseConnection import DatabaseConnection
from protocols.wow.shared.utils.equipment import _parse_equipment_cache
from protocols.wow.shared.utils.player import _decode_player_bytes
from protocols.wow.shared.utils.guid import _guid_bytes_and_masks

from protocols.wow.shared.utils.guid import GuidHelper, HighGuid





def _load_raw_from_path(path: Path) -> Optional[bytes]:
    """Load raw (header+payload) bytes from a JSON dump path."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        Logger.error(f"[WorldHandlers] Failed to read {path}: {exc}")
        return None

    raw_hex = data.get("raw_data_hex")
    if raw_hex:
        try:
            return bytes.fromhex(raw_hex.replace(" ", ""))
        except Exception:
            Logger.error(f"[WorldHandlers] Invalid raw_data_hex in {path}")
            return None

    header_hex = data.get("raw_header_hex")
    payload_hex = data.get("hex_compact") or data.get("hex_spaced")
    if header_hex and payload_hex:
        try:
            header_bytes = bytes.fromhex(header_hex.replace(" ", ""))
            payload_bytes = bytes.fromhex(payload_hex.replace(" ", ""))
            return header_bytes + payload_bytes
        except Exception:
            Logger.error(f"[WorldHandlers] Invalid hex fields in {path}")
            return None
    return None


def _load_payload_from_path(path: Path) -> Optional[bytes]:
    """Load payload-only bytes from a JSON dump path."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        Logger.error(f"[WorldHandlers] Failed to read {path}: {exc}")
        return None

    payload_hex = data.get("hex_compact") or data.get("hex_spaced")
    if payload_hex:
        try:
            return bytes.fromhex(payload_hex.replace(" ", ""))
        except Exception:
            Logger.error(f"[WorldHandlers] Invalid payload hex in {path}")
            return None

    raw_hex = data.get("raw_data_hex")
    header_hex = data.get("raw_header_hex")
    if raw_hex and header_hex:
        try:
            raw_bytes = bytes.fromhex(raw_hex.replace(" ", ""))
            header_len = len(bytes.fromhex(header_hex.replace(" ", "")))
            return raw_bytes[header_len:]
        except Exception:
            Logger.error(f"[WorldHandlers] Invalid raw hex fields in {path}")
            return None

    return None


def _load_raw_packet(opcode_name: str) -> Optional[bytes]:
    """
    Load raw (header+payload) bytes for a server opcode from debug or captures.
    Includes focus captures if present.
    """
    paths = []
    proto_root = get_protocol_root()
    if proto_root:
        paths.append(proto_root / "data" / "debug" / f"{opcode_name}.json")
    paths.extend(
        [
            get_captures_root() / "debug" / f"{opcode_name}.json",
            get_captures_root(focus=True) / "debug" / f"{opcode_name}.json",
        ]
    )

    for path in paths:
        if not path.exists():
            continue
        raw = _load_raw_from_path(path)
        if raw:
           return raw, True

    return None

def _load_raw_packet_focus(opcode_name: str) -> Optional[bytes]:
    """
    Load raw (header+payload) bytes for a server opcode from debug or captures.
    Includes focus captures if present.
    """
    paths = []
    proto_root = get_protocol_root()
    if proto_root:
        paths.append(proto_root / "captures" / "focus" / "debug" / f"{opcode_name}.json")
    paths.extend(
        [
            get_captures_root() / "captures" / "focus" / "debug" / f"{opcode_name}.json",
            get_captures_root(focus=True) / "captures" / "focus" / "debug" / f"{opcode_name}.json",
        ]
    )

    for path in paths:
        if not path.exists():
            continue
        raw = _load_raw_from_path(path)
        if raw:
            return raw, True

    return None


def _load_payload_packet_focus(opcode_name: str) -> Optional[bytes]:
    """Load payload-only bytes from a focus capture JSON."""
    paths = []
    proto_root = get_protocol_root()
    if proto_root:
        paths.append(proto_root / "captures" / "focus" / "debug" / f"{opcode_name}.json")
    paths.extend(
        [
            get_captures_root() / "captures" / "focus" / "debug" / f"{opcode_name}.json",
            get_captures_root(focus=True) / "captures" / "focus" / "debug" / f"{opcode_name}.json",
        ]
    )

    for path in paths:
        if not path.exists():
            continue
        payload = _load_payload_from_path(path)
        if payload is not None:
            return payload

    return None


def _load_payload_packet(opcode_name: str) -> Optional[bytes]:
    """Load payload-only bytes for a server opcode from debug/captures."""
    paths = []
    proto_root = get_protocol_root()
    if proto_root:
        paths.append(proto_root / "data" / "debug" / f"{opcode_name}.json")
    paths.extend(
        [
            get_captures_root() / "debug" / f"{opcode_name}.json",
            get_captures_root(focus=True) / "debug" / f"{opcode_name}.json",
        ]
    )

    for path in paths:
        if not path.exists():
            continue
        payload = _load_payload_from_path(path)
        if payload is not None:
            return payload

    return None


# ---------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------

def _encode(name: str, data: Dict[str, Any]) -> bytes:
    """
    Centralized encoder wrapper so logging / debugging
    can be added in one place.
    """
    try:
        return EncoderHandler.encode_packet(name, data)
    except Exception as exc:
        Logger.error(f"[WorldLogin][ENCODE FAIL] {name}: {exc}")
        raise


# ------------------------------------------------------------
# Opcode → builder dispatch
# ------------------------------------------------------------

def build_login_packet(opcode: str, ctx):
    """
    Dispatch helper used by worldLogin.flow.

    Looks for a function named:
        build_<OPCODE_NAME>
    """
    fn_name = f"build_{opcode}"
    fn = globals().get(fn_name)

    if fn is None:
        return None

    return fn(ctx)

# ---------------------------------------------------------------------
# Core login packets
# ---------------------------------------------------------------------

def build_SMSG_SET_DUNGEON_DIFFICULTY(ctx) -> bytes:
    return _encode("SMSG_SET_DUNGEON_DIFFICULTY", {
        "difficulty": 0,
        "unknown": 0,
    })


# ---------------------------------------------------------------------
# Pre-loading packets
# ---------------------------------------------------------------------

def build_SMSG_ACCOUNT_DATA_TIMES_old(ctx) -> bytes:
    now = int(time.time())
    return _encode("SMSG_ACCOUNT_DATA_TIMES", {
        "flag": 0x80,
        "mask": 0,
        "timestamps": [now] * 8,
        "server_time": now,
    })


def build_SMSG_ACCOUNT_DATA_TIMES(_ctx=None) -> bytes:
    now = int(time.time())
    Logger.info(f"[ACCOUNT DATA] server_time={now}")
    payload = _encode("SMSG_ACCOUNT_DATA_TIMES", {
        "flag": 0x80,
        "mask": 0,
        "timestamps": [now] * 8,
        "server_time": now,
    })
    if len(payload) != 41:
        raise AssertionError(f"SMSG_ACCOUNT_DATA_TIMES malformed length: {len(payload)} != 41")
    return payload

def build_SMSG_CLIENTCACHE_VERSION(_ctx=None) -> bytes:
    ctx = _ctx or type("Ctx", (), {"client_cache_version": 5})()
    return _encode("SMSG_CLIENTCACHE_VERSION", {
        "version": int(getattr(ctx, "client_cache_version", 5)),
    })

def build_SMSG_TUTORIAL_FLAGS(ctx) -> bytes:
    fields = {
        "list": [
            19,
            2112,
            0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]
    }
    return EncoderHandler.encode_packet("SMSG_TUTORIAL_FLAGS", fields)


def build_SMSG_FEATURE_SYSTEM_STATUS(ctx) -> bytes:
    # Minimal Blizzard-safe MoP payload: keep all feature flags disabled except
    # mount preview. Build this packet raw to avoid any accidental flag
    # derivation from context or stale captures.
    payload = struct.pack(
        "<IIIIIIII3B",
        0,  # voice
        0,  # browser
        0,  # scroll
        1,  # mountpreview
        0,  # complaint1
        0,  # complaint2
        0,  # flags1
        0,  # flags2
        0, 0, 0,  # flags3[3]
    )
    Logger.info(f"[MOP DEBUG] FEATURE_SYSTEM_STATUS size={len(payload)}")
    if len(payload) != 35:
        raise AssertionError(f"SMSG_FEATURE_SYSTEM_STATUS malformed length: {len(payload)} != 35")
    return payload


def build_SMSG_MOTD_old(ctx) -> bytes:
    return _encode("SMSG_MOTD", {
        "motd": ctx.motd,
    })

def build_SMSG_MOTD(_ctx=None) -> bytes:
    ctx = _ctx or type("Ctx", (), {"motd": "Welcome to PyPandaria"})()
    motd = getattr(ctx, "motd", "Welcome to PyPandaria")
    if motd is None:
        motd = ""
    motd = str(motd)
    # MoP-safe MOTD: uint32 line_count followed by null-terminated strings.
    lines = [motd if motd else ""]
    payload = bytearray()
    payload += struct.pack("<I", len(lines))
    for line in lines:
        payload += line.encode("utf-8", errors="strict") + b"\x00"
    payload = bytes(payload)
    Logger.info(f"[MOP DEBUG] MOTD lines={len(lines)} size={len(payload)}")
    if len(payload) < 5:
        raise AssertionError(f"SMSG_MOTD malformed length: {len(payload)} < 5")
    return payload


def build_SMSG_PVP_SEASON(ctx) -> bytes:
    return _encode("SMSG_PVP_SEASON", {
        "current_season": ctx.pvp_season,
        "previous_season": ctx.pvp_prev_season,
    })


def build_SMSG_SET_TIME_ZONE_INFORMATION(ctx) -> bytes:
    tz = "Etc/UTC"
    fields = {
        "len1": len(tz),
        "len2": len(tz),
        "time_zone1": tz,
        "time_zone2": tz,
    }
    return EncoderHandler.encode_packet(
        "SMSG_SET_TIME_ZONE_INFORMATION",
        fields,
    )

def build_SMSG_HOTFIX_NOTIFY_BLOB(ctx) -> bytes:
    return _encode("SMSG_HOTFIX_NOTIFY_BLOB", {
        "count": 0,
    })


def build_SMSG_CONTACT_LIST(ctx) -> bytes:
    return _encode("SMSG_CONTACT_LIST", {
        "flags": 0,
        "count": 0,
        "contacts": [],
    })


def build_SMSG_BIND_POINT_UPDATE(ctx) -> bytes:
    return _encode("SMSG_BIND_POINT_UPDATE", {
        "map_id": int(getattr(ctx, "bind_map_id", 0) or getattr(ctx, "map_id", 0)),
        "x": float(getattr(ctx, "bind_x", getattr(ctx, "x", 0.0))),
        "y": float(getattr(ctx, "bind_y", getattr(ctx, "y", 0.0))),
        "z": float(getattr(ctx, "bind_z", getattr(ctx, "z", 0.0))),
        "area_id": int(getattr(ctx, "bind_area_id", 0) or getattr(ctx, "zone", 0)),
    })


def build_SMSG_UPDATE_TALENT_DATA(ctx) -> bytes:
    return _encode("SMSG_UPDATE_TALENT_DATA", {
        "active_spec_group": int(getattr(ctx, "activespec", 0) if hasattr(ctx, "activespec") else 0),
        "spec_group_count": 0,
        "spec_groups": [],
    })


def build_SMSG_WORLD_SERVER_INFO_old(ctx) -> bytes:
    return _encode("SMSG_WORLD_SERVER_INFO", ctx.world_server_info)


def build_SMSG_WORLD_SERVER_INFO(_ctx=None) -> bytes:
    ctx = _ctx or type("Ctx", (), {"world_server_info": {}})()
    info = dict(getattr(ctx, "world_server_info", {}) or {})
    return _encode("SMSG_WORLD_SERVER_INFO", {
        "is_tournament_realm": int(info.get("is_tournament_realm", 0)),
        "unk0": int(info.get("unk0", 0)),
        "weekly_reset_time": int(info.get("weekly_reset_time", 0)),
        "flags": int(info.get("flags", 0)),
    })


def build_SMSG_SEND_KNOWN_SPELLS(ctx) -> bytes:
    return _encode("SMSG_SEND_KNOWN_SPELLS", {
        "initial_login": 1,
        "spell_count": len(getattr(ctx, "known_spells", []) or []),
        "spells": [{"spell_id": int(spell)} for spell in (getattr(ctx, "known_spells", []) or [])],
    })


def build_SMSG_SEND_UNLEARN_SPELLS(ctx) -> bytes:
    return _encode("SMSG_SEND_UNLEARN_SPELLS", {
        "count": 0,
        "spells": [],
    })


def build_SMSG_UPDATE_ACTION_BUTTONS(ctx) -> bytes:
    # MoP 5.4.x uses a bitpacked/XOR'd 132-entry action bar payload.
    # We build it manually here until a proper DSL case exists.
    button_count = 132
    packet_type = 1
    source_buttons = list(getattr(ctx, "action_buttons", []) or [])
    button_values = [0] * button_count

    for index, value in enumerate(source_buttons[:button_count]):
        try:
            button_values[index] = int(value) & 0xFFFFFFFF
        except Exception:
            button_values[index] = 0

    button_bytes = [
        list(int(value).to_bytes(8, "little", signed=False))
        for value in button_values
    ]

    bits = BitWriter()
    for byte_index in (4, 5, 3, 1, 6, 7, 0, 2):
        for raw in button_bytes:
            bits.write_bits(1 if raw[byte_index] else 0, 1)

    payload = bytearray(bits.getvalue())

    for byte_index in (0, 1, 4, 6, 7, 2, 5, 3):
        for raw in button_bytes:
            if raw[byte_index]:
                payload.append(raw[byte_index] ^ 0x01)

    payload.append(packet_type & 0xFF)
    return bytes(payload)


def build_SMSG_INITIALIZE_FACTIONS(ctx) -> bytes:
    factions = list(getattr(ctx, "factions", []) or [])
    if not factions:
        factions = [{"flags": 0, "standing": 0} for _ in range(163)]
    return _encode("SMSG_INITIALIZE_FACTIONS", {
        "count": 0,
        "factions": factions[:163],
    })


def build_SMSG_ALL_ACHIEVEMENT_DATA(ctx) -> bytes:
    return _encode("SMSG_ALL_ACHIEVEMENT_DATA", {
        "criteria_count": 0,
        "achievement_count": 0,
    })


def build_SMSG_LOAD_EQUIPMENT_SET(ctx) -> bytes:
    return _encode("SMSG_LOAD_EQUIPMENT_SET", {
        "set_count": 0,
    })


def build_SMSG_LOGIN_SET_TIME_SPEED_old(ctx) -> bytes:
    return _encode("SMSG_LOGIN_SET_TIME_SPEED", {
        "server_time": ctx.server_time,
        "game_time": 0,
        "speed": 1.0,
    })


def build_SMSG_LOGIN_SET_TIME_SPEED(_ctx=None) -> bytes:
    ctx = _ctx or type("Ctx", (), {"server_time": int(time.time())})()
    server_time = int(getattr(ctx, "server_time", int(time.time())))
    game_time = int(getattr(ctx, "game_time", server_time))
    time_speed = float(getattr(ctx, "time_speed", 0.01666667))
    return _encode("SMSG_LOGIN_SET_TIME_SPEED", {
        "unk_1": 0,
        "game_time_1": game_time,
        "unk_2": 0,
        "game_time_2": game_time,
        "time_speed": time_speed,
    })



def build_SMSG_SET_FORCED_REACTIONS(ctx) -> bytes:
    return _encode("SMSG_SET_FORCED_REACTIONS", {
        "faction_count": 0,
        "reactions": [],
    })


def build_SMSG_QUERY_TIME_RESPONSE(_ctx=None) -> bytes:
    ctx = _ctx or type("Ctx", (), {"server_time": int(time.time())})()
    return _encode("SMSG_QUERY_TIME_RESPONSE", {
        "server_time": int(getattr(ctx, "server_time", int(time.time()))),
        "unk": int(getattr(ctx, "query_time_unk", 24024)),
    })


def build_SMSG_UI_TIME(_ctx=None) -> bytes:
    ctx = _ctx or type("Ctx", (), {"server_time": int(time.time())})()
    return _encode("SMSG_UI_TIME", {
        "server_time": int(getattr(ctx, "server_time", int(time.time()))),
    })


def build_SMSG_SETUP_CURRENCY(ctx) -> bytes:
    return _encode("SMSG_SETUP_CURRENCY", {
        "currencies": [],
    })


# ---------------------------------------------------------------------
# Post-loading packets (world entered)
# ---------------------------------------------------------------------

def build_SMSG_LOGIN_VERIFY_WORLD_old(ctx) -> bytes:
    row = DatabaseConnection.get_character(2, 1)
    if not row:
        raise RuntimeError("Character 2 not found in DB")

    return EncoderHandler.encode_packet(
        "SMSG_LOGIN_VERIFY_WORLD",
        {
            "x": float(row.position_x),
            "facing": float(row.orientation),
            "y": float(row.position_y),
            "map": int(row.map),
            "z": float(row.position_z),
        },
    )

def build_SMSG_LOGIN_VERIFY_WORLD(_ctx=None) -> bytes:
    ctx = _ctx or type(
        "Ctx",
        (),
        {"x": 0.0, "y": 0.0, "z": 0.0, "orientation": 0.0, "map_id": 0},
    )()
    return _encode("SMSG_LOGIN_VERIFY_WORLD", {
        "x": float(getattr(ctx, "x", 0.0)),
        "facing": float(getattr(ctx, "orientation", 0.0)),
        "y": float(getattr(ctx, "y", 0.0)),
        "map": int(getattr(ctx, "map_id", 0)),
        "z": float(getattr(ctx, "z", 0.0)),
    })


def build_SMSG_UPDATE_OBJECT_old(_ctx=None) -> bytes:
    """
    Send captured raw SMSG_UPDATE_OBJECT.
    Bypasses DSL completely.
    """
    raw = _load_raw_packet("SMSG_UPDATE_OBJECT")
    if not raw:
        raise RuntimeError("Raw SMSG_UPDATE_OBJECT not found")
    return raw


def build_SMSG_UPDATE_OBJECT_1768335962(_ctx=None) -> bytes:
    """
    Send captured raw SMSG_UPDATE_OBJECT.
    Bypasses DSL completely.
    """
    raw = _load_raw_packet_focus("SMSG_UPDATE_OBJECT")
    if not raw:
        raise RuntimeError("Raw SMSG_UPDATE_OBJECT not found")
    return raw

def build_SMSG_UPDATE_OBJECT_1768335964(_ctx=None) -> bytes:
    """
    Send captured raw SMSG_UPDATE_OBJECT.
    Bypasses DSL completely.
    """
    raw = _load_raw_packet_focus("SMSG_UPDATE_OBJECT_1768335964")
    if not raw:
        raise RuntimeError("Raw SMSG_UPDATE_OBJECT_1768335964 not found")
    return raw

def build_SMSG_UPDATE_OBJECT_1768336025(_ctx=None) -> bytes:
    """
    Send captured raw SMSG_UPDATE_OBJECT.
    Bypasses DSL completely.
    """
    raw = _load_raw_packet_focus("SMSG_UPDATE_OBJECT_1768336025")
    if not raw:
        raise RuntimeError("Raw SMSG_UPDATE_OBJECT_1768336025 not found")
    return raw

def build_SMSG_UPDATE_OBJECT_1768336030(_ctx=None) -> bytes:
    """
    Send captured raw SMSG_UPDATE_OBJECT.
    Bypasses DSL completely.
    """
    raw = _load_raw_packet_focus("SMSG_UPDATE_OBJECT_1768336030")
    if not raw:
        raise RuntimeError("Raw SMSG_UPDATE_OBJECT_1768336030 not found")
    return raw

def build_SMSG_UPDATE_OBJECT_1768336134(_ctx=None) -> bytes:
    """
    Send captured raw SMSG_UPDATE_OBJECT.
    Bypasses DSL completely.
    """
    raw = _load_raw_packet_focus("SMSG_UPDATE_OBJECT_1768336134")
    if not raw:
        raise RuntimeError("Raw SMSG_UPDATE_OBJECT_1768336134 not found")
    return raw


def _resolve_update_world_guid(ctx: Any) -> int:
    world_guid = getattr(ctx, "world_guid", None)
    if world_guid is None:
        world_guid = GuidHelper.make(
            high=HighGuid.PLAYER,
            realm=int(getattr(ctx, "realm_id", 0) or 0),
            low=int(getattr(ctx, "char_guid", 0) or 0),
        )
    return int(world_guid)


def _build_manual_active_mover_payload(mover_guid: int) -> bytes:
    raw = int(mover_guid).to_bytes(8, "little", signed=False)
    payload = bytes([raw[0], raw[6]])
    if len(payload) != 2:
        raise AssertionError(
            f"SMSG_MOVE_SET_ACTIVE_MOVER manual payload length mismatch: {len(payload)} != 2"
        )
    return payload

def build_SMSG_PHASE_SHIFT_CHANGE_old(ctx) -> bytes:
    return _encode("SMSG_PHASE_SHIFT_CHANGE", {
        "phase_mask": 1,
        "terrain_swap": 0,
        "phase_count": 0,
        "phase_ids": [],
        "visible_map_count": 0,
        "visible_map_ids": [],
        "ui_map_phase_count": 0,
        "ui_map_phase_ids": [],
    })

def build_SMSG_PHASE_SHIFT_CHANGE(_ctx=None) -> bytes:
    ctx = _ctx or type("Ctx", (), {})()
    return _encode("SMSG_PHASE_SHIFT_CHANGE", {
        "phase_mask": int(getattr(ctx, "phase_mask", 1) or 1),
        "terrain_swap": int(getattr(ctx, "terrain_swap", 0) or 0),
        "phase_count": int(getattr(ctx, "phase_count", 0) or 0),
        "phase_ids": list(getattr(ctx, "phase_ids", []) or []),
        "visible_map_count": int(getattr(ctx, "visible_map_count", 0) or 0),
        "visible_map_ids": list(getattr(ctx, "visible_map_ids", []) or []),
        "ui_map_phase_count": int(getattr(ctx, "ui_map_phase_count", 0) or 0),
        "ui_map_phase_ids": list(getattr(ctx, "ui_map_phase_ids", []) or []),
    })


def build_SMSG_TRANSFER_PENDING(_ctx=None) -> bytes:
    ctx = _ctx or type("Ctx", (), {"map_id": 0})()
    return _encode("SMSG_TRANSFER_PENDING", {
        "map_id": int(getattr(ctx, "map_id", 0) or 0),
    })


def build_SMSG_NEW_WORLD(_ctx=None) -> bytes:
    ctx = _ctx or type(
        "Ctx",
        (),
        {"map_id": 0, "x": 0.0, "y": 0.0, "z": 0.0, "orientation": 0.0},
    )()
    return _encode("SMSG_NEW_WORLD", {
        "map_id": int(getattr(ctx, "map_id", 0) or 0),
        "x": float(getattr(ctx, "x", 0.0) or 0.0),
        "y": float(getattr(ctx, "y", 0.0) or 0.0),
        "z": float(getattr(ctx, "z", 0.0) or 0.0),
        "orientation": float(getattr(ctx, "orientation", 0.0) or 0.0),
    })

def build_SMSG_INIT_WORLD_STATES_old(ctx) -> bytes:
    return _encode("SMSG_INIT_WORLD_STATES", {
        "map_id": ctx.map_id,
        "zone_id": ctx.zone,
        "area_id": 0,
        "world_states": [],
    })

def build_SMSG_INIT_WORLD_STATES(_ctx=None) -> bytes:
    ctx = _ctx or type("Ctx", (), {"map_id": 0, "zone": 0})()
    return _encode("SMSG_INIT_WORLD_STATES", {
        "map_id": int(getattr(ctx, "map_id", 0)),
        "zone_id": int(getattr(ctx, "zone", 0)),
        "area_id": int(getattr(ctx, "zone", 0)),
        "states": [],
        "_": 0,
    })


def handle_CMSG_REQUEST_HOTFIX(sock, opcode, payload):
    captured = _load_payload_packet("SMSG_HOTFIX_NOTIFY_BLOB")
    if captured is not None:
        return 0, ("SMSG_HOTFIX_NOTIFY_BLOB", captured)
    return 0, ("SMSG_HOTFIX_NOTIFY_BLOB", _encode("SMSG_HOTFIX_NOTIFY_BLOB", {
        "count": 0,
    }))

def build_SMSG_UPDATE_WORLD_STATE(ctx) -> bytes:
    return _encode("SMSG_UPDATE_WORLD_STATE", {
        "hidden": 0,
        "value": int(getattr(ctx, "value", 0) or 0),
        "state_id": int(getattr(ctx, "variable_id", 0) or 0),
    })

def build_SMSG_WEATHER(ctx) -> bytes:
    return _encode("SMSG_WEATHER", {
        "weather_id": 0,   # clear
        "intensity": 0.0,
        "abrupt": 0,
    })
def build_SMSG_HOTFIX_NOTIFY_BLOB(_ctx=None) -> bytes:
    return _encode("SMSG_HOTFIX_NOTIFY_BLOB", {
        "count": 0,
    })

def build_SMSG_TIME_SYNC_REQUEST_old(ctx) -> bytes:
    return _encode("SMSG_TIME_SYNC_REQUEST", {
        "sequence_id": ctx.time_sync_seq,
    })

def build_SMSG_TIME_SYNC_REQUEST(_ctx=None) -> bytes:
    ctx = _ctx or type("Ctx", (), {"time_sync_seq": 0})()
    return _encode("SMSG_TIME_SYNC_REQUEST", {
        "sequence_id": int(getattr(ctx, "time_sync_seq", 0)),
    })

def build_SMSG_LOAD_CUF_PROFILES(ctx) -> bytes:
    return _encode("SMSG_LOAD_CUF_PROFILES", {
        "profiles": [],
    })
# packets.py

def build_SMSG_AUTH_RESPONSE(ctx) -> bytes:
    realm = DatabaseConnection.get_all_realms()[0]

    races = [{"expansion": 4, "race_id": r} for r in RACES_MOP]
    classes = [{"expansion": 4, "class_id": c} for c in CLASSES_MOP]

    fields = {
        "auth_ok": 1,
        "realm_count": 1,

        "realm_meta_data": [{
            "name_len": len(realm.name),
            "normalized_len": len(realm.name.lower()),
            "is_home": 1,
            "class_count": len(classes),
            "unk21": 0,
            "flag0": realm.flag or 0,
            "flag1": 0,
            "flag2": 0,
            "flag3": 0,
            "race_count": len(races),
            "empty_bit": 0,
            "queued": int(realm.population > 1.5),
        }],

        "realm": [{
            "realm_id": realm.id,
            "realm_name": realm.name,
            "normalized_name": realm.name.lower(),

            "races": races,
            "classes": classes,

            "flag1_int": realm.flag or 0,
            "expansion_active": 4,
            "flag2_int": 0,
            "flag3_int": 0,
            "expansion_server": 4,
            "flag4_int": 0,
            "flag5_int": 0,
            "flag6_int": 0,
            "auth_result": 12,
        }],
    }

    return EncoderHandler.encode_packet("SMSG_AUTH_RESPONSE", fields)


def build_SMSG_ADDON_INFO(addons: list[dict]) -> bytes:
    return _encode("SMSG_ADDON_INFO", {
        "addons": addons,
    })


def build_SMSG_TUTORIAL_FLAGS(ctx) -> bytes:
    values = list(getattr(ctx, "tutorial_flags", []) or [])
    if len(values) < 16:
        values.extend([0] * (16 - len(values)))
    return _encode("SMSG_TUTORIAL_FLAGS", {
        "list": values[:16],
    })


CHAR_META_MASK_FIELDS = (
    # guid masks
    "guid_0_mask",
    "guid_1_mask",
    "guid_2_mask",
    "guid_3_mask",
    "guid_4_mask",
    "guid_5_mask",
    "guid_6_mask",
    "guid_7_mask",

    # guild guid masks (BÅDA NAMNEN)
    "guildguid_0_mask",
    "guildguid_1_mask",
    "guildguid_2_mask",
    "guildguid_3_mask",
    "guildguid_4_mask",
    "guildguid_5_mask",
    "guildguid_6_mask",
    "guildguid_7_mask",
)

def build_SMSG_MOVE_SET_ACTIVE_MOVER(_ctx=None) -> bytes:
    ctx = _ctx or type("Ctx", (), {"world_guid": None, "realm_id": 0, "char_guid": 0})()
    mover_guid = _resolve_update_world_guid(ctx)
    mover_guid_mask = GuidHelper.pack(mover_guid)[0]
    Logger.info(
        f"[ACTIVE_MOVER DEBUG] guid={hex(int(mover_guid))} mask=0x{mover_guid_mask:02X}"
    )
    return _encode("SMSG_MOVE_SET_ACTIVE_MOVER", {
        "raw": _build_manual_active_mover_payload(mover_guid),
    })

def build_SMSG_MOVE_SET_ACTIVE_MOVER_old(ctx) -> bytes:
    mover_guid = GuidHelper.make(
        high=HighGuid.PLAYER,
        realm=int(getattr(ctx, "realm_id", 0) or 0),
        low=int(getattr(ctx, "char_guid", 0) or 0),
    )

    return _encode("SMSG_MOVE_SET_ACTIVE_MOVER", {
        "moverGUID": mover_guid,
    })

def build_ENUM_CHARACTERS_RESULT(account_id: int, realm_id: int) -> bytes:
    """
    Build SMSG_ENUM_CHARACTERS_RESULT using ONLY live DB data.
    No fallbacks. Invalid characters are skipped.
    """

    rows = DatabaseConnection.get_characters_for_account(account_id, realm_id)

    chars_meta: list[dict] = []
    chars: list[dict] = []

    for idx, row in enumerate(rows):
        try:
            # ---------- NAME ----------
            name = row.name or ""
            name_bytes = name.encode("utf-8")
            if not (1 <= len(name_bytes) <= 63):
                Logger.error(f"[ENUM] Invalid name length guid={row.guid}")
                continue

            # ---------- GUID ----------
            enum_guid = GuidHelper.make(
                high=HighGuid.PLAYER,
                realm=int(realm_id),
                low=int(row.guid),
            )
            guid_bytes, guid_masks = _guid_bytes_and_masks(enum_guid)
            if not guid_masks:
                Logger.error(f"[ENUM] Invalid GUID masks guid={row.guid}")
                continue

            # ---------- META ----------
            # Starta med ALLA maskfält satta till 0 (DSL-krav)
            meta = {
                # guid masks
                "guid_0_mask": 0,
                "guid_1_mask": 0,
                "guid_2_mask": 0,
                "guid_3_mask": 0,
                "guid_4_mask": 0,
                "guid_5_mask": 0,
                "guid_6_mask": 0,
                "guid_7_mask": 0,

                # guild guid masks (båda namnformerna)
                "guildguid_0_mask": 0,
                "guildguid_1_mask": 0,
                "guildguid_2_mask": 0,
                "guildguid_3_mask": 0,
                "guildguid_4_mask": 0,
                "guildguid_5_mask": 0,
                "guildguid_6_mask": 0,
                "guildguid_7_mask": 0,

                # övriga meta-fält
                "boosted": 0,
                "at_login_first": 1 if row.at_login else 0,
                "name_len": len(name_bytes),
            }

            # Applicera GUID-masker (överskriver 0 → 1 där byte != 0)
            meta.update(guid_masks)

            # ---------- APPEARANCE ----------
            appearance = _decode_player_bytes(row.playerBytes, row.playerBytes2)
            if not appearance:
                Logger.error(f"[ENUM] Missing appearance guid={row.guid}")
                continue

            # ---------- EQUIPMENT ----------
            equipment = _parse_equipment_cache(row.equipmentCache or "")
            if not equipment or len(equipment) != 23:
                Logger.warning(f"[ENUM] Invalid equipment guid={row.guid}, using empty fallback")
                equipment = [
                    {"enchant": 0, "int_type": 0, "display_id": 0}
                    for _ in range(23)
                ]

            # ---------- CHARACTER ----------
            char = {
                "unk02": 0,
                "slot": row.slot,
                "hair_style": appearance["hair_style"],
                "name": name,
                "x": float(row.position_x),
                "unk00": 0,
                "face": appearance["face"],
                "class": int(row.class_),
                "equipment": equipment,
                "customizationFlag": int(row.at_login),
                "petFamily": 0,
                "mapId": int(row.map),
                "race": int(row.race),
                "skin": appearance["skin"],
                "level": int(row.level),
                "hair_color": appearance["hair_color"],
                "gender": int(row.gender),
                "facial_hair": appearance["facial_hair"],
                "pet_level": 0,
                "y": float(row.position_y),
                "petDisplayID": 0,
                "unk3": 0,
                "char_flags": int(row.playerFlags),
                "zone": int(row.zone),
                "z": float(row.position_z),
                "guid": 0,        # combined by DSL
                "guildguid": 0,   # combined by DSL
            }

            # Inject GUID bytes conditionally
            for i in range(8):
                if meta.get(f"guid_{i}_mask"):
                    char[f"guid_{i}"] = guid_bytes[i]

            chars_meta.append(meta)
            chars.append(char)

        except Exception as exc:
            Logger.error(f"[ENUM] Failed guid={getattr(row, 'guid', None)}: {exc}")
            continue

    fields = {
        "faction_mask_bits": 0,
        "char_count_bits": len(chars),
        "chars_meta": chars_meta,
        "success": 1,
        "chars": chars,
    }

    Logger.info(
        f"[ENUM] Built {len(chars)} characters for account={account_id} realm={realm_id}"
    )

    return EncoderHandler.encode_packet("SMSG_ENUM_CHARACTERS_RESULT", fields)
