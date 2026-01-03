#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Vanilla 1.12.1 authentication handling (SRP6).

Handles:
    • AUTH_LOGON_CHALLENGE_C
    • AUTH_LOGON_PROOF_C
    • REALM_LIST_C
    • AUTH_RECONNECT_CHALLENGE_C

Used by AuthServer to process DSL-decoded packets.
"""

import os
import json
import socket
import traceback

from utils.Logger import Logger
from utils.ConfigLoader import ConfigLoader
from protocols.wow.shared.utils.OpcodeLoader import load_auth_opcodes

from modules.dsl.DecoderHandler import DecoderHandler
from modules.dsl.EncoderHandler import EncoderHandler
from modules.dsl.NodeTreeParser import NodeTreeParser
from modules.dsl.Processor import load_case
from modules.dsl.Session import get_session

from protocols.wow.vanilla.v1121.modules.crypto.SRP6Session import SRP6Session
from protocols.wow.vanilla.v1121.modules.database.DatabaseConnection import DatabaseConnection


# ---- Global state ---------------------------------------------------------

srp6_sessions: dict[int, SRP6Session] = {}
authenticated_users: dict[int, str] = {}

# Opcode maps: int → name (per direction) + reverse for convenience
AUTH_CLIENT_OPCODES, AUTH_SERVER_OPCODES, _ = load_auth_opcodes()
AUTH_SERVER_OPCODE_BY_NAME = {name: code for code, name in AUTH_SERVER_OPCODES.items()}


# ---- DSL decoding ---------------------------------------------------------

def dsl_decode(def_name: str, payload: bytes, silent: bool = False) -> dict:
    cfg = ConfigLoader.load_config()
    program = cfg["program"]
    expansion = cfg.get("expansion")
    version = cfg["version"]

    name, lines, _, expected, _ = load_case(
        program,
        version,
        def_name,
        expansion=expansion,
    )

    session = get_session()
    session.reset()

    NodeTreeParser.parse((name, lines, payload, expected))
    return DecoderHandler.decode((name, lines, payload, expected), silent=silent)


# ---- AUTH_LOGON_CHALLENGE ----------------------------------------------

def handle_AUTH_LOGON_CHALLENGE_C(client_socket, opcode, data: bytes):
    cfg = ConfigLoader.load_config()

    try:
        decoded = dsl_decode("AUTH_LOGON_CHALLENGE_C", data, silent=True)
    except Exception as exc:
        Logger.error(f"[AUTH_LOGON_CHALLENGE_C] Decode failed: {exc}")
        return 1, None

    username = (decoded.get("I") or decoded.get("username") or "").upper()
    if not username:
        return 0, EncoderHandler.encode_packet(
            "AUTH_LOGON_CHALLENGE_S", {"cmd": 0, "error": 4}
        )

    account = DatabaseConnection.get_user_by_username(username)
    if account is None:
        return 0, EncoderHandler.encode_packet(
            "AUTH_LOGON_CHALLENGE_S", {"cmd": 0, "error": 4}
        )

    # ---- Vanilla: SRP verifier from account salt/verifier ----
    salt_hex = getattr(account, "s", None) or getattr(account, "salt", None)
    verifier_hex = getattr(account, "v", None) or getattr(account, "verifier", None)
    if not salt_hex or not verifier_hex:
        return 0, EncoderHandler.encode_packet(
            "AUTH_LOGON_CHALLENGE_S", {"cmd": 0, "error": 2}
        )

    srp_mode = cfg.get("crypto", {}).get("srp6_mode", "vmangos")
    verifier_endian = "little" if srp_mode in ("skyfire", "vmangos", "vanilla") else "big"

    def _coerce_srp_bytes(value, size: int, endian: str):
        if value is None:
            return None
        if isinstance(value, (bytes, bytearray)):
            raw = bytes(value)
        elif isinstance(value, str):
            v = value.strip()
            try:
                raw = bytes.fromhex(v)
            except Exception:
                raw = int(v, 0).to_bytes(size, endian, signed=False)
        elif isinstance(value, int):
            raw = int(value).to_bytes(size, endian, signed=False)
        else:
            try:
                raw = bytes(value)
            except Exception:
                return None
        if size and len(raw) != size:
            return None
        return raw

    try:
        salt_bytes = _coerce_srp_bytes(salt_hex, 32, "little")
        verifier_bytes = _coerce_srp_bytes(verifier_hex, 32, verifier_endian)
    except Exception as exc:
        Logger.error(f"[AUTH_LOGON_CHALLENGE] Invalid SRP data: {exc}")
        return 0, EncoderHandler.encode_packet(
            "AUTH_LOGON_CHALLENGE_S", {"cmd": 0, "error": 2}
        )

    storage_endian = str(cfg.get("crypto", {}).get("srp6_storage_endian", "")).lower()
    if not storage_endian and srp_mode in ("vmangos", "vanilla"):
        storage_endian = "big"

    if storage_endian in ("big", "be"):
        if salt_bytes:
            salt_bytes = salt_bytes[::-1]
        if verifier_bytes:
            verifier_bytes = verifier_bytes[::-1]
    elif storage_endian in ("little", "le"):
        pass

    if len(salt_bytes) != 32 or len(verifier_bytes) != 32:
        Logger.error("[AUTH_LOGON_CHALLENGE] SRP salt/verifier size mismatch")
        return 0, EncoderHandler.encode_packet(
            "AUTH_LOGON_CHALLENGE_S", {"cmd": 0, "error": 2}
        )

    session = SRP6Session(username, salt_bytes, verifier_bytes, mode=srp_mode)
    fd = client_socket.fileno()
    srp6_sessions[fd] = session

    try:
        B_bytes = session.generate_B()
    except Exception as exc:
        Logger.error(f"[AUTH_LOGON_CHALLENGE] SRP generate_B failed: {exc}")
        srp6_sessions.pop(fd, None)
        return 0, EncoderHandler.encode_packet(
            "AUTH_LOGON_CHALLENGE_S", {"cmd": 0, "error": 2}
        )

    Logger.info(
        "[SRP6] "
        f"mode={srp_mode} "
        f"N={session.core.get_N_bytes().hex().upper()} "
        f"B={B_bytes.hex().upper()} "
        f"B_len={len(B_bytes)}"
    )

    fields = {
        "cmd": 0,
        "error": 0,
        "B": B_bytes,
        "l": 1,
        "g": session.core.G,
        "blob": 32,
        "N": session.core.get_N_bytes(),
        "s": salt_bytes,
        "unk3": os.urandom(16),
        "securityFlags": 0,
    }

    try:
        return 0, build_AUTH_LOGON_CHALLENGE_S(fields)
    except Exception:
        srp6_sessions.pop(fd, None)
        return 1, None

def build_AUTH_LOGON_CHALLENGE_S(fields: dict) -> bytes:
    """
    Encode AUTH_LOGON_CHALLENGE_S using provided fields.
    Keeps handling logic separate from encoding for reuse and clarity.
    """
    return EncoderHandler.encode_packet("AUTH_LOGON_CHALLENGE_S", fields)


# ---- AUTH_LOGON_PROOF --------------------------------------------------

def _dump_srp_session(session):
    if session is None:
        return
    def fmt(v):
        if isinstance(v, (bytes, bytearray)):
            return v.hex().upper()
        return v
    fields = {k: fmt(v) for k, v in vars(session).items() if k != "core"}
    # Lägg till lite från core också
    fields["core.mode"] = session.core.mode
    fields["core.endian"] = session.core._endian
    fields["core.G"] = session.core.G
    fields["core.N"] = session.core.get_N_bytes().hex().upper()
    Logger.info("[SRP6] session " + json.dumps(fields, indent=2, default=str))

def handle_AUTH_LOGON_PROOF_C(client_socket, opcode, data: bytes):
    try:
        decoded = dsl_decode("AUTH_LOGON_PROOF_C", data, silent=True)
        Logger.success("AUTH_LOGON_PROOF_C\n" + json.dumps(decoded, indent=4))
    except Exception as exc:
        Logger.error(f"[AUTH_LOGON_PROOF_C] Decode failed: {exc}")
        return 1, None

    fd = client_socket.fileno()
    session = srp6_sessions.get(fd)
    if not session:
        Logger.error("[AUTH_LOGON_PROOF] No SRP session for socket")
        return 1, None
    _dump_srp_session(session)

    A_raw = decoded.get("A")
    M1_raw = decoded.get("M1")

    A = bytes.fromhex(A_raw) if isinstance(A_raw, str) else A_raw
    M1 = bytes.fromhex(M1_raw) if isinstance(M1_raw, str) else M1_raw

    if not A or not M1:
        Logger.error("[AUTH_LOGON_PROOF] Missing A or M1")
        srp6_sessions.pop(fd, None)
        return 1, None

    # ---- SRP verification ----
    try:
        ok, M2, session_key = session.verify_proof(A, M1)
    except Exception as exc:
        def hx(x): return x.hex().upper() if isinstance(x, (bytes, bytearray)) else x
        Logger.error(
            "[AUTH_LOGON_PROOF] SRP verify failed: "
            f"{exc} user={session.username} "
            f"A={hx(A)} M1={hx(M1)} "
            f"salt={hx(getattr(session, 'salt', b''))} "
            f"verifier={hx(getattr(session, 'verifier', b''))} "
            f"B={hx(getattr(session, 'B', b''))}"
        )
        srp6_sessions.pop(fd, None)
        return 1, None

    if not ok:
        def hx(x): return x.hex().upper() if isinstance(x, (bytes, bytearray)) else x
        Logger.error(
            "[AUTH_LOGON_PROOF] SRP proof invalid "
            f"user={session.username} "
            f"A={hx(A)} "
            f"M1_client={hx(M1)} "
            f"salt={hx(getattr(session, 'salt', b''))} "
            f"verifier={hx(getattr(session, 'verifier', b''))} "
            f"B={hx(getattr(session, 'B', b''))}"
        )
        srp6_sessions.pop(fd, None)
        return 1, None

    # ---- Persist session key ----
    try:
        account = DatabaseConnection.get_user_by_username(session.username)
        if not account:
            Logger.error("[AUTH_LOGON_PROOF] Account not found after SRP success")
            srp6_sessions.pop(fd, None)
            return 1, None

        if session_key:
            DatabaseConnection.update_login_metadata(
                account=account,
                session_key_bytes=session_key,
                last_ip=client_socket.getpeername()[0],
            )
    except Exception as exc:
        Logger.error(f"[AUTH_LOGON_PROOF] Failed to update DB: {exc}")

    authenticated_users[fd] = session.username

    # ---- Build AUTH_LOGON_PROOF_S (Vanilla) ----
    try:
        fields = {"cmd": 1, "M2": M2, "error": 0, "unk1": 0}
        out = build_AUTH_LOGON_PROOF_S(fields)
    except Exception as exc:
        Logger.error(f"[AUTH_LOGON_PROOF_S] Encoding failed: {exc}")
        srp6_sessions.pop(fd, None)
        return 1, None

    srp6_sessions.pop(fd, None)
    return 0, out


def build_AUTH_LOGON_PROOF_S(fields: dict) -> bytes:
    """
    Encode AUTH_LOGON_PROOF_S using provided fields.
    """
    return EncoderHandler.encode_packet("AUTH_LOGON_PROOF_S", fields)


# ---- REALM LIST ----------------------------------------------------------

def calculate_population(char_count: int) -> float:
    if char_count <= 0:
        return 0.05
    if char_count < 50:
        return 1.0
    if char_count < 200:
        return 2.0
    if char_count < 1000:
        return 3.0
    return 5.0


def is_realm_online(address: str, port: int) -> bool:
    try:
        with socket.create_connection((address, port), timeout=0.1):
            return True
    except Exception:
        return False


def realm_flag(online: bool) -> int:
    return 0 if online else 4


def build_realmlist_entries(realms, account_id):
    entries = []

    for realm in realms:
        if account_id is None:
            char_count = 0
        else:
            char_count = DatabaseConnection.count_characters_for_account(
                account_id, realm.id
            )

        online = is_realm_online(realm.address, realm.port)

        entries.append({
            "icon": realm.icon,
            "realmflags": realm_flag(online),
            "name": realm.name,
            "address": f"{realm.address}:{realm.port}",
            "pop": calculate_population(char_count),
            "characters": char_count,
            "timezone": realm.timezone,
            "realmid": realm.id,
        })

    return entries

def handle_REALM_LIST_C(client_socket, opcode, data: bytes):
    try:
        decoded = dsl_decode("REALM_LIST_C", data, silent=True)
        Logger.info(f"[REALM_LIST_C] {decoded}")
    except Exception:
        pass

    fd = client_socket.fileno()
    username = authenticated_users.get(fd)

    account_id = None

    if username:
        acc = DatabaseConnection.get_user_by_username(username)
        if acc:
            account_id = acc.id

    db_realms = DatabaseConnection.get_all_realms()
    if not db_realms:
        Logger.error("[REALM_LIST] No realms in DB")
        return 1, None

    realm_entries = build_realmlist_entries(db_realms, account_id)

    try:
        out = build_REALM_LIST_S(realm_entries)
        Logger.info(f"REALM_LIST_S raw: {out.hex().upper()}")
        return 0, out
    except Exception as exc:
        Logger.error(f"[REALM_LIST_S] Encoding failed: {exc}")
        Logger.error(traceback.format_exc())
        return 1, None

def build_REALM_LIST_S(realm_entries) -> bytes:
    fields = {
        "cmd": 0x10,
        "size": 0,  # will be patched after encode
        "unk1": 0,
        "realm_count": len(realm_entries),
        "realmlist": realm_entries,
        "unk2": 0x02,
    }
    encoded = EncoderHandler.encode_packet("REALM_LIST_S", fields)
    size = max(0, len(encoded) - 3)
    if fields["size"] != size:
        fields["size"] = size
        encoded = EncoderHandler.encode_packet("REALM_LIST_S", fields)
    return encoded


# ---- AUTH_RECONNECT_CHALLENGE -----------------------------------------

def handle_AUTH_RECONNECT_CHALLENGE_C(client_socket, opcode, data: bytes):
    """
    Handle AUTH_RECONNECT_CHALLENGE_C.
    Input: client socket, opcode byte, raw payload.
    Output: (err, response_bytes) tuple built from DSL encoder.
    """
    try:
        decoded = dsl_decode("AUTH_RECONNECT_CHALLENGE_C", data, silent=True)
        Logger.info(f"[AUTH_RECONNECT_CHALLENGE_C] {decoded}")
    except Exception:
        pass

    try:
        out = build_AUTH_RECONNECT_CHALLENGE_S()
        return 0, out
    except Exception as exc:
        Logger.error(f"[AUTH_RECONNECT_CHALLENGE_S] Encode failed: {exc}")
        return 1, None

def build_AUTH_RECONNECT_CHALLENGE_S() -> bytes:
    """
    Build AUTH_RECONNECT_CHALLENGE_S packet.
    Input: none; uses os.urandom for two 16-byte fields, cmd fixed to 0x02.
    Output: raw bytes ready to send (header+payload per EncoderHandler).
    """
    fields = {
        "cmd": 0x02,
        "_1": 0,
        "reconnectProof": os.urandom(16),
        "_2": os.urandom(16),
    }

    return EncoderHandler.encode_packet("AUTH_RECONNECT_CHALLENGE_S", fields)

# ---- Opcode dispatch -----------------------------------------------------

opcode_handlers = {
    "AUTH_LOGON_CHALLENGE_C": handle_AUTH_LOGON_CHALLENGE_C,
    "AUTH_LOGON_PROOF_C": handle_AUTH_LOGON_PROOF_C,
    "REALM_LIST_C": handle_REALM_LIST_C,
    "AUTH_RECONNECT_CHALLENGE_C": handle_AUTH_RECONNECT_CHALLENGE_C,
}
