#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Minimal world server för debug:
  - Lyssnar på world-porten
  - Dekodar world-paket via DSL-runtime (watch när möjligt)
  - Handler-stöd (protocols/<program>/<version>/handlers/WorldHandlers.py)
  - Rå fallback: kan svara med sparade raw_data för ofärdiga paket
  - Initierar ARC4 vid CMSG_AUTH_SESSION via DB-session_key (samma som world_proxy)
"""

import importlib
import json
import socket
import signal
import threading
import traceback

from modules.DslRuntime import DslRuntime
from utils.ConfigLoader import ConfigLoader
from utils.Logger import Logger
from utils.OpcodeLoader import load_world_opcodes
from modules.crypto.ARC4Crypto import Arc4CryptoHandler
from protocols.mop.v18414.database.DatabaseConnection import DatabaseConnection

# Map client opcodes → server response opcode to send as raw_data.
RAW_RESPONSE_FALLBACKS: dict[str, str] = {}

config = ConfigLoader.load_config()
config["Logging"]["logging_levels"] = "Information, Success, Error"

HOST = config["worldserver"]["host"]
PORT = config["worldserver"]["port"]

runtime: DslRuntime | None = None
HANDSHAKE_SERVER = b"0\x00WORLD OF WARCRAFT CONNECTION - SERVER TO CLIENT\x00"
HANDSHAKE_CLIENT = b"0\x00WORLD OF WARCRAFT CONNECTION - CLIENT TO SERVER\x00"

WORLD_CLIENT_OPCODES, WORLD_SERVER_OPCODES, _world_lookup = load_world_opcodes()

try:
    handlers_mod = importlib.import_module(
        f"protocols.{config['program']}.{config['version']}.handlers.WorldHandlers"
    )
    opcode_handlers = getattr(handlers_mod, "opcode_handlers", {})
    Logger.info("[WorldServer] Loaded world opcode handlers")
except Exception:
    opcode_handlers = {}
    Logger.warning("[WorldServer] No WorldHandlers found, raw fallback only")


# ---- Helpers -----------------------------------------------------------

def recv_exact(sock: socket.socket, length: int) -> bytes | None:
    buf = b""
    while len(buf) < length:
        chunk = sock.recv(length - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def parse_header(header: bytes) -> tuple[int | None, int | None, str]:
    if len(header) < 4:
        return None, None, "0x????"
    size = int.from_bytes(header[0:2], "little")
    opcode = int.from_bytes(header[2:4], "little")
    return size, opcode, f"0x{opcode:04X}"


def opcode_name(direction: str, opcode: int) -> str | None:
    return WORLD_CLIENT_OPCODES.get(opcode) if direction == "C" else WORLD_SERVER_OPCODES.get(opcode)


def load_saved_raw(opcode: str) -> bytes | None:
    base_proto = f"protocols/{config['program']}/{config['version']}/debug/{opcode}.json"
    base_cap = f"misc/captures/debug/{opcode}.json"

    for path in (base_proto, base_cap):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            continue
        except Exception as exc:
            Logger.error(f"[WorldServer] Failed to read raw for {opcode} from {path}: {exc}")
            continue

        raw_hex = data.get("raw_data_hex")
        if raw_hex:
            try:
                return bytes.fromhex(raw_hex.replace(" ", ""))
            except Exception:
                Logger.error(f"[WorldServer] Invalid raw_data_hex in {path}")
                continue

        raw_header = data.get("raw_header_hex")
        payload = data.get("hex_compact") or data.get("hex_spaced")
        if raw_header and payload:
            try:
                header_bytes = bytes.fromhex(raw_header.replace(" ", ""))
                payload_bytes = bytes.fromhex(payload.replace(" ", ""))
                return header_bytes + payload_bytes
            except Exception:
                Logger.error(f"[WorldServer] Invalid hex fields in {path}")
                continue
    return None


def send_raw_response(sock: socket.socket, opcode: str) -> bool:
    raw = load_saved_raw(opcode)
    if not raw:
        Logger.warning(f"[WorldServer] No saved raw_data for {opcode}")
        return False
    try:
        Logger.success(f"[WorldServer] → client {opcode} ({len(raw)} bytes)")
        Logger.success(raw.hex().upper())
        sock.sendall(raw)
        Logger.success(f"[WorldServer] Sent saved raw packet for {opcode} ({len(raw)} bytes)")
        return True
    except Exception as exc:
        Logger.error(f"[WorldServer] Failed to send raw {opcode}: {exc}")
        return False


# ---- Client handling ---------------------------------------------------

def handle_client(sock: socket.socket, addr: tuple[str, int]) -> None:
    Logger.info(f"[WorldServer] New connection from {addr}")
    crypto = Arc4CryptoHandler()
    encrypted = False

    try:
        sock.sendall(HANDSHAKE_SERVER)
        Logger.success(f"[WorldServer] → client HANDSHAKE ({len(HANDSHAKE_SERVER)} bytes)")
        Logger.success(HANDSHAKE_SERVER.hex().upper())
    except Exception as exc:
        Logger.error(f"[WorldServer] Failed to send handshake: {exc}")
        return

    try:
        while True:
            try:
                peek = sock.recv(len(HANDSHAKE_CLIENT), socket.MSG_PEEK)
            except Exception:
                peek = b""

            if peek.startswith(HANDSHAKE_CLIENT):
                _ = recv_exact(sock, len(HANDSHAKE_CLIENT))
                Logger.info(f"[WorldServer] {addr}: received client HANDSHAKE")
                continue

            # ----- Header decode (plain vs encrypted) -----
            if not encrypted:
                header = recv_exact(sock, 4)
                if not header:
                    Logger.info(f"[WorldServer] {addr}: disconnected")
                    break
                size, opcode, hexop = parse_header(header)
                if size is None or opcode is None:
                    Logger.warning(f"[WorldServer] {addr}: invalid header {header.hex()}")
                    break
                payload_len = max(0, size - 4) if opcode == 0x01F6 else size
                payload = recv_exact(sock, payload_len) or b""
                raw_header = header
            else:
                enc_header = recv_exact(sock, 4)
                if not enc_header:
                    Logger.info(f"[WorldServer] {addr}: disconnected")
                    break
                dec_header = crypto.decrypt_recv(enc_header)
                hdr = crypto.unpack_data(dec_header)
                opcode = hdr.cmd
                hexop = f"0x{opcode:04X}"
                payload_len = max(0, hdr.size - 4) if opcode == 0x01F6 else hdr.size
                enc_payload = recv_exact(sock, payload_len) or b""
                payload = crypto.decrypt_recv(enc_payload)
                raw_header = dec_header

            name = opcode_name("C", opcode) or f"UNKNOWN_CMSG_{hexop}"

            Logger.info(f"[WorldServer] C→S {name} ({hexop}) size={payload_len}")
            Logger.info(f"[WorldServer] Raw: {(raw_header + payload).hex().upper()}")

            # Initiera ARC4 när CMSG_AUTH_SESSION dyker upp
            if not encrypted and name == "CMSG_AUTH_SESSION":
                try:
                    decoded = runtime.decode(name, payload, silent=True) or {}
                    username = decoded.get("user") or decoded.get("username")
                    if username:
                        acc = DatabaseConnection.get_user_by_username(username.upper())
                        K = acc.session_key if acc else None
                        if isinstance(K, (bytes, bytearray)):
                            K = K.hex()
                        if isinstance(K, str):
                            crypto.init_arc4(K)
                            encrypted = True
                            Logger.success(f"[WorldServer] ARC4 initialized for {username}")
                        else:
                            Logger.error("[WorldServer] No session key found for user")
                except Exception as exc:
                    Logger.error(f"[WorldServer] Failed to init ARC4: {exc}")

            try:
                runtime.decode(name, payload, silent=True)
            except Exception as exc:
                Logger.error(f"[WorldServer] DSL decode failed for {name}: {exc}")
                Logger.error(traceback.format_exc())

            handler = opcode_handlers.get(name)
            response = None
            err = 0

            if handler:
                try:
                    err, response = handler(sock, opcode, payload)
                except Exception as exc:
                    Logger.error(f"[WorldServer] Handler crash for {name}: {exc}")
                    Logger.error(traceback.format_exc())
                    err = 1

            if err != 0:
                Logger.warning(f"[WorldServer] Handler error for {name}, closing connection")
                break

            sent = False
            if response:
                try:
                    if encrypted:
                        opcode_int = int.from_bytes(response[2:4], "little")
                        payload_only = response[4:]
                        size = len(payload_only)
                        if opcode_int == 0x01F6:  # MoP: size inkluderar header
                            size += 4
                        enc_header = crypto.encrypt_send(crypto.pack_data(opcode_int, size))
                        enc_payload = crypto.encrypt_send(payload_only)
                        out = enc_header + enc_payload
                    else:
                        out = response

                    Logger.success(f"[WorldServer] → client ({len(out)} bytes)")
                    Logger.success(out.hex().upper())
                    sock.sendall(out)
                    sent = True
                    Logger.info(f"[WorldServer] Sent handler response ({len(response)} bytes)")
                except Exception as exc:
                    Logger.error(f"[WorldServer] Failed to send handler response: {exc}")
                    break

            # Raw fallback endast i okrypterat läge
            if not sent and (not encrypted) and name in RAW_RESPONSE_FALLBACKS:
                target = RAW_RESPONSE_FALLBACKS[name]
                sent = send_raw_response(sock, target)
                if not sent:
                    Logger.warning(f"[WorldServer] Missing raw fallback for {target}")

    except Exception as exc:
        Logger.error(f"[WorldServer] {addr}: unexpected error {exc}")
        Logger.error(traceback.format_exc())
    finally:
        try:
            sock.close()
        except Exception:
            pass
        Logger.info(f"[WorldServer] Closed connection from {addr}")


# ---- Server loop ------------------------------------------------------

def start_server() -> None:
    ensure_runtime()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(5)
    Logger.info(f"[WorldServer] Listening on {HOST}:{PORT}")
    while True:
        sock, addr = srv.accept()
        threading.Thread(target=handle_client, args=(sock, addr), daemon=True).start()


# ---- Main --------------------------------------------------------------

def _init_runtime() -> DslRuntime:
    try:
        rt = DslRuntime(config["program"], config["version"], watch=True)
        rt.load_all()
        Logger.info("[WorldServer] DSL runtime ready (watching defs)")
        return rt
    except Exception as exc:
        Logger.error(f"[WorldServer] Failed to init runtime with watch: {exc}")
        rt = DslRuntime(config["program"], config["version"], watch=False)
        rt.load_all()
        return rt


def ensure_runtime() -> None:
    global runtime
    if runtime is None:
        runtime = _init_runtime()


def sigint(sig, frame):
    Logger.info("Shutting down WorldServer (Ctrl+C)…")
    raise SystemExit


if __name__ == "__main__":
    signal.signal(signal.SIGINT, sigint)
    ensure_runtime()
    Logger.info(
        f"{config['friendly_name']} "
        f"({config['program']}:{config['version']}) WorldServer (Minimal Mode)"
    )
    start_server()
