#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import importlib
import socket
import signal
import threading
import traceback

from utils.Logger import Logger
from utils.ConfigLoader import ConfigLoader
from utils.OpcodeLoader import load_world_opcodes
from utils.PacketDump import PacketDump
from modules.crypto.ARC4Crypto import Arc4CryptoHandler
from modules.interpretation.EncryptedWorldStream import EncryptedWorldStream
from modules.interpretation.OpcodeResolver import OpcodeResolver
from modules.interpretation.PacketInterpreter import (
    DumpPolicy,
    DslDecoder,
    JsonNormalizer,
    PacketDumper,
    PacketInterpreter,
)
from modules.interpretation.parser import parse_plain_packets
from modules.interpretation.utils import dsl_decode


# ---- Configuration ------------------------------------------------------

config = ConfigLoader.load_config()
config["Logging"]["logging_levels"] = "Information, Success, Error"

program = config["program"]
version = config["version"]

mod = importlib.import_module(f"protocols.{program}.{version}.database.DatabaseConnection")
DatabaseConnection = getattr(mod, "DatabaseConnection")
DatabaseConnection.initialize()

HOST = config["worldserver"]["host"]
PORT = config["worldserver"]["port"]
running = True


# ---- Opcodes/handlers ---------------------------------------------------

WORLD_CLIENT_OPCODES, WORLD_SERVER_OPCODES, world_lookup = load_world_opcodes()
opcode_resolver = OpcodeResolver(WORLD_CLIENT_OPCODES, WORLD_SERVER_OPCODES, world_lookup)

try:
    AUTH_SESSION_OPCODE = world_lookup.WorldClientOpcodes.CMSG_AUTH_SESSION.value
except Exception:
    AUTH_SESSION_OPCODE = 0x00B2  # MoP fallback

AUTH_RESPONSE_OPCODE = EncryptedWorldStream.AUTH_RESPONSE_OPCODE

try:
    handlers_mod = importlib.import_module(
        f"protocols.{program}.{version}.handlers.WorldHandlers"
    )
    opcode_handlers = getattr(handlers_mod, "opcode_handlers", {})
    get_auth_challenge = getattr(handlers_mod, "get_auth_challenge", None)
    reset_handler_state = getattr(handlers_mod, "reset_state", None)
    Logger.info("[WorldServer] Loaded world opcode handlers")
except Exception:
    opcode_handlers = {}
    get_auth_challenge = None
    reset_handler_state = None
    Logger.warning("[WorldServer] No WorldHandlers found, raw fallback only")


# ---- Interpretation helpers --------------------------------------------

packet_dumper = PacketDump(f"protocols/{program}/{version}")
interpreter = PacketInterpreter(
    decoder=DslDecoder(),
    normalizer=JsonNormalizer(),
    policy=DumpPolicy(dump=False, update=False),
    dumper=PacketDumper(packet_dumper),
)


# ---- Constants ----------------------------------------------------------

HANDSHAKE_SERVER = b"0\x00WORLD OF WARCRAFT CONNECTION - SERVER TO CLIENT\x00"
HANDSHAKE_CLIENT = b"0\x00WORLD OF WARCRAFT CONNECTION - CLIENT TO SERVER\x00"


# ---- Signal handling ----------------------------------------------------

def sigint(sig, frame):
    """Gracefully stop worldserver on Ctrl+C."""
    global running
    Logger.info("Shutting down WorldServer (Ctrl+C)…")
    running = False


# ---- Utility helpers ----------------------------------------------------

def safe_decode(direction: str, name: str, raw_header: bytes, payload: bytes) -> None:
    """Decode DSL packets via interpretation without crashing handlers."""
    try:
        interpreter.interpret(name, raw_header, payload)
    except Exception as exc:
        Logger.error(f"[{direction}] decode failed for {name}: {exc}")
        Logger.error(traceback.format_exc())


def parse_client_packets(data: bytes, encrypted: bool, stream: EncryptedWorldStream, buffer: bytearray, crypto: Arc4CryptoHandler):
    """Parse incoming client data based on encryption state."""
    if not encrypted:
        return parse_plain_packets(data, "C")

    buffer.extend(data)
    return stream.feed(buffer, crypto=crypto, direction="C")


def build_encrypted_response(packets, crypto: Arc4CryptoHandler) -> bytes:
    """Encrypt only the headers for server responses."""
    out = bytearray()

    for raw_header, h, payload in packets:
        if h.cmd < 0:
            out.extend(raw_header)
            out.extend(payload)
            continue

        size_field = len(payload)
        if h.cmd == AUTH_RESPONSE_OPCODE:
            size_field += 4

        packed = crypto.pack_data(h.cmd, size_field)
        if packed is None:
            Logger.error("[WorldServer] Failed to pack world header")
            continue

        enc_header = crypto.encrypt_send(packed)
        out.extend(enc_header)
        out.extend(payload)

    return bytes(out)


def parse_server_packets(raw: bytes):
    """
    Parse server packets that already contain packed world headers (size<<13 | opcode).
    Keeps payloads plaintext; used for logging/DSL decode before header encryption.
    """
    buf = bytearray(raw)
    packets = []

    while len(buf) >= 4:
        header = bytes(buf[:4])
        del buf[:4]

        hdr = Arc4CryptoHandler().unpack_data(header)
        size = hdr.size
        cmd = hdr.cmd

        if len(buf) < size:
            break

        payload = bytes(buf[:size])
        del buf[:size]

        class Header:
            pass

        h = Header()
        h.size = size
        h.cmd = cmd
        h.hex = f"0x{cmd:04X}"
        h.header_raw = header

        packets.append((header, h, payload))

    return packets


# ---- Client session handler ---------------------------------------------

def handle_client(sock: socket.socket, addr: tuple[str, int]) -> None:
    """Handle a single world client connection."""
    Logger.info(f"[WorldServer] New connection from {addr}")

    if reset_handler_state:
        try:
            reset_handler_state()
        except Exception as exc:
            Logger.error(f"[WorldServer] Failed to reset handler state: {exc}")

    crypto = Arc4CryptoHandler()
    stream = EncryptedWorldStream()
    encrypted = False
    buffer = bytearray()
    auth_challenge_sent = False

    try:
        sock.sendall(HANDSHAKE_SERVER)
        Logger.success(f"[WorldServer] → client HANDSHAKE ({len(HANDSHAKE_SERVER)} bytes)")
    except Exception as exc:
        Logger.error(f"[WorldServer] Failed to send handshake: {exc}")
        sock.close()
        return

    try:
        while running:
            data = sock.recv(4096)
            if not data:
                Logger.info(f"[WorldServer] {addr}: disconnected")
                break

            packets = parse_client_packets(data, encrypted, stream, buffer, crypto)

            for raw_header, h, payload in packets:
                opcode_int = h.cmd

                if opcode_int < 0:
                    Logger.info(f"[WorldServer] {addr}: handshake/raw payload ({h.size} bytes)")
                    if (not encrypted) and (not auth_challenge_sent) and get_auth_challenge:
                        try:
                            challenge = get_auth_challenge()
                            if challenge:
                                Logger.info("[WorldServer] Sending SMSG_AUTH_CHALLENGE after handshake")
                                sock.sendall(challenge)
                                auth_challenge_sent = True
                            else:
                                Logger.warning("[WorldServer] No SMSG_AUTH_CHALLENGE raw available")
                        except Exception as exc:
                            Logger.error(f"[WorldServer] Failed to send auth challenge: {exc}")
                    continue

                name = opcode_resolver.decode_opcode(opcode_int, "C")
                Logger.info(f"[WorldServer] C→S {name} ({h.hex}) size={len(payload)}")
                Logger.info(f"[WorldServer] Raw: {(raw_header + payload).hex().upper()}")

                # ARC4 init on first AUTH_SESSION
                if not encrypted and opcode_int == AUTH_SESSION_OPCODE:
                    decoded_auth = dsl_decode("CMSG_AUTH_SESSION", payload, silent=False)
                    account = (
                        decoded_auth.get("account")
                        or decoded_auth.get("username")
                        or decoded_auth.get("user")
                        or decoded_auth.get("I")
                    )

                    if not account:
                        Logger.error("[WorldServer] AUTH_SESSION missing account")
                        break

                    acc = DatabaseConnection.get_user_by_username(account.upper())
                    key = acc.session_key if acc else None

                    if isinstance(key, (bytes, bytearray)):
                        key = key.hex()

                    if not isinstance(key, str):
                        Logger.error("[WorldServer] No session key found for user")
                        break

                    crypto.init_arc4(key)
                    encrypted = True
                    Logger.success(f"[WorldServer] ARC4 initialized for {account}")

                safe_decode("Client", name, raw_header, payload)

                handler = opcode_handlers.get(name)
                if handler is None:
                    Logger.warning(f"[WorldServer] No handler for {name}")
                    continue

                try:
                    err, response = handler(sock, opcode_int, payload)
                except Exception as exc:
                    Logger.error(f"[WorldServer] Handler crash for {name}: {exc}")
                    Logger.error(traceback.format_exc())
                    break

                if err != 0:
                    Logger.warning(f"[WorldServer] Handler error for {name}, closing connection")
                    break

                if not response:
                    Logger.info(f"[WorldServer] Handler returned no response for {name}")
                    continue

                response_packets = parse_server_packets(response)

                for resp_header, resp_h, resp_payload in response_packets:
                    if resp_h.cmd < 0:
                        continue
                    server_name = opcode_resolver.decode_opcode(resp_h.cmd, "S")
                    Logger.info(f"[WorldServer] S→C {server_name} ({resp_h.hex}) size={len(resp_payload)}")
                    Logger.info(f"[WorldServer] Raw: {(resp_header + resp_payload).hex().upper()}")
                    safe_decode("Server", server_name, resp_header, resp_payload)

                out = response if not encrypted else build_encrypted_response(response_packets, crypto)

                try:
                    sock.sendall(out)
                except Exception as exc:
                    Logger.error(f"[WorldServer] Failed to send response: {exc}")
                    break

            else:
                continue

            break

    except Exception as exc:
        Logger.error(f"[WorldServer] {addr}: unexpected error {exc}")
        Logger.error(traceback.format_exc())
    finally:
        try:
            sock.close()
        except Exception:
            pass
        Logger.info(f"[WorldServer] Closed connection from {addr}")


# ---- Server loop --------------------------------------------------------

def start_server() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(5)

    Logger.info(f"[WorldServer] Listening on {HOST}:{PORT}")

    while running:
        try:
            srv.settimeout(1.0)
            sock, addr = srv.accept()
            threading.Thread(target=handle_client, args=(sock, addr), daemon=True).start()
        except socket.timeout:
            continue
        except Exception as exc:
            Logger.error(f"[WorldServer] Server error: {exc}")
            Logger.error(traceback.format_exc())

    Logger.info("WorldServer stopping…")
    srv.close()


# ---- Main entry ---------------------------------------------------------

if __name__ == "__main__":
    signal.signal(signal.SIGINT, sigint)

    Logger.info(
        f"{config['friendly_name']} "
        f"({config['program']}:{config['version']}) WorldServer (Minimal Mode)"
    )

    start_server()
