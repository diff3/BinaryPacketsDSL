from utils.Logger import Logger
from utils.ConfigLoader import ConfigLoader
from utils.OpcodeLoader import load_world_opcodes
from modules.crypto.ARC4Crypto import Arc4CryptoHandler

import socket
import threading
import importlib

# SessionManager (från auth-proxy)
from modules.crypto.SessionManager import SessionManager

# DSL imports
from modules.Processor import load_case
from modules.NodeTreeParser import NodeTreeParser
from modules.DecoderHandler import DecoderHandler
from modules.Session import get_session


cfg = ConfigLoader.load_config()
cfg["Logging"]["logging_levels"] = "Information, Success, Script, Error"


# ---- Load auth-db for fallback -----------------------------------------
_db_mod = importlib.import_module(
    f"protocols.{cfg['program']}.{cfg['version']}.database.DatabaseConnection"
)
DatabaseConnection = getattr(_db_mod, "DatabaseConnection")

try:
    DatabaseConnection.initialize()
except Exception as e:
    Logger.error(f"[WorldProxy] Failed to initialize auth-db: {e}")


# ---- DSL decode helper --------------------------------------------------

def dsl_decode(def_name, payload, silent=False):
    try:
        cfg = ConfigLoader.load_config()
        program = cfg["program"]
        version = cfg["version"]

        case_name, lines, _, expected = load_case(program, version, def_name)
        session = get_session()
        session.reset()

        NodeTreeParser.parse((case_name, lines, payload, expected))
        return DecoderHandler.decode((case_name, lines, payload, expected))
    except Exception as e:
        if not silent:
            Logger.error(f"[DSL] decode {def_name} failed: {e}")
        return {}


# ========================================================================
# WORLD PROXY
# ========================================================================

class WorldProxy:
    """
    Minimal MoP world proxy som korrekt tunnelar handskaken,
    fångar CMSG_AUTH_SESSION och initierar ARC4.
    """

    HANDSHAKE = b"WORLD OF WARCRAFT CONNECTION"

    def __init__(self, listen_host, listen_port, world_host, world_port):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.world_host = world_host
        self.world_port = world_port

        self.client_opcodes, self.server_opcodes, lookup = load_world_opcodes()
        self.world_lookup = lookup

        # Hitta AUTH_SESSION opcode
        try:
            self.AUTH_SESSION_OPCODE = self.world_lookup.WorldClientOpcodes.CMSG_AUTH_SESSION.value
        except Exception:
            self.AUTH_SESSION_OPCODE = 0x00B2  # fallback MoP

    # ---- opcode decode ---------------------------------------------------

    def decode_opcode(self, opcode: int, direction: str) -> str:
        if direction == "C":
            if self.client_opcodes and opcode in self.client_opcodes:
                return self.client_opcodes[opcode]
            try:
                return self.world_lookup.WorldOpcodes.getClientOpCodeName(opcode)
            except Exception:
                return f"UNKNOWN_CMSG_0x{opcode:04X}"
        else:
            if self.server_opcodes and opcode in self.server_opcodes:
                return self.server_opcodes[opcode]
            try:
                return self.world_lookup.WorldOpcodes.getServerOpCodeName(opcode)
            except Exception:
                return f"UNKNOWN_SMSG_0x{opcode:04X}"

    # ---- start -----------------------------------------------------------

    def start(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.listen_host, self.listen_port))
        s.listen(5)

        Logger.info(
            f"[WorldProxy] Listening on {self.listen_host}:{self.listen_port} "
            f"→ {self.world_host}:{self.world_port}"
        )

        while True:
            client_sock, addr = s.accept()
            Logger.success(f"[WorldProxy] Client connected from {addr}")

            threading.Thread(
                target=self.handle_client,
                args=(client_sock,),
                daemon=True,
            ).start()

    # ---- handle ----------------------------------------------------------

    def handle_client(self, client_sock):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            server_sock.connect((self.world_host, self.world_port))
        except Exception as e:
            Logger.error(f"[WorldProxy] Failed to connect to worldserver: {e}")
            client_sock.close()
            return

        crypto = Arc4CryptoHandler()
        state = {"encrypted": False}

        threading.Thread(
            target=self.forward_c2s,
            args=(client_sock, server_sock, crypto, state),
            daemon=True,
        ).start()

        self.forward_s2c(server_sock, client_sock, crypto, state)

        client_sock.close()
        server_sock.close()
        Logger.info("[WorldProxy] Connection closed")

    # ---- ARC4 init -------------------------------------------------------

    def init_arc4_from_session_manager(self, client_ip, crypto):
        sm = SessionManager()

        if hasattr(sm, "get_session"):
            info = sm.get_session(client_ip)
            if not info:
                return False
            username = info.get("username")
            session_key = info.get("session_key")
        else:
            username = sm.get_username(client_ip) if hasattr(sm, "get_username") else None
            session_key = sm.get_session_key(client_ip) if hasattr(sm, "get_session_key") else None

        if not session_key:
            return False

        if isinstance(session_key, (bytes, bytearray)):
            session_key = session_key.hex()

        Logger.success(f"[WorldProxy] ARC4 init from SessionManager ({username})")
        crypto.init_arc4(session_key)
        return True

    def init_arc4_from_auth_payload(self, crypto, payload):
        try:
            base_len = 26
            off = base_len
            end = payload.find(b"\x00", off)
            if end == -1:
                return False

            username = payload[off:end].decode("utf-8", errors="ignore")

            acc = DatabaseConnection.get_user_by_username(username.upper())
            if not acc or not getattr(acc, "session_key", None):
                return False

            sk = acc.session_key
            if isinstance(sk, (bytes, bytearray)):
                sk = sk.hex()

            Logger.success("[WorldProxy] ARC4 init via fallback DB")
            crypto.init_arc4(sk)
            return True

        except Exception:
            return False

    # ---- simplified packet split ----------------------------------------

    def parse_multi_header_payloads(self, raw_data, encrypted):
        if encrypted:
            return [(None, None, raw_data)]

        out = []
        while raw_data:
            if len(raw_data) < 4:
                out.append((None, None, raw_data))
                break

            size = int.from_bytes(raw_data[:2], "little")
            cmd = int.from_bytes(raw_data[2:4], "little")
            payload = raw_data[4:4 + size]

            class H: pass
            h = H()
            h.size = size
            h.cmd = cmd

            out.append((raw_data[:4], h, payload))
            raw_data = raw_data[4 + size:]

        return out

    # ---- S→C -------------------------------------------------------------

    def forward_s2c(self, server, client, crypto, state):
        try:
            while True:
                data = server.recv(4096)
                if not data:
                    break

                # ---- HANDSHAKE: passthrough only ----
                if data.startswith(self.HANDSHAKE):
                    Logger.info("[WorldProxy S→C] Handshake")
                    client.sendall(data)
                    continue

                if not state["encrypted"]:
                    headers = self.parse_multi_header_payloads(data, False)
                    for _, h, _ in headers:
                        if h:
                            name = self.decode_opcode(h.cmd, "S")
                            Logger.info(f"[WorldProxy S→C] {name} (0x{h.cmd:04X}), size={h.size}")

                client.sendall(data)

        except Exception as e:
            Logger.error(f"[WorldProxy S→C] {e}")

    # ---- C→S -------------------------------------------------------------

    def forward_c2s(self, client, server, crypto, state):
        try:
            while True:
                data = client.recv(4096)
                if not data:
                    break

                # ---- HANDSHAKE: passthrough only ----
                if data.startswith(self.HANDSHAKE):
                    Logger.info("[WorldProxy C→S] Handshake")
                    server.sendall(data)
                    continue

                headers = self.parse_multi_header_payloads(data, state["encrypted"])

                # ---- ARC4 INIT (only if not encrypted yet) ----
                if not state["encrypted"]:
                    for _, h, payload in headers:
                        if not h:
                            continue

                        if h.cmd == self.AUTH_SESSION_OPCODE:
                            Logger.success("[WorldProxy] CMSG_AUTH_SESSION detected")

                            client_ip, _ = client.getpeername()

                            # 1) SessionManager
                            if self.init_arc4_from_session_manager(client_ip, crypto):
                                state["encrypted"] = True
                                break

                            # 2) DSL decoding
                            decoded = dsl_decode("CMSG_AUTH_SESSION", payload, silent=True)
                            username = decoded.get("user")

                            if username:
                                Logger.info(f"[WorldProxy] DSL username '{username}'")
                                acc = DatabaseConnection.get_user_by_username(username.upper())
                                if acc and getattr(acc, "session_key", None):
                                    sk = acc.session_key
                                    if isinstance(sk, (bytes, bytearray)):
                                        sk = sk.hex()
                                    crypto.init_arc4(sk)
                                    Logger.success("[WorldProxy] ARC4 init via DSL + DB")
                                    state["encrypted"] = True
                                    break

                            # 3) fallback
                            if self.init_arc4_from_auth_payload(crypto, payload):
                                state["encrypted"] = True
                                break

                            Logger.error("[WorldProxy] Could NOT initialize ARC4 — continue anyway.")

                server.sendall(data)

        except Exception as e:
            Logger.error(f"[WorldProxy C→S] {e}")