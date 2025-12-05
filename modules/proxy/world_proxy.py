#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import threading
import importlib
import json

from utils.Logger import Logger
from utils.ConfigLoader import ConfigLoader
from utils.OpcodeLoader import load_world_opcodes
from modules.crypto.ARC4Crypto import Arc4CryptoHandler
from modules.DslRuntime import DslRuntime

from utils.PacketDump import PacketDump, dump_capture


cfg = ConfigLoader.load_config()
cfg["Logging"]["logging_levels"] = "Information, Success, Script, Error"

program = cfg['program']
version = cfg['version']

mod = importlib.import_module(f"protocols.{program}.{version}.database.DatabaseConnection")
DatabaseConnection = getattr(mod, "DatabaseConnection")


# ----------------------------------------------------------------------
# JSON helper – gör DSL-output loggvänlig
# ----------------------------------------------------------------------

def to_safe_json(value, key=None):
    """
    Convert DSL-returned structures to JSON-safe types.
    - GUID-int → "0xDEADBEEF..."
    - bytes/bytearray → hexstr
    """
    if isinstance(value, int):
        if key and ("guid" in key.lower()):
            hexstr = hex(value)[2:]
            if len(hexstr) % 2 == 1:
                hexstr = "0" + hexstr
            return "0x" + hexstr.upper()
        return value

    if isinstance(value, bytearray):
        return value.hex()

    if isinstance(value, bytes):
        return value.hex()

    if isinstance(value, dict):
        return {k: to_safe_json(v, k) for k, v in value.items()}

    if isinstance(value, (list, tuple)):
        return [to_safe_json(v, key) for v in value]

    return value


_dsl_runtime = None


def _get_dsl_runtime():
    """Lazy init of DSL runtime with cached ASTs + watchdog reload."""
    global _dsl_runtime
    if _dsl_runtime is None:
        cfg_local = ConfigLoader.load_config()
        program_local = cfg_local["program"]
        version_local = cfg_local["version"]
        try:
            rt = DslRuntime(program_local, version_local, watch=True)
            rt.load_all()
            _dsl_runtime = rt
            Logger.info(f"[DSL] Runtime ready (watching {program_local}/{version_local})")
        except Exception as e:
            Logger.error(f"[DSL] Failed to init runtime (watch disabled): {e}")
            rt = DslRuntime(program_local, version_local, watch=False)
            rt.load_all()
            _dsl_runtime = rt
    return _dsl_runtime


def dsl_decode(def_name, payload, silent=False):
    """
    Safe DSL decoder; expect payload WITHOUT world header (size/opcode).
    Returns {} on failure.
    """
    try:
        rt = _get_dsl_runtime()
        return rt.decode(def_name, payload, silent=silent)
    except Exception as e:
        if not silent:
            Logger.error(f"[DSL] decode {def_name} failed: {e}")
        return {}


# ---- Plain world header parser -----------------------------------------

def parse_header(header: bytes):
    """
    WoW world header: ALWAYS 4 bytes
        uint16 size (little-endian)
        uint16 opcode (little-endian)
    """
    if len(header) < 4:
        return None, None, None
    size   = int.from_bytes(header[0:2], "little")
    opcode = int.from_bytes(header[2:4], "little")
    return size, opcode, f"0x{opcode:04X}"


# ========================================================================
# WORLD PROXY (hybrid: gammal före AUTH, stream efter AUTH)
# ========================================================================

class WorldProxy:
    """
    Hybrid-proxy:
      - Före CMSG_AUTH_SESSION:
          * Batch-parsning per recv()-chunk (som gamla proxyn).
      - Efter CMSG_AUTH_SESSION:
          * Riktig stream-parser med ARC4-header-decrypt
            och pending header per riktning.
      - Kan dumpa world-paket (bin/json/debug) via PacketDump.
    """

    HANDSHAKE = b"0\x00WORLD OF WARCRAFT CONNECTION"

    def __init__(self, listen_host, listen_port, world_host, world_port, dump=False, update=False):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.world_host = world_host
        self.world_port = world_port

        self.dump = dump
        self.update = update
        self.ignored = set(cfg.get("IgnoredWorldOpcodes", []))

        # WORLD_CLIENT_OPCODES, WORLD_SERVER_OPCODES, lookup-funktion
        self.client_opcodes, self.server_opcodes, self.world_lookup = load_world_opcodes()

        try:
            self.AUTH_SESSION_OPCODE = (
                self.world_lookup.WorldClientOpcodes.CMSG_AUTH_SESSION.value
            )
        except Exception:
            self.AUTH_SESSION_OPCODE = 0x00B2  # MoP fallback

        # Pending headers – för att undvika RC4-desync i stream-läge
        self._pending_headers = {
            "C": None,   # C → S
            "S": None,   # S → C
        }

        # Packet dumper – samma layout som AuthProxy
        self.dumper = PacketDump(f"protocols/{cfg['program']}/{cfg['version']}")

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
        DatabaseConnection.initialize()

        while True:
            client_sock, addr = s.accept()
            Logger.success(f"[WorldProxy] Client connected from {addr}")

            threading.Thread(
                target=self.handle_client,
                args=(client_sock,),
                daemon=True,
            ).start()

    # ---- per connection --------------------------------------------------

    def handle_client(self, client_sock):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            server_sock.connect((self.world_host, self.world_port))
        except Exception as e:
            Logger.error(f"[WorldProxy] Failed to connect to worldserver: {e}")
            client_sock.close()
            return

        crypto = Arc4CryptoHandler()

        session = {
            "username": None,
            "key": None,
            "initialized": False,
        }

        # Delad state: före/efter AUTH
        state = {"encrypted": False}

        # Buffertar används endast efter AUTH (stream-läge)
        buffer_s2c = bytearray()
        buffer_c2s = bytearray()

        threading.Thread(
            target=self.forward_c2s,
            args=(client_sock, server_sock, crypto, session, state, buffer_c2s),
            daemon=True,
        ).start()

        self.forward_s2c(server_sock, client_sock, crypto, session, state, buffer_s2c)

        client_sock.close()
        server_sock.close()
        Logger.info("[WorldProxy] Connection closed")

    # ============================================================
    # Plain / pre-AUTH parser (gammal stil)
    # ============================================================

    def parse_plain_packets(self, raw_data: bytes, direction: str):
        """
        Motsvarar gamla parse_multi_header_payloads i okrypterat läge.
        - Ingen persistent buffert.
        - Tillåter att payload är kortare än size.
        - Returnerar lista (orig_header, header_obj, payload).
        """
        packets = []

        while raw_data:
            if len(raw_data) < 4:
                break

            header = raw_data[:4]
            orig = header

            # Handshake specialfall – hela buffern som ett "paket"
            if b"WORLD OF WARCRAFT" in raw_data:
                class H:
                    pass
                h = H()
                h.size = len(raw_data)
                h.cmd = -1
                h.hex = "HANDSHAKE"
                h.header_raw = header
                packets.append((orig, h, raw_data))
                break

            size, cmd, hexop = parse_header(header)
            if size is None:
                break

            # -----------------------------------------------------------
            # SPECIALFALL (MoP): SMSG_AUTH_RESPONSE (opcode 0x01F6)
            # innehåller header i storleken → payload = size - 4 bytes
            # -----------------------------------------------------------
            adj_size = size
            if cmd == 0x01F6:
                adj_size = max(0, size - 4)

            payload = raw_data[4:4 + adj_size]  # kan vara kort
            raw_data = raw_data[4 + adj_size:]

            class H:
                pass

            h = H()
            h.size = adj_size
            h.cmd = cmd
            h.hex = hexop
            h.header_raw = header

            packets.append((orig, h, payload))

        return packets

    # ============================================================
    # Encrypted / post-AUTH stream parser
    # ============================================================

    def feed_buffer(self, raw_buf: bytearray, crypto, encrypted: bool, direction: str):
        """
        Används ENDAST efter att state['encrypted'] blivit True.
        Stream-parser:
        - 4 bytes header per gång
        - header dekrypteras med ARC4
        - header packad som (size << 13) | (opcode & 0x1FFF)
        - payload läses när tillräckligt många bytes finns
        """
        packets = []

        if not encrypted:
            return packets

        while True:
            pending = self._pending_headers[direction]

            # Ingen pending header? Försök läsa en ny.
            if pending is None:
                if len(raw_buf) < 4:
                    break

                enc_header = raw_buf[:4]
                del raw_buf[:4]

                if direction == "C":
                    dec_header = crypto.decrypt_recv(enc_header)
                else:
                    # följer existerande design: S→C använder encrypt_send-streamen
                    dec_header = crypto.encrypt_send(enc_header)

                h_dec = crypto.unpack_data(dec_header)

                size = h_dec.size
                cmd = h_dec.cmd

                # -----------------------------------------------------------
                # SPECIALFALL (MoP): SMSG_AUTH_RESPONSE inkluderar headern
                # Opcode 0x01F6
                # -----------------------------------------------------------
                if cmd == 0x01F6:
                    size = max(0, size - 4)

                pending = {
                    "size": size,
                    "opcode": cmd,
                    "hex": f"0x{cmd:04X}",
                    "header_raw": dec_header,
                }
                self._pending_headers[direction] = pending

            size = pending["size"]

            if len(raw_buf) < size:
                break  # väntar på mer payload

            payload = raw_buf[:size]
            del raw_buf[:size]

            class H:
                pass

            h = H()
            h.size = pending["size"]
            h.cmd = pending["opcode"]
            h.hex = pending["hex"]
            h.header_raw = pending["header_raw"]

            packets.append((h.header_raw, h, payload))
            self._pending_headers[direction] = None

        return packets

    # ============================================================
    # DSL + dump helper
    # ============================================================

    def handle_dsl_and_dump(self, direction: str, name: str, raw_header: bytes, payload: bytes):
        """
        DSL-decode + dump:
        --dump   → captures/
        --update → protocols/
        inget    → bara logga JSON
        """

        # Full rådata (för logg)
        raw_full = raw_header + payload

        # Decode payload via DSL
        decoded = dsl_decode(name, payload, silent=True)
        safe = to_safe_json(decoded if decoded else {})

        # Logga alltid DSL-resultat (även tomt) för transparens
        try:
            Logger.success(f"[DSL] {name}\n{json.dumps(safe, indent=2)}")
        except Exception:
            Logger.warning(f"[DSL] {name} (result not serializable)")

        # -------------------------------------------------
        # UPDATE-LÄGE (skriver till protocols/) — körs även om dump är aktiv.
        if self.update:
            try:
                bin_p, json_p, dbg_p = self.dumper.dump_fixed(
                    name,
                    raw_header,     # rätt
                    payload,        # rätt
                    safe            # rätt
                )
                Logger.success(f"[UPDATE] {name} → {bin_p}")
            except Exception as e:
                Logger.error(f"[UPDATE ERROR] {name}: {e}")

        # DUMP-LÄGE (skriver till captures/) — körs oberoende av update.
        if self.dump:
            try:
                bin_p, json_p, dbg_p = dump_capture(
                    name,
                    raw_header,     # rätt
                    payload,        # rätt
                    safe            # rätt
                )
                Logger.success(f"[DUMP] {name} → {bin_p}")
            except Exception as e:
                Logger.error(f"[DUMP ERROR] {name}: {e}")

        # Om varken update eller dump är aktiva, fortsätt till logg nedan.

        # if decoded:
            #Logger.success(json.dumps(safe, indent=4))

    # ---- S→C -------------------------------------------------------------

    def forward_s2c(self, server, client, crypto, session, state, buffer):
        try:
            while True:
                data = server.recv(4096)
                print("forward_s2c")
                print(data)
                if not data:
                    break

                # Handshake (okrypterad)
                if data.startswith(self.HANDSHAKE):
                    Logger.info("[WorldProxy S→C] HANDSHAKE")
                    client.sendall(data)
                    continue

                if not state["encrypted"]:
                    # Pre-AUTH: gammal stil, per recv-chunk
                    packets = self.parse_plain_packets(data, "S")
                else:
                    # Post-AUTH: stream-läge med buffer
                    buffer.extend(data)
                    packets = self.feed_buffer(buffer, crypto, state["encrypted"], "S")

                for raw_header, h, payload in packets:
                    name = self.decode_opcode(h.cmd, "S")
                    if h.cmd < 0:
                        Logger.success(f"[WorldProxy S→C] RAW ({h.hex}), size={h.size}")
                        Logger.success(f"\n{json.dumps(payload, indent=4)}")
                        continue

                    if name in self.ignored:
                        # Hoppa över logg, DSL-dump mm – men FORWADA paketet som vanligt
                        continue

                    Logger.success(f"[WorldProxy S→C] {name} ({h.hex}), size={h.size}")

                    # DSL + dump (full world-paket)
                    self.handle_dsl_and_dump("S", name, raw_header, payload)

                # Transparent forward
                client.sendall(data)

        except Exception as e:
            Logger.success(f"[WorldProxy S→C] RAW ({h.hex}), size={h.size}")
            Logger.success(f"\n{payload}")
           # Logger.error(f"[WorldProxy S→C] {e}")

    # ---- C→S -------------------------------------------------------------

    def forward_c2s(self, client, server, crypto, session, state, buffer):
        try:
            while True:
                data = client.recv(4096)
                print("forward_c2s")
                print(data)
                if not data:
                    break

                # Handshake
                if data.startswith(self.HANDSHAKE):
                    Logger.info("[WorldProxy C→S] HANDSHAKE")
                    server.sendall(data)
                    continue

                if not state["encrypted"]:
                    # Pre-AUTH: gammal stil, per recv-chunk
                    packets = self.parse_plain_packets(data, "C")
                else:
                    # Post-AUTH: stream-läge
                    buffer.extend(data)
                    packets = self.feed_buffer(buffer, crypto, state["encrypted"], "C")

                for raw_header, h, payload in packets:
                    if h.cmd < 0:
                        Logger.info(f"[WorldProxy C→S] RAW ({h.hex}), size={h.size}")
                        continue

                    name = self.decode_opcode(h.cmd, "C")
                    if name in self.ignored:
                        # Hoppa över logg, DSL-dump mm – men FORWADA paketet som vanligt
                        continue

                    Logger.info(f"[WorldProxy C→S] {name} ({h.hex}), size={h.size}, header raw: {raw_header.hex()}")

                    # DSL + dump (full world-paket)
                    self.handle_dsl_and_dump("C", name, raw_header, payload)

                    # ------------------------------
                    #    C M S G _ A U T H _ S E S S I O N
                    # ------------------------------
                    if not state["encrypted"] and h.cmd == self.AUTH_SESSION_OPCODE:
                        Logger.success("[WorldProxy] CMSG_AUTH_SESSION detected")

                        decoded_auth = dsl_decode("CMSG_AUTH_SESSION", payload, silent=True)
                        username = decoded_auth.get("user") or decoded_auth.get("username")

                        if username:
                            acc = DatabaseConnection.get_user_by_username(username.upper())
                            if acc and acc.session_key:
                                K = acc.session_key
                                if isinstance(K, (bytes, bytearray)):
                                    K = K.hex()

                                Logger.success("[WorldProxy] ARC4 init (via DSL + DB)")
                                crypto.init_arc4(K)
                                session["username"] = username
                                session["key"] = K
                                session["initialized"] = True
                                state["encrypted"] = True
                                continue

                        Logger.error("[WorldProxy] FAILED to init ARC4")

                # Transparent forward
                server.sendall(data)

        except Exception as e:
            Logger.error(f"[WorldProxy C→S] {e}")
