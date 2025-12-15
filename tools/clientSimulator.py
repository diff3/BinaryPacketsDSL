#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Minimal MoP 5.4.8 authentication + world test client.

Features:
  • DSL decoding (AUTH_LOGON_CHALLENGE_S, AUTH_LOGON_PROOF_S, REALM_LIST_S)
  • SRP6Client for SRP math
  • Realm selection and basic world connect (ARC4 + packed world headers)
  • config.yaml for all client parameters
"""

import getpass
import hashlib
import json
import os
import socket
import struct
import time
from pathlib import Path

from utils.ConfigLoader import ConfigLoader
from utils.Logger import Logger

from modules.DecoderHandler import DecoderHandler
from modules.EncoderHandler import EncoderHandler
from modules.NodeTreeParser import NodeTreeParser
from modules.Processor import load_case
from modules.Session import get_session
from modules.crypto.ARC4Crypto import Arc4CryptoHandler
from modules.crypto.SRP6Client import SRP6Client, H
from modules.crypto.SRP6Crypto import SRP6Crypto
from protocols.mop.v18414.opcodes.WorldOpcodes import WorldClientOpcodes

from modules.crypto.SRP6Crypto import SRP6Crypto
import struct, os

def to_bytes(val):
    if isinstance(val, bytes):
        return val
    if isinstance(val, str):
        return bytes.fromhex(val)
    raise TypeError(f"Expected bytes or hexstr, got {type(val)}")

def _recv_exact(self, sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"socket closed while reading {n} bytes (got {len(buf)})")
        buf += chunk
    return bytes(buf)

def dsl_decode(def_name, payload, cfg=None):
    cfg = cfg or ConfigLoader.load_config()
    program = cfg["program"]
    version = cfg["version"]

    case_name, lines, _, expected, _ = load_case(program, version, def_name)

    session = get_session()
    session.reset()

    NodeTreeParser.parse((case_name, lines, payload, expected))
    # Run silent to avoid noisy logs when used from scripts
    return DecoderHandler.decode((case_name, lines, payload, expected), silent=True)


def load_raw(name: str, cfg) -> bytes | None:
    paths = [
        Path("protocols") / cfg["program"] / cfg["version"] / "debug" / f"{name}.json",
        Path("misc") / "captures" / "debug" / f"{name}.json",
    ]
    for path in paths:
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text())
            raw_hex = data.get("raw_data_hex")
            if raw_hex:
                return bytes.fromhex(raw_hex.replace(" ", ""))
        except Exception as exc:
            Logger.error(f"Failed to load raw {name} from {path}: {exc}")
    return None



def resolve_addon_data(cfg) -> bytes:
    """
    Prefer real addon data from config or captured packet payloads instead of a hardcoded blob.
    Priority:
      1) client.addon_data_hex in config (hex string)
      2) client.addon_data_path pointing to a binary file
      3) captured CMSG_AUTH_SESSION debug payload (addon_data field)
      4) fallback to empty bytes
    """
    client_cfg = cfg.get("client", {})

    addon_hex = client_cfg.get("addon_data_hex")
    if addon_hex:
        try:
            return bytes.fromhex(addon_hex.replace(" ", ""))
        except ValueError as exc:
            Logger.error(f"addon_data_hex invalid hex: {exc}")

    addon_path = client_cfg.get("addon_data_path")
    if addon_path:
        path_obj = Path(addon_path)
        if path_obj.exists():
            try:
                return path_obj.read_bytes()
            except Exception as exc:
                Logger.error(f"Failed reading addon_data_path {addon_path}: {exc}")

    raw = load_raw("CMSG_AUTH_SESSION", cfg)
    if raw:
        try:
            payload = raw[4:] if len(raw) > 4 else raw
            decoded = dsl_decode("CMSG_AUTH_SESSION", payload, cfg)
            addon_hex = decoded.get("addon_data")
            if addon_hex:
                return bytes.fromhex(addon_hex.replace(" ", ""))
        except Exception as exc:
            Logger.error(f"Failed to derive addon_data from capture: {exc}")

    return b""


def build_cmsg_auth_session(account: str,
                            server_seed: int,
                            session_key_hex: str,
                            build: int,
                            virtual_realm_id: int = 1,
                            addon_data: bytes = b"",
                            client_seed: int | None = None) -> bytes:
    """
    Builds full world packet (4-byte header + payload) for CMSG_AUTH_SESSION.
    NOTE: After CMSG_AUTH_SESSION, only headers are ARC4-encrypted (payload is plain).
    """



    srp = SRP6Crypto()

    # --- account (SkyFire ASCII upper) ---
    acct_up = srp.upper_skyfire(account)

    # --- clientSeed: ALWAYS exactly 4 bytes ---
    if client_seed is None:
        client_seed_bytes = os.urandom(4)
    elif isinstance(client_seed, int):
        client_seed_bytes = struct.pack("<I", client_seed)
    elif isinstance(client_seed, (bytes, bytearray)):
        client_seed_bytes = bytes(client_seed)
    else:
        raise TypeError("client_seed must be None, int, or bytes")

    assert len(client_seed_bytes) == 4

    # --- serverSeed: ALWAYS exactly 4 bytes ---
    if isinstance(server_seed, int):
        server_seed_bytes = struct.pack("<I", server_seed)
    elif isinstance(server_seed, (bytes, bytearray)):
        server_seed_bytes = bytes(server_seed)
    else:
        raise TypeError("server_seed must be int or bytes")

    assert len(server_seed_bytes) == 4

    # --- sessionKey: EXACTLY 40 bytes ---
    key_bytes = bytes.fromhex(session_key_hex)
    assert len(key_bytes) == 40

    # --- World auth digest (SkyFire exact) ---
    digest_bytes = srp.sha1(
        acct_up.encode("latin-1"),
        b"\x00\x00\x00\x00",
        client_seed_bytes,
        server_seed_bytes,
        key_bytes,
    )



    # Your DSL expects digest as "decimal-joined" bytes, so keep that format.
    digest_dec_join = "".join(str(b) for b in digest_bytes)

    # addons: encoder seems to accept hex string; make it from raw bytes
    # addons_hex = addon_data.hex() if addon_data else ""
    addons_hex = "30050000789c7593d16e83300c45f98d49fb8469ffd0762bea542456685f2793b860116264025afbf50b9ad4edc1e19173edc437d72f59966d1dddef20f66b633ac20507f4e17cc81edf1f17d301b2e3f696e0e84127b309c45e655b900665ea784ce0101c5e099d2dc8d300a326226fc9b77a0307a62f407ad4a7da81436f4134d4818bb0c549af7414adaa60417b0121681c4e9a8c8706c291db24abf13be87004134e40762f30e8cdcffb52f84afad16fd8cc6dcdec34f8ee0dcf3ea07cf02c1e9c22c9dd6decd4d9f3229aa31b9a17d52c0bea19c96772760bbe4fd31dfb20ecd202951cfc34a2d16f7408386c5c9c1492295c25159b1892548e56c5796c052caafcc8dcc7da3d4bfa920518619df08225588594187e7740ad8b34fd7c6b72d4aa135e59dad4a4f5ba11ba93350d58808716b57da9b947ddde7ab5adeac9e9cf1a317914955d986c1558e299ba039752fdff39e314761d934185ae1df57e9b39748fc5ffaf787a7d2e7f00f7775a3f"
    addon_bytes = bytes.fromhex(addons_hex)
    addon_size = len(addon_bytes)

    fields = {
        "digest": digest_dec_join,
        "VirtualRealmID": virtual_realm_id,
        "clientSeed": client_seed_bytes,
        "clientBuild": build,
        "addonSize": addon_size,
        "addons": addons_hex,
        "hasAccountBit": 0,
        "accountNameLength": len(acct_up),
        "account": acct_up,
    }

    payload = EncoderHandler.encode_packet("CMSG_AUTH_SESSION", fields)

    opcode = WorldClientOpcodes.CMSG_AUTH_SESSION
    size = len(payload) + 2

    header = size.to_bytes(2, "little") + int(opcode).to_bytes(2, "little")
    return header + payload

def build_challenge_packet(username, cfg):
    client = cfg["client"]

    game = b"WoW\x00"
    platform = client["platform"].encode() + b"\x00"
    os_name = client["os"].encode() + b"\x00"
    country = client["country"].encode()
    timezone = client["timezone"]
    build = client["build"]

    version1, version2, version3 = 5, 4, 8

    ip_bytes = socket.inet_aton(client["ip"])
    u = username.upper().encode("ascii")
    ulen = len(u)

    tail = (
        game +
        bytes([version1, version2, version3]) +
        struct.pack("<H", build) +
        platform +
        os_name +
        country +
        struct.pack("<I", timezone) +
        ip_bytes +
        bytes([ulen]) +
        u
    )

    return b"\x00" + b"\x08" + struct.pack("<H", len(tail)) + tail


def build_proof_packet(srp):
    if not (srp.A_wire and srp.M1 and srp.K):
        raise ValueError("SRP6Client not fully initialized")

    crc = H(srp.A_wire, srp.M1, srp.K)

    return (
        b"\x01" +
        srp.A_wire +
        srp.M1 +
        crc +
        b"\x00" +
        b"\x00"
    )


class ClientSimulator:
    HANDSHAKE_SERVER = b"0\x00WORLD OF WARCRAFT CONNECTION - SERVER TO CLIENT\x00"
    HANDSHAKE_CLIENT = b"0\x00WORLD OF WARCRAFT CONNECTION - CLIENT TO SERVER\x00"

    def __init__(self):
        self.cfg = ConfigLoader.load_config()
        self.cfg["Logging"]["logging_levels"] = "Information, Success, Script, Error"
        self.username = ""
        self.password = ""
        self.session_key_hex: str | None = None
        self.srp: SRP6Client | None = None

    # ---- Auth flow ------------------------------------------------------

    def run(self):
        if not self._prompt_credentials():
            return

        auth_host = self.cfg["auth_proxy"]["listen_host"]
        auth_port = self.cfg["auth_proxy"]["listen_port"]
        Logger.info(f"Connecting to {auth_host}:{auth_port}")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((auth_host, auth_port))

            if not self._auth_logon(sock):
                return

            realms = self._fetch_realms(sock)

        if not realms:
            Logger.error("No realms returned; aborting world connect.")
            return

        selected_realm = self._choose_realm(realms)
        if not selected_realm:
            return

        self._connect_world(selected_realm)

    def _prompt_credentials(self) -> bool:
        self.username = input("Username: ").strip()
        self.password = getpass.getpass("Password: ").strip()

        if not self.username or not self.password:
            Logger.error("Missing username or password.")
            return False
        return True

    def _auth_logon(self, sock: socket.socket) -> bool:
        challenge = build_challenge_packet(self.username, self.cfg)
        Logger.info(f"[SEND] CHALLENGE_C")
        # Logger.info(f"[SEND] CHALLENGE_C = {challenge.hex()}")
        dsl_decode("AUTH_LOGON_CHALLENGE_C", challenge, self.cfg)
        sock.sendall(challenge)

        response = sock.recv(4096)
        Logger.info(f"[RECV] CHALLENGE_S")
        # Logger.info(f"[RECV] CHALLENGE_S = {response.hex()}")
        decoded = dsl_decode("AUTH_LOGON_CHALLENGE_S", response, self.cfg)
        if decoded.get("error", 1) != 0:
            Logger.error(f"Challenge failed with error {decoded['error']}")
            return False

        self._init_srp(decoded)

        proof = build_proof_packet(self.srp)
        Logger.info(f"[SEND] PROOF_C")
        # Logger.info(f"[SEND] PROOF_C = {proof.hex()}")
        dsl_decode("AUTH_LOGON_PROOF_C", proof, self.cfg)
        sock.sendall(proof)

        data = sock.recv(4096)
        Logger.info(f"[RECV] PROOF_S")
        # Logger.info(f"[RECV] PROOF_S = {data.hex()}")
        proof_resp = dsl_decode("AUTH_LOGON_PROOF_S", data, self.cfg)
        if proof_resp.get("error", 1) != 0:
            Logger.error("Proof failed")
            return False

        self.session_key_hex = self.srp.K.hex() if self.srp and self.srp.K else None
        Logger.success("Logged in successfully.")
        return True

    def _init_srp(self, decoded_challenge: dict) -> None:
        B = to_bytes(decoded_challenge["B"])
        g = decoded_challenge["g"]
        N = to_bytes(decoded_challenge["N"])
        salt = to_bytes(decoded_challenge["s"])

        self.srp = SRP6Client(self.username, self.password)
        self.srp.load_challenge(B_wire=B, g=g, N_wire=N, salt=salt)
        self.srp.compute_A()
        self.srp.compute_shared_key()
        self.srp.compute_M1()

    # ---- Realm list -----------------------------------------------------

    def _fetch_realms(self, sock: socket.socket):
        realm_req = EncoderHandler.encode_packet(
            "REALM_LIST_C",
            {
                "cmd": 0x10,
                "build": self.cfg["client"]["build"],
            },
        )
        # Logger.info(f"[SEND] REALM_LIST_C = {realm_req.hex()}")
        Logger.info(f"[SEND] REALM_LIST_C")
        dsl_decode("REALM_LIST_C", realm_req, self.cfg)
        sock.sendall(realm_req)

        data = sock.recv(4096)
        Logger.info(f"[RECV] REALM_LIST_S")
        # Logger.info(f"[RECV] REALM_LIST_S = {data.hex()}")
        realm_list = dsl_decode("REALM_LIST_S", data, self.cfg)
        return realm_list.get("realmlist", [])

    def _choose_realm(self, realms: list) -> dict | None:
        print()
        print("REALMLIST\n")
        # Logger.info("Realms:")
        for idx, realm in enumerate(realms, 1):
            name = realm.get("name", f"realm{idx}")
            addr = realm.get("address", "0.0.0.0:0")
            # Logger.info(f"{idx} - {name} - {addr}")
            print(f"{idx} - {name} - {addr}")

        choice = input(f"Select realm [1-{len(realms)}] (default 1): ").strip()
        print()
        try:
            choice_idx = int(choice) - 1 if choice else 0
        except ValueError:
            choice_idx = 0
        choice_idx = max(0, min(choice_idx, len(realms) - 1))
        return realms[choice_idx] if realms else None

    # ---- World flow -----------------------------------------------------

    def _connect_world(self, realm: dict):
        addr = realm.get("address", "0.0.0.0:0")
        try:
            world_host, world_port = addr.split(":")
            world_port = int(world_port)
        except Exception:
            Logger.error(f"Invalid realm address: {addr}")
            return

        time.sleep(1)
        Logger.info(f"Connecting to world {world_host}:{world_port}")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as ws:
            ws.connect((world_host, world_port))

            if not self._world_handshake(ws):
                return

            # 1) Auth challenge comes in cleartext (no ARC4 yet)
            seed = self._recv_world_auth_challenge(ws)
            if seed is None:
                return

            # 2) Send CMSG_AUTH_SESSION with okrypterad header
            self._send_world_auth_session(ws, seed)

            # 3) Läs AUTH_RESPONSE (fortfarande okrypterat); init ARC4 först efter auth_ok
            crypto = self._recv_world_auth_response(ws)
            if not crypto:
                return

            # 4) Fortsätt med ping/ready/enum över ARC4
            self._post_auth_flow(ws, crypto)

    def _world_handshake(self, ws: socket.socket) -> bool:
        hs = ws.recv(len(self.HANDSHAKE_SERVER))
        # Logger.info(f"[RECV] HANDSHAKE = {hs}")
        Logger.info(f"[RECV] HANDSHAKE")
        ws.sendall(self.HANDSHAKE_CLIENT)
        Logger.info("[SEND] HANDSHAKE_CLIENT")
        return True

    def _init_world_crypto(self) -> Arc4CryptoHandler | None:
        if not self.session_key_hex:
            Logger.error("Missing session key; cannot init ARC4.")
            return None

        crypto = Arc4CryptoHandler()
        Logger.info(f"K-client (DB/SRP): {self.session_key_hex}")
        try:
            crypto.init_arc4(self.session_key_hex)
        except Exception as exc:
            Logger.error(f"[CLIENT] ARC4 init failed: {exc}")
            return None
        Logger.success(f"[CLIENT] ARC4 init (via DSL)")
        return crypto

    def _recv_world_auth_challenge(self, ws: socket.socket) -> int | None:
        resp = ws.recv(4096)
        if not resp:
            Logger.error("Empty world response.")
            return None

        header = Arc4CryptoHandler().unpack_data(resp[:4])  # plain header

        payload = resp[4:4 + header.size]
        packet = dsl_decode("SMSG_AUTH_CHALLENGE", payload, self.cfg)
        Logger.info(f"[RECV] cmd=0x{header.cmd:04X}")
        # Logger.info(f"[RECV] cmd=0x{header.cmd:04X} size={header.size} payload={payload.hex()}")
        return packet.get("seed")

    def _send_world_auth_session(self, ws: socket.socket, server_seed: int):
        if not self.session_key_hex:
            Logger.error("Missing session key; cannot send CMSG_AUTH_SESSION.")
            return

        addon_data = resolve_addon_data(self.cfg)

        packet = build_cmsg_auth_session(
            account=self.username,
            server_seed=server_seed,
            session_key_hex=self.session_key_hex,
            build=self.cfg["client"]["build"],
            addon_data=addon_data,
        )

        Logger.info(f"[SEND] CMSG_AUTH_SESSION")
        ws.sendall(packet)

    def _recv_world_auth_response(self, ws: socket.socket) -> Arc4CryptoHandler | None:
        # AUTH_RESPONSE är OKRYPTERAD
        hdr = ws.recv(4)
        if not hdr:
            Logger.error("[WORLD] Empty response after auth session.")
            return None

        # ❗ unpacka RAW header, inte via ARC4
        header = Arc4CryptoHandler().unpack_data(hdr)

        payload = b""
        if header.size:
            payload = ws.recv(header.size)

        name = self._opcode_name_map().get(header.cmd, f"0x{header.cmd:04X}")

        decoded = None
        try:
            decoded = dsl_decode("SMSG_AUTH_RESPONSE", payload, self.cfg)
        except Exception as exc:
            Logger.error(f"[WORLD DECODE FAIL] SMSG_AUTH_RESPONSE: {exc}")

        Logger.info(f"[RECV] {name} size={header.size}")

        if decoded and decoded.get("auth_ok"):
            Logger.success("[WORLD] AUTH OK — init ARC4 and continue")

            # ✅ ARC4 init här – används FÖRSTA GÅNGEN på NÄSTA packet
            crypto = self._init_world_crypto()
            return crypto

        Logger.error("[WORLD] AUTH NOT OK")
        return None
    def _post_auth_flow(self, ws: socket.socket, crypto: Arc4CryptoHandler):
        # Ping/pong
        self._send_world_packet(ws, crypto, "CMSG_PING", {
            "ping": int(time.time()) & 0xFFFFFFFF,
            "latency": 0,
        })
        self._recv_world_packet(ws, crypto, expect="SMSG_PONG")

        # Account-data ready marker
        self._send_world_packet(ws, crypto, "CMSG_READY_FOR_ACCOUNT_DATA_TIMES")
        # Dra in alla SMSG_ACCOUNT_DATA_TIMES som kommer direkt efter
        while True:
            cmd2, name2, dec2, _ = self._recv_world_packet(ws, crypto, allow_empty=True)
            if name2 != "SMSG_ACCOUNT_DATA_TIMES":
                # stoppa om det var något annat
                break
        # Char enum
        self._send_world_packet(ws, crypto, "CMSG_ENUM_CHARACTERS")
        self._recv_world_packet(ws, crypto, expect="SMSG_ENUM_CHARACTERS_RESULT")

    def _opcode_name_map(self):
        return {
            val: key for key, val in WorldClientOpcodes.__dict__.items()
            if key.isupper() and isinstance(val, int)
        }

    def _recv_world_packet(self, ws: socket.socket, crypto: Arc4CryptoHandler, expect: str | None = None, allow_empty: bool = False):
        hdr_bytes = ws.recv(4)
        if not hdr_bytes:
            if not allow_empty:
                Logger.error("[WORLD] Empty header")
            return None, None, None, b""

        dec_header = crypto.decrypt_recv(hdr_bytes)
        header = crypto.unpack_data(dec_header)

        payload = b""
        if header.size:
            payload = ws.recv(header.size)

        name_map = self._opcode_name_map()
        name = name_map.get(header.cmd)
        decoded = None
        if name and name.startswith("SMSG_"):
            try:
                decoded = dsl_decode(name, payload, self.cfg)
            except Exception as exc:
                Logger.error(f"[WORLD DECODE FAIL] {name}: {exc}")

        Logger.info(f"[RECV] {name or '0x%04X' % header.cmd} size={header.size} payload={payload.hex()}")
        if expect and name != expect:
            Logger.warning(f"[WORLD] Expected {expect}, got {name}")
        return header.cmd, name, decoded, payload

    def _send_world_packet(self, ws: socket.socket, crypto: Arc4CryptoHandler, name: str, fields: dict | None = None):
        fields = fields or {}
        payload = EncoderHandler.encode_packet(name, fields)
        opcode = getattr(WorldClientOpcodes, name)
        header = crypto.pack_data(opcode, len(payload))
        enc_header = crypto.encrypt_send(header)
        ws.sendall(enc_header + payload)
        # Logger.info(f"[SEND] {name} size={len(payload)} payload={payload.hex()}")
        Logger.info(f"[SEND] {name} size={len(payload)} payload={payload.hex()}")


if __name__ == "__main__":
    Logger.info("Mist of Pandaria 5.4.8 client simulator")
    ClientSimulator().run()
