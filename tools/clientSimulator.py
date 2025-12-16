#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MoP 5.4.8 test client – protocol-oriented version.

Goals:
  • Readable protocol flow
  • No socket/buffer micromanagement in client
  • Reuse interpretation-layer logic
"""

import getpass
import os
import socket
import struct
import time

from utils.ConfigLoader import ConfigLoader
from utils.Logger import Logger
from utils.OpcodeLoader import load_world_opcodes

from modules.EncoderHandler import EncoderHandler
from modules.crypto.ARC4Crypto import Arc4CryptoHandler
from modules.crypto.SRP6Client import SRP6Client, H
from modules.crypto.SRP6Crypto import SRP6Crypto

from protocols.mop.v18414.opcodes.WorldOpcodes import WorldClientOpcodes

# interpretation layer
from modules.interpretation.PacketInterpreter import DslDecoder
from modules.interpretation.OpcodeResolver import OpcodeResolver
from modules.interpretation.EncryptedWorldStream import ClientWorldStream
from modules.interpretation.parser import parse_header
from modules.interpretation.utils import build_world_header, build_world_header_plain


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def to_bytes(val):
    if isinstance(val, bytes):
        return val
    if isinstance(val, str):
        return bytes.fromhex(val)
    raise TypeError(val)


# ----------------------------------------------------------------------
# Client
# ----------------------------------------------------------------------

class ClientSimulator:
    HANDSHAKE_SERVER = b"0\x00WORLD OF WARCRAFT CONNECTION - SERVER TO CLIENT\x00"
    HANDSHAKE_CLIENT = b"0\x00WORLD OF WARCRAFT CONNECTION - CLIENT TO SERVER\x00"

    def __init__(self):
        self.cfg = ConfigLoader.load_config()
        self.cfg["Logging"]["logging_levels"] = "Information, Success, Script, Error"

        self.username = ""
        self.password = ""
        self.session_key_hex = None
        self.srp: SRP6Client | None = None

        # interpretation
        self.stream = ClientWorldStream()
        self._world_rx_buf = bytearray()
        self.decoder = DslDecoder()

        client_ops, server_ops, world_lookup = load_world_opcodes()
        self.opcode_resolver = OpcodeResolver(
            client_ops,
            server_ops,
            world_lookup,
        )


    # ============================================================
    # AUTH FLOW
    # ============================================================

    def run(self):
        if not self._prompt_credentials():
            return

        sock = self._auth_flow()
        if not sock:
            return

        realms = self._fetch_realms(sock)
        if not realms:
            sock.close()
            return

        realm = self._choose_realm(realms)
        sock.close()

        if not realm:
            return

        self._world_flow(realm)

    def _prompt_credentials(self) -> bool:
        self.username = input("Username: ").strip()
        self.password = getpass.getpass("Password: ").strip()
        return bool(self.username and self.password)

    def _auth_flow(self) -> socket.socket | None:
        host = self.cfg["auth_proxy"]["listen_host"]
        port = self.cfg["auth_proxy"]["listen_port"]

        Logger.info(f"Connecting to auth {host}:{port}")

        sock = socket.create_connection((host, port))

        self._send_auth_challenge(sock)
        challenge = self._recv_auth_challenge(sock)
        if challenge.get("error", 1) != 0:
            sock.close()
            return None

        self._init_srp(challenge)

        self._send_auth_proof(sock)
        proof = self._recv_auth_proof(sock)
        if proof.get("error", 1) != 0:
            sock.close()
            return None

        self.session_key_hex = self.srp.K.hex()
        Logger.success("Auth OK")

        return sock

    def _send_auth_challenge(self, sock):
        client = self.cfg["client"]

        game = b"WoW\x00"
        platform = client["platform"].encode() + b"\x00"
        os_name = client["os"].encode() + b"\x00"
        country = client["country"].encode()
        timezone = client["timezone"]
        build = client["build"]

        version1, version2, version3 = 5, 4, 8

        ip_bytes = socket.inet_aton(client["ip"])
        u = self.username.upper().encode("ascii")
        ulen = len(u)

        payload = (
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

        pkt = b"\x00" + b"\x08" + struct.pack("<H", len(payload)) + payload

        Logger.info("[SEND] AUTH_LOGON_CHALLENGE_C")
        sock.sendall(pkt)

    def _recv_auth_challenge(self, sock) -> dict:
        data = sock.recv(4096)
        Logger.info("[RECV] AUTH_LOGON_CHALLENGE_S")
        return self.decoder.decode("AUTH_LOGON_CHALLENGE_S", data) or {}

    def _send_auth_proof(self, sock):
        pkt = (
            b"\x01" +
            self.srp.A_wire +
            self.srp.M1 +
            H(self.srp.A_wire, self.srp.M1, self.srp.K) +
            b"\x00\x00"
        )
        Logger.info("[SEND] AUTH_LOGON_PROOF_C")
        sock.sendall(pkt)

    def _recv_auth_proof(self, sock) -> dict:
        data = sock.recv(4096)
        Logger.info("[RECV] AUTH_LOGON_PROOF_S")
        return self.decoder.decode("AUTH_LOGON_PROOF_S", data) or {}

    def _init_srp(self, challenge: dict):
        self.srp = SRP6Client(self.username, self.password)
        self.srp.load_challenge(
            B_wire=to_bytes(challenge["B"]),
            g=challenge["g"],
            N_wire=to_bytes(challenge["N"]),
            salt=to_bytes(challenge["s"]),
        )
        self.srp.compute_A()
        self.srp.compute_shared_key()
        self.srp.compute_M1()

    # ============================================================
    # REALM LIST
    # ============================================================

    def _fetch_realms(self, sock: socket.socket):
        build = self.cfg["client"]["build"]

        pkt = bytes([0x10]) + build.to_bytes(4, "little")

        Logger.info("[SEND] REALM_LIST_C (raw cmd + build)")
        sock.sendall(pkt)

        data = sock.recv(4096)
        Logger.info("[RECV] REALM_LIST_S")

        realm_list = self.decoder.decode("REALM_LIST_S", data) or {}
        return realm_list.get("realmlist", [])
    
    def _choose_realm(self, realms):
        print("\nREALMS\n")
        for i, r in enumerate(realms, 1):
            print(f"{i}. {r['name']} ({r['address']})")

        choice = input(f"\nSelect realm [1-{len(realms)}] (default 1): ").strip()

        try:
            idx = int(choice) - 1 if choice else 0
        except ValueError:
            idx = 0

        idx = max(0, min(idx, len(realms) - 1))
        return realms[idx]

    # ============================================================
    # WORLD FLOW
    # ============================================================
    def _world_flow(self, realm: dict):
        host, port = realm["address"].split(":")
        port = int(port)

        Logger.info(f"Connecting to world {host}:{port}")

        ws = socket.create_connection((host, port))

        # 1) Handshake (plaintext)
        self._recv_world_handshake(ws)
        self._send_world_handshake(ws)

        # 2) Auth challenge (plaintext)
        seed = self._recv_SMSG_AUTH_CHALLENGE(ws)

        # 3) Auth session (plaintext)
        self._send_CMSG_AUTH_SESSION(ws, seed)

        # 4) Init ARC4
        crypto = Arc4CryptoHandler()
        crypto.init_arc4(self.session_key_hex)
        Logger.success("ARC4 initialized")
        ws.settimeout(5)

        # 5) Läs första krypterade server-paket (MÅSTE vara SMSG_AUTH_RESPONSE)
        leftovers = []
        while True:
            packets = self._recv_world_packets(ws, crypto)
            for _, h, payload in packets:
                name = self.opcode_resolver.decode_opcode(h.cmd, "S")
                Logger.info(f"[RECV] {name}")

                if name == "SMSG_AUTH_RESPONSE":
                    decoded = self.decoder.decode(name, payload) or {}
                    if not decoded.get("auth_ok"):
                        Logger.error("World auth failed")
                        return
                    Logger.success("World auth OK")

                    # nu är vi i post-auth-fasen — process any remaining packets too
                    leftovers = [(rh, hh, pl) for (rh, hh, pl) in packets if hh is not h]
                    self._post_auth(ws, crypto, initial_packets=leftovers)
                    return
                else:
                    leftovers.append((_, h, payload))


    def _recv_world_handshake(self, ws):
        data = ws.recv(len(self.HANDSHAKE_SERVER))
        Logger.info("[RECV] HANDSHAKE")

    def _send_world_handshake(self, ws):
        ws.sendall(self.HANDSHAKE_CLIENT)
        Logger.info("[SEND] HANDSHAKE")

    def _recv_SMSG_AUTH_CHALLENGE(self, ws) -> int:
        hdr = ws.recv(4)
        size, opcode, _ = parse_header(hdr)
        payload = ws.recv(size) if size else b""

        decoded = self.decoder.decode("SMSG_AUTH_CHALLENGE", payload) or {}
        Logger.info("[RECV] SMSG_AUTH_CHALLENGE")
        return decoded["seed"]

    def _send_CMSG_AUTH_SESSION(self, ws, seed: int):
        srp = SRP6Crypto()
        acct = srp.upper_skyfire(self.username)

        client_seed = struct.unpack("<I", os.urandom(4))[0]

        digest_bytes = srp.compute_world_auth_digest(
            account=self.username,
            client_seed_bytes=struct.pack("<I", client_seed),
            server_seed_bytes=struct.pack("<I", seed),
            session_key_bytes=bytes.fromhex(self.session_key_hex),
        )

        addons_bytes = bytes.fromhex("30050000789c7593514ec3300c868b38051247403cf2be0d360dad5259bbbd222ff15aab695cb969c576134ec2f548858440725ef3fd76e23fbf1fb22c5b3aba5e41ecfbc234841376e8c3619bdd7cde7e3d65ffb89806901dd79704470f3a194d20f62a5b829c508686fb040ec1e199d0d99c3c75d06b22f2967cad377060da1ca4457daa1538f41644430db8086b1cf44a47d1aa1226b447108293c34193717782b0e33ac92afc083aecc1843d905d0b747af3c3ba103e937ef5339ec6ba62761a7cf186471f505e79140f4e916cdca56fd4d93779344737749397a34ca867643392b34bf06d9aaed807619716a864eb871e8dfea26dc06ee1e2a4904ce12c29d9c490a472342b0e7d2d6051e53be636d6ae59d28fccc108eb84272cc02aa4c0f0b3036a5da4e9ef9b93a356edf1cc52a726ade68dd09daca8c31c3cd4a8ed4bc52deaf656b36d654b4effd688c9a3a8ecc864cbc012efd41d3816eaf9db884358354c06153a77d4fb2dc6d0fc2efe5fc5dde37df10de06e9df7")

        fields = {
            "digest": digest_bytes,
            "VirtualRealmID": 1,
            "clientSeed": client_seed,
            "clientBuild": self.cfg["client"]["build"],
            "addonSize": len(addons_bytes),
            "addons": addons_bytes,
            "hasAccountBit": 0,
            "accountNameLength": len(acct),
            "account": acct,
        }

        payload = EncoderHandler.encode_packet("CMSG_AUTH_SESSION", fields)
        header = build_world_header_plain(WorldClientOpcodes.CMSG_AUTH_SESSION, payload)

        Logger.info("[SEND] CMSG_AUTH_SESSION")
        ws.sendall(header + payload)

    def _recv_SMSG_AUTH_RESPONSE(self, ws) -> Arc4CryptoHandler | None:
        crypto = Arc4CryptoHandler()
        crypto.init_arc4(self.session_key_hex)
        Logger.success("ARC4 initialized")

        # Header är krypterad
        enc_hdr = ws.recv(4)
        hdr = crypto.decrypt_recv(enc_hdr)

        size, opcode, _ = parse_header(hdr)

        # Payload är ALLTID okrypterad
        payload = ws.recv(size) if size else b""

        decoded = self.decoder.decode("SMSG_AUTH_RESPONSE", payload) or {}
        Logger.info("[RECV] SMSG_AUTH_RESPONSE")

        if not decoded.get("auth_ok"):
            Logger.error("World auth failed")
            return None
        
        Logger.success("Auth OK")
        return crypto
    
    def _recv_world_packets(self, ws, crypto):
        while True:
            try:
                chunk = ws.recv(4096)
            except socket.timeout:
                continue

            if not chunk:
                raise ConnectionError("World socket closed")

            self._world_rx_buf.extend(chunk)

            packets = self.stream.feed(self._world_rx_buf, crypto=crypto, direction="S")
            if packets:
                return packets
            
    def _recv_one(self, ws, crypto):
        packets = self._recv_world_packets(ws, crypto)
        raw, h, payload = packets[0]
        name = self.opcode_resolver.decode_opcode(h.cmd, "S")
        decoded = self.decoder.decode(name, payload) if name.startswith("SMSG_") else {}
        return name, decoded, payload, packets[1:]

    def _post_auth(self, ws, crypto, initial_packets=None):
        """
        Handle post-auth initial server packets and respond with
        CMSG_READY_FOR_ACCOUNT_DATA_TIMES at the correct point.
        """

        # Reset buffers/pending state for post-auth stream
        self._world_rx_buf.clear()
        self.stream._pending = None
        Logger.info("[WORLD] Entering post-auth loop")

        # Process any packets already read with the auth response
        pending_packets = list(initial_packets) if initial_packets else []

        while True:
            if not pending_packets:
                packets = self._recv_world_packets(ws, crypto)
            else:
                packets, pending_packets = pending_packets, []

            Logger.info(f"[WORLD] Post-auth received {len(packets)} packet(s)")
            for _, h, payload in packets:
                name = self.opcode_resolver.decode_opcode(h.cmd, "S")
                Logger.info(f"[RECV] {name} (cmd=0x{h.cmd:04X} size={h.size})")

                if name == "SMSG_SET_TIME_ZONE_INFORMATION":
                    # Send ready_for_account_data_times after server TZ info
                    ready_hdr = crypto.pack_data(WorldClientOpcodes.CMSG_READY_FOR_ACCOUNT_DATA_TIMES, 0)
                    # C->S headers use decrypt_recv stream
                    ws.sendall(crypto.decrypt_recv(ready_hdr))
                    Logger.info("[SEND] CMSG_READY_FOR_ACCOUNT_DATA_TIMES (size=0, C->S)")
                    continue

                if name == "SMSG_ACCOUNT_DATA_TIMES":
                    Logger.info("[WORLD] Received SMSG_ACCOUNT_DATA_TIMES")
                    # Immediately request character list
                    enum_hdr = crypto.pack_data(WorldClientOpcodes.CMSG_ENUM_CHARACTERS, 0)
                    # C->S headers use decrypt_recv stream
                    ws.sendall(crypto.decrypt_recv(enum_hdr))
                    Logger.info("[SEND] CMSG_ENUM_CHARACTERS (size=0, C->S)")
                    continue

                if name == "SMSG_ENUM_CHARACTERS_RESULT":
                    decoded = self.decoder.decode(name, payload) or {}
                    chars = (
                        decoded.get("characters")
                        or decoded.get("chars")
                        or decoded.get("list")
                        or []
                    )

                    print("\nCHARACTERS\n")
                    if not chars:
                        print("[no characters decoded]")
                        Logger.info(f"[WORLD] Decoded ENUM payload keys: {list(decoded.keys())}")
                    else:
                        for i, ch in enumerate(chars, 1):
                            cname = ch.get("name", "Unknown")
                            clevel = ch.get("level", ch.get("lvl", "?"))
                            cclass = ch.get("class", ch.get("cls", "?"))
                            print(f"{i}. {cname} (level {clevel}, class {cclass})")

                    Logger.info("[WORLD] Received character list; post-auth flow complete")
                    return

            # No terminal packet yet; continue loop
            Logger.info("[WORLD] Still waiting for account data/enum packets…")

# ----------------------------------------------------------------------

if __name__ == "__main__":
    Logger.info("MoP 5.4.8 client simulator")
    ClientSimulator().run()
