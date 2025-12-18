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
import select
import sys

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

from protocols.mop.v18414.data.text_emotes import TEXT_EMOTES


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

    def _extract_guid(self, ch: dict) -> int | None:
        """
        Extract a GUID from a character entry, handling multiple formats.
        """
        candidates = [
            ch.get("guid"),
            ch.get("player_guid"),
            ch.get("char_guid"),
        ]

        for cand in candidates:
            if cand is None or cand is True or cand is False:
                continue

            if isinstance(cand, int):
                return cand

            if isinstance(cand, bytes):
                return int.from_bytes(cand, "little")

            if isinstance(cand, str):
                txt = cand.strip()
                for base in (0, 16, 10):
                    try:
                        return int(txt, base)
                    except ValueError:
                        continue

        # Fallback: rebuild from guid_N bytes if present
        parts = []
        for idx in range(8):
            try:
                val = ch.get(f"guid_{idx}")
                if val is None:
                    continue
                parts.append((idx, int(val) & 0xFF))
            except (TypeError, ValueError):
                continue

        if parts:
            guid = 0
            for idx, byte_val in parts:
                guid |= byte_val << (idx * 8)
            return guid

        return None

    def _enter_world(self, ws, crypto, guid: int):
        Logger.info(f"[WORLD] Entering world with GUID {guid} (0x{guid:016X})")

        payload = EncoderHandler.encode_packet(
            "CMSG_PLAYER_LOGIN",
            {"guid": guid}
        )

        plain_header = crypto.pack_data(
            WorldClientOpcodes.CMSG_PLAYER_LOGIN,
            len(payload)
        )

        enc_header = crypto.decrypt_recv(plain_header)

        # C→S: headers använder decrypt_recv-streamen
        ws.sendall(enc_header + payload)
        Logger.info(
            f"[SEND] CMSG_PLAYER_LOGIN (header={enc_header.hex()} payload={len(payload)} bytes)"
        )

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
                self._handle_server_autorespond(ws, crypto, name, payload)

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

                    if not chars:
                        Logger.error("No characters returned by server")
                        return

                    print("\nCHARACTERS\n")
                    for i, ch in enumerate(chars, 1):
                        cname = ch.get("name", "Unknown")
                        clevel = ch.get("level", ch.get("lvl", "?"))
                        cclass = ch.get("class", ch.get("cls", "?"))
                        print(f"{i}. {cname} (level {clevel}, class {cclass})")

                    choice = input(f"\nSelect character [1-{len(chars)}] (default 1): ").strip()
                    try:
                        idx = int(choice) - 1 if choice else 0
                    except ValueError:
                        idx = 0

                    idx = max(0, min(idx, len(chars) - 1))
                    ch = chars[idx]

                    extracted_guid = self._extract_guid(ch)
                    if extracted_guid is not None:
                        Logger.info(f"[WORLD] Extracted GUID {extracted_guid} (0x{extracted_guid:016X})")
                    else:
                        Logger.info(f"[WORLD] Failed to extract GUID; character keys: {list(ch.keys())}")

                    # Använd hårdkodat GUID för enkelhet enligt önskemål
                    guid_override = "3303978696704"
                    Logger.info(f"[WORLD] Using GUID override {guid_override}")
                    guid = int(guid_override)

                    Logger.success(f"[WORLD] Logging in as {ch.get('name', '<unknown>')}")

                    self._enter_world(ws, crypto, guid)
                    self._world_idle(ws, crypto)
                    return
            # No terminal packet yet; continue loop
            Logger.info("[WORLD] Still waiting for account data/enum packets…")
    def _join_channel(self, ws, crypto, name: str):
        payload = EncoderHandler.encode_packet(
            "CMSG_CHAT_JOIN_CHANNEL",
            {
                "channel_id": 0,
                "channel_name": name,
                "password": "",
            },
        )

        hdr = crypto.pack_data(
            WorldClientOpcodes.CMSG_CHAT_JOIN_CHANNEL,
            len(payload),
        )

        ws.sendall(crypto.decrypt_recv(hdr) + payload)
        Logger.info(f"[SEND] CMSG_CHAT_JOIN_CHANNEL {name}") 

    def _send_channel_chat(self, ws, crypto, channel: str, text: str):
        msg = text.encode("utf-8")
        chan = channel.encode("utf-8")

        payload = EncoderHandler.encode_packet(
            "CMSG_MESSAGECHAT_CHANNEL",
            {
                "channel_len": len(chan),
                "channel": chan,
                "msg_len": len(msg),
                "msg": msg,
            },
        )

        hdr = crypto.pack_data(
            WorldClientOpcodes.CMSG_MESSAGECHAT_CHANNEL,
            len(payload),
        )

        ws.sendall(crypto.decrypt_recv(hdr) + payload)
        Logger.info(f"[SEND] CHANNEL({channel}): {text}")

    def _send_yell(self, ws, crypto, text: str):
        msg = text.encode("utf-8")

        payload = EncoderHandler.encode_packet(
            "CMSG_MESSAGECHAT_YELL",
            {
                "language": 0,   # LANG_UNIVERSAL
                "msg_len": len(msg),
                "msg": msg,
            },
        )

        hdr = crypto.pack_data(
            WorldClientOpcodes.CMSG_MESSAGECHAT_YELL,
            len(payload),
        )
        ws.sendall(crypto.decrypt_recv(hdr) + payload)

    def _send_whisper(self, ws, crypto, target: str, text: str):
        msg = text.encode("utf-8")
        tgt = target.encode("utf-8")

        payload = EncoderHandler.encode_packet(
            "CMSG_MESSAGECHAT_WHISPER",
            {
                "language": 0,                # LANG_UNIVERSAL
                "msg_len": len(msg),          # 8-bit length
                "target_len": len(tgt),       # 9-bit length
                "msg": msg,
                "target": tgt,
            },
        )

        hdr = crypto.pack_data(
            WorldClientOpcodes.CMSG_MESSAGECHAT_WHISPER,
            len(payload),
        )
        ws.sendall(crypto.decrypt_recv(hdr) + payload)


    def _handle_server_autorespond(self, ws, crypto, name: str, payload: bytes):
        """
        Minimal post-login reflexes (no game logic).
        """
        if name == "SMSG_TIME_SYNC_REQUEST":
            decoded = self.decoder.decode(name, payload) or {}

            seq = (
                decoded.get("sequence_id")
                or decoded.get("sequence")
                or decoded.get("seq")
                or decoded.get("I")
            )

            if seq is None:
                Logger.error("[WORLD] Missing sequence_id in SMSG_TIME_SYNC_REQUEST")
                return

            # FIX 1: uint16
            seq = int(seq) & 0xFFFF

            # FIX 2: uint32 wraparound
            client_ticks = int(time.time() * 1000) & 0xFFFFFFFF

            resp_payload = EncoderHandler.encode_packet(
                "CMSG_TIME_SYNC_RESPONSE",
                {
                    "sequence_id": seq,
                    "client_ticks": client_ticks,
                },
            )

            resp_header = crypto.pack_data(
                WorldClientOpcodes.CMSG_TIME_SYNC_RESPONSE,
                len(resp_payload),
            )

            ws.sendall(crypto.decrypt_recv(resp_header) + resp_payload)
            # Logger.info(f"[SEND] CMSG_TIME_SYNC_RESPONSE seq={seq} ticks={client_ticks}")
            return
        elif name == "SMSG_PING":
            decoded = self.decoder.decode(name, payload) or {}
            ping = decoded.get("ping") or decoded.get("I")

            if ping is None:
                Logger.error("[WORLD] Missing ping value in SMSG_PING")
                return

            ping = int(ping) & 0xFFFFFFFF

            resp_payload = EncoderHandler.encode_packet(
                "CMSG_PONG",
                {"ping": ping},
            )

            hdr = crypto.pack_data(
                WorldClientOpcodes.CMSG_PONG,
                len(resp_payload),
            )

            ws.sendall(crypto.decrypt_recv(hdr) + resp_payload)
            Logger.info(f"[SEND] CMSG_PONG ping={ping}")
            return
        elif name == "SMSG_LOGIN_VERIFY_WORLD":
            Logger.info("[WORLD] World verified, sending loading screen notify")

            payload = EncoderHandler.encode_packet(
                "CMSG_LOADING_SCREEN_NOTIFY",
                {"is_loading": 0}
            )

            hdr = crypto.pack_data(
                WorldClientOpcodes.CMSG_LOADING_SCREEN_NOTIFY,
                len(payload),
            )

            ws.sendall(crypto.decrypt_recv(hdr) + payload)
            Logger.info("[SEND] CMSG_LOADING_SCREEN_NOTIFY")

            self._join_channel(ws, crypto, "General")
            return
        elif name == "SMSG_MESSAGECHAT":
            Logger.info(payload.hex())
        elif name == "SMSG_EMOTE":
            decoded = self.decoder.decode(name, payload) or {}
            emote_id = decoded.get("emote_id")
            guid = decoded.get("guid")

            Logger.info(f"[EMOTE] guid={guid} emote_id={emote_id}")
        elif name == "SMSG_TEXT_EMOTE":
            raw = self.decoder.decode(name, payload).get("raw")
            print(raw)

    def _send_chat(self, ws, crypto, text: str):
        text = text.strip()
        if not text:
            return

        # -------- /yell --------
        if text.startswith("/y "):
            self._send_yell(ws, crypto, text[3:])
            return

        # -------- /whisper --------
        if text.startswith("/w "):
            try:
                target, msg = text[3:].split(" ", 1)
            except ValueError:
                Logger.error("Usage: /w <name> <message>")
                return
            self._send_whisper(ws, crypto, target, msg)
            return

        # -------- /emote --------
        if text.startswith("/"):
            self._send_emote_id(ws, crypto, text[1:])
            return

        # -------- normal SAY --------
        msg = text.encode("utf-8")

        payload = EncoderHandler.encode_packet(
            "CMSG_MESSAGECHAT_SAY",
            {
                "language": 0,  # LANG_UNIVERSAL
                "msg_len": len(msg),
                "msg": msg,
            },
        )

        hdr = crypto.pack_data(
            WorldClientOpcodes.CMSG_MESSAGECHAT_SAY,
            len(payload),
        )

        ws.sendall(crypto.decrypt_recv(hdr) + payload)
        Logger.info(f"[SEND] CMSG_MESSAGECHAT_SAY '{text}'")



    def _send_emote_id(self, ws, crypto, emote_name: str):
        emote_name = emote_name.lower()

        if emote_name not in TEXT_EMOTES:
            Logger.error(f"[EMOTE] Unknown emote '{emote_name}'")
            return

        emote_id = TEXT_EMOTES[emote_name]

        payload = EncoderHandler.encode_packet(
            "CMSG_SEND_TEXT_EMOTE",
            {
                "emote_id": emote_id,
                "target_guid": 0,
            },
        )

        hdr = crypto.pack_data(
            WorldClientOpcodes.CMSG_SEND_TEXT_EMOTE,
            len(payload),
        )

        ws.sendall(crypto.decrypt_recv(hdr) + payload)
        Logger.info(f"[SEND] CMSG_SEND_TEXT_EMOTE {emote_name} ({emote_id})")
    def _world_idle(self, ws, crypto):
        """
        Keep the world socket alive after login and allow simple chat input.
        """
        Logger.info("[WORLD] Entering idle loop (breathing)")
        Logger.info("Type chat messages and press Enter to speak.")

        QUIET_OPCODES = {
            "SMSG_SPLINE_MOVE_UNSET_FLYING",
            "SMSG_ON_MONSTER_MOVE",
            "SMSG_SPELL_EXECUTE_LOG",
            "SMSG_TIME_SYNC_REQUEST",
            "CMSG_TIME_SYNC_RESPONSE"
            "SMSG_UPDATE_WORLD_STATE",
            "SMSG_SET_PROFICIENCY",
        }

        while True:
            try:
                rlist, _, _ = select.select(
                    [ws, sys.stdin],
                    [],
                    [],
                    0.1,  # tick
                )
            except Exception as e:
                Logger.error(f"[WORLD] select() failed: {e}")
                return

            # ---------- stdin ----------
            if sys.stdin in rlist:
                line = sys.stdin.readline().strip()
                if line:
                    self._send_chat(ws, crypto, line)

            # ---------- socket ----------
            if ws in rlist:
                try:
                    packets = self._recv_world_packets(ws, crypto)
                except ConnectionError as e:
                    Logger.error(f"[WORLD] Connection closed: {e}")
                    return
                except Exception as e:
                    Logger.error(f"[WORLD] Error while reading world socket: {e}")
                    continue

                for _, h, payload in packets:
                    name = self.opcode_resolver.decode_opcode(h.cmd, "S")

                    if name not in QUIET_OPCODES:
                        Logger.info(f"[RECV] {name} (cmd=0x{h.cmd:04X} size={h.size})")

                    self._handle_server_autorespond(ws, crypto, name, payload)
# ----------------------------------------------------------------------

if __name__ == "__main__":
    Logger.info("MoP 5.4.8 client simulator")
    ClientSimulator().run()
