#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""World proxy: relays world traffic and handles ARC4 header parsing."""

import importlib
import json
import socket
import threading
from typing import Any, Dict, Optional, Set, Tuple

from utils.Logger import Logger
from utils.ConfigLoader import ConfigLoader
from utils.OpcodeLoader import load_world_opcodes
from utils.OpcodesFilter import filter_opcode
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
from modules.interpretation.utils import dsl_decode
from modules.interpretation.parser import parse_plain_packets
from modules.proxy.control_state import ControlState


cfg = ConfigLoader.load_config()
cfg["Logging"]["logging_levels"] = "Information, Success, Script, Error"

program = cfg["program"]
version = cfg["version"]

mod = importlib.import_module(f"protocols.{program}.{version}.modules.database.DatabaseConnection")
DatabaseConnection = getattr(mod, "DatabaseConnection")


class WorldProxy:
    """Hybrid world proxy: plain pre-AUTH, ARC4 stream post-AUTH."""

    HANDSHAKE = b"0\x00WORLD OF WARCRAFT CONNECTION"

    def __init__(self, listen_host: str, listen_port: int, world_host: str, world_port: int, dump: bool = False, update: bool = False, focus_dump=None, control_state: Optional[ControlState] = None) -> None:
        """Initialize proxy configuration and helpers."""
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.world_host = world_host
        self.world_port = world_port

        self.dump = dump
        # update mode removed; keep attr for compatibility but keep disabled
        self.update = False
        self.focus_dump = set(focus_dump) if focus_dump else None
        self.cfg = cfg
        self.control_state = control_state

        self.client_opcodes, self.server_opcodes, self.world_lookup = load_world_opcodes()

        self.opcode_resolver = OpcodeResolver(
            self.client_opcodes,
            self.server_opcodes,
            self.world_lookup,
        )

        try:
            self.AUTH_SESSION_OPCODE = (
                self.world_lookup.WorldClientOpcodes.CMSG_AUTH_SESSION.value
            )
        except Exception:
            self.AUTH_SESSION_OPCODE = 0x00B2  # MoP fallback

        self.stream = EncryptedWorldStream()

        # Packet dumper – same layout as AuthProxy
        self.dumper = PacketDump(f"protocols/{cfg['program']}/{cfg['version']}/data")

        self.interpreter = PacketInterpreter(
            decoder=DslDecoder(),
            normalizer=JsonNormalizer(),
            policy=DumpPolicy(
                dump=self.dump,
                update=self.update,
                focus_dump=self.focus_dump,
            ),
            dumper=PacketDumper(self.dumper),
        )
  
    # ---- start -----------------------------------------------------------

    def start(self) -> None:
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

    def handle_client(self, client_sock: socket.socket) -> None:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            server_sock.connect((self.world_host, self.world_port))
        except Exception as e:
            Logger.error(f"[WorldProxy] Failed to connect to worldserver: {e}")
            client_sock.close()
            return

        crypto = Arc4CryptoHandler()

        session: Dict[str, Any] = {
            "username": None,
            "key": None,
            "initialized": False,
        }

        state: Dict[str, bool] = {"encrypted": False}

        # Buffers are only used after AUTH (stream mode)
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


    # ---- S→C -------------------------------------------------------------

    def forward_s2c(self, server: socket.socket, client: socket.socket, crypto: Arc4CryptoHandler, session: Dict[str, Any], state: Dict[str, bool], buffer: bytearray) -> None:
        try:
            while True:
                data = server.recv(4096)

                if not data:
                    break

                # Handshake (plaintext)
                if data.startswith(self.HANDSHAKE):
                    Logger.info("[WorldProxy Server → Client] HANDSHAKE")
                    client.sendall(data)
                    continue

                if not state["encrypted"]:
                    # Pre-AUTH: per recv-chunk, plaintext header
                    packets = parse_plain_packets(data, "S")
                else:
                    # Post-AUTH: stream mode with ARC4 headers
                    buffer.extend(data)
                    packets = self.stream.feed(
                        buffer,
                        crypto=crypto,
                        direction="S",
                    )

                for raw_header, h, payload in packets:
                    name = self.opcode_resolver.decode_opcode(h.cmd, "S")
                    opcode_int = h.cmd

                    policy, filters, ignore, whitelist, show_raw_flag, show_debug_flag = self._state_snapshot()
                    decoded_safe = self.interpreter.interpret(name, raw_header, payload, policy=policy)

                    # Handshake/raw without opcode
                    if opcode_int < 0:
                        Logger.success(f"[WorldProxy Server → Client] RAW ({h.hex}), size={h.size}")
                        Logger.success(f"\n{payload.hex(' ')}")
                        continue

                    # Filter: which opcodes get details?
                    show_details = self._allow_opcode(name, opcode_int, ignore, whitelist)

                    # RAW flag: global toggle
                    show_raw = bool(show_raw_flag)

                    # Decode once (and dump if --dump/--update)
                    if show_details and show_debug_flag:
                        decoded_json = json.dumps(decoded_safe, indent=2)
                        if decoded_json == "{}":
                            decoded_json = ""
                    else:
                        decoded_json = ""

                    view_json = decoded_json

                    display = ControlState.matches_filters(name, filters) if opcode_int >= 0 else True

                    if display and show_details:
                        Logger.info(f"[WorldProxy Server → Client] {name} ({h.hex}), size={h.size}{view_json}")

                    # RAW data dump
                    if show_details and show_raw:
                        Logger.info(f"[RAW]\n{payload}")


                # Transparent forward
                client.sendall(data)

        except Exception as e:
            Logger.success(f"[WorldProxy S→C] RAW ({h.hex}), size={h.size}")
            Logger.success(f"\n{payload}")

    # ---- C→S -------------------------------------------------------------

    def forward_c2s(self, client: socket.socket, server: socket.socket, crypto: Arc4CryptoHandler, session: Dict[str, Any], state: Dict[str, bool], buffer: bytearray) -> None:
        try:
            while True:
                data = client.recv(4096)
                if not data:
                    break

                # Handshake
                if data.startswith(self.HANDSHAKE):
                    Logger.info("[WorldProxy Client → Server] HANDSHAKE")
                    server.sendall(data)
                    continue

                if not state["encrypted"]:
                    # Pre-AUTH: per recv-chunk
                    packets = parse_plain_packets(data, "C")
                else:
                    # Post-AUTH: stream mode
                    buffer.extend(data)
                    packets = self.stream.feed(
                        buffer,
                        crypto=crypto,
                        direction="C",
                    )

                for raw_header, h, payload in packets:
                    name = self.opcode_resolver.decode_opcode(h.cmd, "C")

                    opcode_int = h.cmd
                    policy, filters, ignore, whitelist, show_raw_flag, show_debug_flag = self._state_snapshot()
                    decoded_safe = self.interpreter.interpret(name, raw_header, payload, policy=policy)

                    # Handshake/raw without opcode
                    if opcode_int < 0:
                        Logger.success(f"[WorldProxy Client → Server] RAW ({h.hex}), size={h.size}")
                        Logger.success(f"\n{payload.hex(' ')}")
                        continue

                    # Filter: which opcodes get details?
                    show_details = self._allow_opcode(name, opcode_int, ignore, whitelist)

                    # RAW flag: global toggle
                    show_raw = bool(show_raw_flag)

                    # Decode once (and dump if --dump/--update)
                    if show_details and show_debug_flag:
                        decoded_json = json.dumps(decoded_safe, indent=2)
                        if decoded_json == "{}":
                            decoded_json = ""
                    else:
                        decoded_json = ""

                    view_json = decoded_json

                    display = ControlState.matches_filters(name, filters) if opcode_int >= 0 else True

                    if display and show_details:
                        Logger.info(f"[WorldProxy Client → Server] {name} ({h.hex}), size={h.size}{view_json}")

                    # RAW data dump
                    if show_details and show_raw:
                        Logger.info(f"[RAW]\n{payload}")


                    # CMSG_AUTH_SESSION → initialize ARC4 and switch to encrypted mode
                    if not state["encrypted"] and h.cmd == self.AUTH_SESSION_OPCODE:
                        Logger.success("[WorldProxy] CMSG_AUTH_SESSION detected")

                        decoded_auth = dsl_decode("CMSG_AUTH_SESSION", payload, silent=False)
                        account = decoded_auth.get("account") or decoded_auth.get("account")

                        if not account:
                            Logger.error("[WorldProxy] AUTH_SESSION without username")
                            continue

                        acc = DatabaseConnection.get_user_by_username(account.upper())
                        if not acc or not acc.session_key:
                            Logger.error("[WorldProxy] No session key for account")
                            continue

                        K = acc.session_key
                        if isinstance(K, (bytes, bytearray)):
                            K = K.hex()

                        crypto.init_arc4(K)

                        session["account"] = account
                        session["key"] = K
                        session["initialized"] = True
                        state["encrypted"] = True

                        Logger.success("[WorldProxy] ARC4 initialized — switching to encrypted mode")

                        continue

                # Transparent forward
                server.sendall(data)

        except Exception as e:
            Logger.error(f"[WorldProxy C→S] {e}")

    # ------------------------------------------------------------------
    def _state_snapshot(self) -> Tuple[DumpPolicy, Optional[Set[str]], Set[str], Set[str], bool, bool]:
        """
        Build a DumpPolicy and active filters from shared state once per packet to avoid frequent locking.
        Falls back to constructor flags if no control state is provided.
        """
        if self.control_state:
            snap = self.control_state.snapshot()
            focus_set: Optional[Set[str]] = set(snap.focus) if snap.focus is not None else None
            filters = set(snap.filters) if snap.filters else None
            return (
                DumpPolicy(dump=snap.dump, update=False, focus_dump=focus_set),
                filters,
                snap.ignore,
                snap.whitelist,
                snap.show_raw,
                snap.show_debug,
            )

        return (
            DumpPolicy(dump=self.dump, update=False, focus_dump=self.focus_dump),
            None,
            set(),
            set(),
            True,
            True,
        )

    def _allow_opcode(self, name: str, code: int, ignore: Set[str], whitelist: Set[str]) -> bool:
        """
        Decide if opcode should be shown based on dynamic ignore/whitelist only.
        - ignore always blocks
        - whitelist, if non-empty, acts as allow-list
        """
        # Build a temporary cfg for filter_opcode with runtime-only lists
        blacklist = list(ignore)
        whitelist_cfg = list(whitelist) if whitelist else []
        temp_cfg = {
            "WhiteListedOpcodes": whitelist_cfg,
            "BlackListedOpcodes": blacklist,
        }
        return filter_opcode(name, code, temp_cfg)
