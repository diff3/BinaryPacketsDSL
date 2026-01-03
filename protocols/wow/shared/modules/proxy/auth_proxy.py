from utils.Logger import Logger
from utils.ConfigLoader import ConfigLoader
from protocols.wow.shared.utils.OpcodeLoader import load_auth_opcodes

import json
import socket
from typing import Optional, Set, Tuple
import threading
import traceback
import time

from modules.dsl.DslRuntime import DslRuntime
from utils.PathUtils import get_captures_root
from .control_state import ControlState

from protocols.wow.shared.utils.PacketDump import PacketDump, dump_capture

cfg = ConfigLoader.load_config()
cfg["Logging"]["logging_levels"] = "Information, Success, Script, Error"


class AuthProxy:
    """
    Transparent TCP proxy for the MoP AuthServer.

    Funktionen:
      • Transparent forward, byte-för-byte
      • DSL-decode bara om dump/update är aktiverat
      • Dump/update: sparar EN fil per opcode, aldrig timestampade.
    """

    def __init__(self, listen_host, listen_port, auth_host, auth_port, dump=False, update=False, focus_dump=None, control_state: Optional[ControlState] = None, dsl_runtime: Optional[DslRuntime] = None):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.auth_host = auth_host
        self.auth_port = auth_port

        self.dump = dump       # dump → captures/<opcode>.*
        # update mode removed; keep attr for compatibility but keep disabled
        self.update = False
        self.focus_dump = focus_dump
        self.control_state = control_state
        self.client_opcodes, self.server_opcodes, self.lookup = load_auth_opcodes()
        self.program = cfg["program"]
        self.expansion = cfg.get("expansion")
        self.version = cfg["version"]

        # Update-läge använder denna dumper
        self.dumper = PacketDump(f"protocols/{self.program}/{self.expansion}/{self.version}/data")

        if dsl_runtime is not None:
            self.runtime = dsl_runtime
            Logger.info("[AuthProxy] DSL runtime ready (runtime mode, no JSON)")
        else:
            try:
                # Proxy-läge: ingen JSON, ingen watcher
                self.runtime = DslRuntime(self.program, self.version, watch=False, expansion=self.expansion)
                self.runtime.load_runtime_all()
                Logger.info("[AuthProxy] DSL runtime ready (runtime mode, no JSON)")
            except Exception as e:
                Logger.error(f"[AuthProxy] Runtime init failed (runtime mode): {e}")
                # Fallback – men fortfarande runtime-variant, utan JSON
                self.runtime = DslRuntime(self.program, self.version, watch=False, expansion=self.expansion)
                self.runtime.load_runtime_all()

    # ----------------------------------------------------------------------

    def start(self):
        """Start listening for client connections."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.listen_host, self.listen_port))
        srv.listen(5)

        Logger.info(
            f"[AuthProxy] Listening on {self.listen_host}:{self.listen_port} "
            f"→ {self.auth_host}:{self.auth_port}"
        )

        while True:
            client_sock, addr = srv.accept()
            Logger.success(f"[AuthProxy] Client connected: {addr}")

            t = threading.Thread(target=self.handle_client, args=(client_sock,), daemon=True)
            t.start()

    # ----------------------------------------------------------------------

    def handle_client(self, client_sock):
        """Set up connection to the AuthServer and start bidirectional relay."""
        try:
            auth_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            auth_sock.connect((self.auth_host, self.auth_port))
        except Exception as exc:
            Logger.error(f"[AuthProxy] Failed to connect to AuthServer: {exc}")
            client_sock.close()
            return

        # Start C→S
        threading.Thread(
            target=self.forward, args=(client_sock, auth_sock, "C→S"), daemon=True
        ).start()

        # S→C
        self.forward(auth_sock, client_sock, "S→C")

        try:
            client_sock.close()
            auth_sock.close()
        except:
            pass

        Logger.info("[AuthProxy] Closed connection")

    # ----------------------------------------------------------------------
    def forward(self, src, dst, direction):
        """Transparent relay + valfri DSL decode + dump/update."""
        try:
            while True:
                buf = src.recv(4096)
                if not buf:
                    break

                dump_enabled, update_enabled, focus, filters = self._current_flags()

                # Endast 1 byte opcode i auth
                op = buf[0]
                name = (
                    self.client_opcodes.get(op)
                    if direction == "C→S"
                    else self.server_opcodes.get(op)
                )

                if name:
                    display = ControlState.matches_filters(name, filters)
                    if display:
                        Logger.info(f"{direction} {name} (0x{op:02X})")

                    try:
                        case_name = name
                        decoded = self.runtime.decode(name, buf, silent=True)
                        if display:
                            Logger.success(f"[DSL] {case_name}\n{json.dumps(decoded, indent=2)}")

                        raw_header = buf[:1]
                        payload    = buf[1:]

                        focus_ok = (focus is None) or (case_name in focus)

                        if update_enabled and focus_ok:
                            bin_p, json_p, dbg_p = self.dumper.dump_fixed(
                                case_name,
                                raw_header,
                                payload,
                                decoded
                            )
                            Logger.success(f"[UPDATE] {case_name}")

                        if dump_enabled and focus_ok:
                            root = get_captures_root(focus=True) if focus else None
                            ts = int(time.time()) if focus else None
                            bin_p, json_p, dbg_p = dump_capture(
                                case_name,
                                raw_header,
                                payload,
                                decoded,
                                root=root,
                                ts=ts,
                                debug_only=bool(focus)
                            )
                            Logger.success(f"[DUMP] {case_name}")
                        
                    except Exception:
                        Logger.error(f"[AuthProxy] DSL decode failed for {name}")
                        Logger.error(traceback.format_exc())

                # Transparent forward
                dst.sendall(buf)

        except Exception as exc:
            Logger.error(f"[AuthProxy {direction}] Error: {exc}")
            Logger.error(traceback.format_exc())

    # ----------------------------------------------------------------------
    def _current_flags(self) -> Tuple[bool, bool, Optional[Set[str]], Optional[Set[str]]]:
        """
        Snapshot control flags once per recv iteration to avoid locking often.
        Returns (dump, update, focus_set_or_none, filters_or_none).
        """
        if self.control_state:
            snap = self.control_state.snapshot()
            focus_set = set(snap.focus) if snap.focus is not None else None
            filters = set(snap.filters) if snap.filters else None
            return snap.dump, False, focus_set, filters
        return self.dump, False, set(self.focus_dump) if self.focus_dump else None, None
