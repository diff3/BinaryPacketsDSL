from utils.Logger import Logger
from utils.ConfigLoader import ConfigLoader
from utils.OpcodeLoader import load_auth_opcodes

import json
import socket
import threading
import traceback

from modules.DslRuntime import DslRuntime

from utils.PacketDump import PacketDump, dump_capture

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

    def __init__(self, listen_host, listen_port, auth_host, auth_port, dump=False, update=False):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.auth_host = auth_host
        self.auth_port = auth_port

        self.dump = dump       # dump → captures/<opcode>.*
        self.update = update   # update → protocols/<version>/<opcode>.*

        self.client_opcodes, self.server_opcodes, self.lookup = load_auth_opcodes()
        self.program = cfg["program"]
        self.version = cfg["version"]

        # Update-läge använder denna dumper
        self.dumper = PacketDump(f"protocols/{self.program}/{self.version}")

        try:
            self.runtime = DslRuntime(self.program, self.version, watch=True)
            self.runtime.load_all()
            Logger.info(f"[AuthProxy] DSL runtime ready (watching {self.program}/{self.version})")
        except Exception as e:
            Logger.error(f"[AuthProxy] Runtime init failed, disabling watch: {e}")
            self.runtime = DslRuntime(self.program, self.version, watch=False)
            self.runtime.load_all()

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

                # Endast 1 byte opcode i auth
                op = buf[0]
                name = (
                    self.client_opcodes.get(op)
                    if direction == "C→S"
                    else self.server_opcodes.get(op)
                )

                if name:
                    Logger.info(f"{direction} {name} (0x{op:02X})")

                    try:
                        case_name = name
                        decoded = self.runtime.decode(name, buf, silent=True)
                        # Logga alltid DSL-resultat (även tomt)
                        Logger.success(f"[DSL] {case_name}\n{json.dumps(decoded, indent=2)}")

                        # authpacket = opcode byte + payload
                        raw_header = buf[:1]
                        payload    = buf[1:]

                        # -----------------------------------
                        # UPDATE → protocols/<version>/
                        # -----------------------------------
                        if self.update:
                            bin_p, json_p, dbg_p = self.dumper.dump_fixed(
                                case_name,
                                raw_header,     # korrekt
                                payload,        # korrekt
                                decoded         # korrekt
                            )
                            Logger.success(f"[UPDATE] {case_name}")

                        # -----------------------------------
                        # DUMP → captures/
                        # -----------------------------------
                        if self.dump:
                            bin_p, json_p, dbg_p = dump_capture(
                                case_name,
                                raw_header,     # korrekt
                                payload,        # korrekt
                                decoded         # korrekt
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
