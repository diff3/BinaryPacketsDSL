from utils.Logger import Logger
from utils.ConfigLoader import ConfigLoader
from utils.OpcodeLoader import load_auth_opcodes

import socket
import threading
import traceback

from modules.Processor import load_case
from modules.Session import get_session
from modules.DecoderHandler import DecoderHandler
from modules.NodeTreeParser import NodeTreeParser

from utils.PacketDump import PacketDump, dump_capture


cfg = ConfigLoader.load_config()
cfg["Logging"]["logging_levels"] = "Information, Success, Script, Error"


class AuthProxy:
    """
    Transparent TCP proxy for the MoP AuthServer.

    Detta lager ska aldrig:
        • tolka SRP-state
        • spara username/sessionkey
        • läsa eller skriva till auth-databasen
        • avbryta TCP-sessionen

    Den ska endast:
        • vidarebefordra data byte-för-byte
        • logga och DSL-dekoda om dump/update är aktiverat
        • aldrig påverka SRP-handshake eller sessioner
    """

    def __init__(self, listen_host, listen_port, auth_host, auth_port, dump=False, update=False):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.auth_host = auth_host
        self.auth_port = auth_port

        self.dump = dump
        self.update = update

        self.client_opcodes, self.server_opcodes, self.lookup = load_auth_opcodes()
        self.dumper = PacketDump(f"protocols/{cfg['program']}/{cfg['version']}")

        self.program = cfg["program"]
        self.version = cfg["version"]

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

        # Start pipes
        threading.Thread(
            target=self.forward, args=(client_sock, auth_sock, "C→S"), daemon=True
        ).start()

        self.forward(auth_sock, client_sock, "S→C")

        try:
            client_sock.close()
            auth_sock.close()
        except:
            pass

        Logger.info("[AuthProxy] Closed connection")

    # ----------------------------------------------------------------------

    def forward(self, src, dst, direction):
        """
        Relay bytes between sockets. Optionally decode/log if enabled.

        direction = "C→S" or "S→C"
        """
        try:
            while True:
                buf = src.recv(4096)
                if not buf:
                    break

                op = buf[0]
                name = (
                    self.client_opcodes.get(op)
                    if direction == "C→S"
                    else self.server_opcodes.get(op)
                )

                # ------------------------------------------------------------------
                # Optional DSL decode/logging
                # ------------------------------------------------------------------
                if name:
                    Logger.info(f"{direction} {name} (0x{op:02X})")

                    try:
                        case_name, def_lines, _, expected = load_case(
                            self.program, self.version, name
                        )
                        case = (case_name, def_lines, buf, expected)

                        s = get_session()
                        s.reset()

                        NodeTreeParser.parse(case)
                        decoded = DecoderHandler.decode(case)

                        if self.update:
                            bin_p, json_p, dbg_p = self.dumper.dump_fixed(
                                case_name, buf, decoded
                            )
                            Logger.success(f"[UPDATE] Saved: {bin_p}")

                        elif self.dump:
                            bin_p, json_p, dbg_p = dump_capture(case_name, buf, decoded)
                            Logger.success(f"[DUMP] Captured: {bin_p}")

                    except Exception:
                        Logger.error(f"[AuthProxy] DSL decode failed for {name}")
                        Logger.error(traceback.format_exc())

                # ------------------------------------------------------------------
                # TRANSPARENT FORWARD
                # ------------------------------------------------------------------
                dst.sendall(buf)

        except Exception as exc:
            Logger.error(f"[AuthProxy {direction}] Error: {exc}")
            Logger.error(traceback.format_exc())