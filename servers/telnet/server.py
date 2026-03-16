# telnet/server.py

import socket
import threading
import logging

from telnet.transport import TelnetIO
from telnet.editor import LineEditor   # 👈 TELNET-editor
from cli.repl import run_repl

LOGGER = logging.getLogger("proxy")


def run_telnet_server(global_state, host="127.0.0.1", port=1337):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)
    server.settimeout(1.0)  # allow shutdown polling

    LOGGER.info("telnet listening %s:%s", host, port)

    while not global_state.shutdown:
        try:
            client, addr = server.accept()
        except socket.timeout:
            continue
        except OSError:
            break

        threading.Thread(
            target=_handle_client,
            args=(client, addr, global_state),
            daemon=True,
        ).start()

    try:
        server.close()
    except OSError:
        pass


def _handle_client(sock, addr, global_state):
    io = TelnetIO(sock)

    try:
        # Telnet negotiation (IAC, ECHO, SGA, no LINEMODE)
        io.negotiate()

        io.write(b"Entropy control socket (raw TCP)\r\n")
        io.write(b"Type 'help' for commands.\r\n\r\n")

        # 🔑 Skapa TELNET-editor explicit
        editor = LineEditor(
            io=io,
            prompt=b"> ",
            completer=None,  # eller complete om du vill ha TAB
        )

        # 🔑 Kör REPL med editor, inte med io
        run_repl(
            global_state,
            editor=editor,
        )

    except Exception as exc:
        LOGGER.exception("telnet error from %s: %s", addr, exc)

    finally:
        try:
            sock.close()
        except OSError:
            pass