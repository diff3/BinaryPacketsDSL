# telnet/transport.py

from __future__ import annotations

import socket


IAC = 255
DONT = 254
DO = 253
WONT = 252
WILL = 251

ECHO = 1
SGA = 3
LINEMODE = 34


class TelnetIO:
    """
    Raw TCP transport with minimal telnet negotiation + IAC filtering.

    - read_byte(): returns one non-IAC byte (or None on disconnect)
    - write(): bytes only
    """

    def __init__(self, sock: socket.socket):
        self.sock = sock

    def negotiate(self) -> None:
        """
        Request character-at-a-time input.
        This matches what your old server did.
        """
        seq = bytes(
            [
                IAC, WILL, ECHO,        # server will echo
                IAC, WILL, SGA,         # suppress go-ahead
                IAC, DO, SGA,
                IAC, DONT, LINEMODE,    # disable linemode
            ]
        )
        self.write(seq)

    def read_byte(self) -> bytes | None:
        """
        Read one byte, skipping telnet IAC negotiation sequences.
        """
        try:
            b1 = self.sock.recv(1)
        except OSError:
            return None

        if not b1:
            return None

        # Filter telnet negotiation: IAC <cmd> <opt>
        if b1 == bytes([IAC]):
            try:
                cmd = self.sock.recv(1)
                if not cmd:
                    return None

                # Subnegotiation: IAC SB ... IAC SE
                if cmd == b"\xfa":  # SB
                    while True:
                        x = self.sock.recv(1)
                        if not x:
                            return None
                        if x == bytes([IAC]):
                            y = self.sock.recv(1)
                            if not y:
                                return None
                            if y == b"\xf0":  # SE
                                break
                    return self.read_byte()

                # Normal: cmd + opt
                _opt = self.sock.recv(1)
                return self.read_byte()

            except OSError:
                return None

        return b1

    def read_line(self) -> str | None:
        """
        Optional: line-mode helper (not used by your LineEditor).
        """
        buf = bytearray()
        while True:
            b1 = self.read_byte()
            if b1 is None:
                return None
            if b1 in (b"\r", b"\n"):
                # swallow LF after CR
                if b1 == b"\r":
                    self.sock.setblocking(False)
                    try:
                        peek = self.sock.recv(1, socket.MSG_PEEK)
                        if peek == b"\n":
                            self.sock.recv(1)
                    except OSError:
                        pass
                    finally:
                        self.sock.setblocking(True)
                return bytes(buf).decode("utf-8", errors="replace")
            buf += b1

    def write(self, data: bytes) -> None:
        try:
            self.sock.sendall(data)
        except OSError:
            pass