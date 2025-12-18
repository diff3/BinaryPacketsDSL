#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Simple telnet-style control server for the proxy."""

from __future__ import annotations

import socketserver
import threading
import socket
from typing import List, Tuple
import os
from pathlib import Path

from utils.Logger import Logger
from utils.ConfigLoader import ConfigLoader
from modules.proxy.control_state import ControlState
from modules.proxy import promoter
from utils.OpcodeLoader import load_auth_opcodes, load_world_opcodes


class _ControlTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, RequestHandlerClass, *, control_state: ControlState):
        super().__init__(server_address, RequestHandlerClass)
        self.control_state = control_state
        self.username: str | None = None
        self.password: str | None = None
        self.enabled: bool = True
        # telnet option constants
        self.IAC = 255
        self.DO = 253
        self.DONT = 254
        self.WILL = 251
        self.WONT = 252
        self.ECHO = 1
        self.SGA = 3
        self.LINEMODE = 34
        self.command_completions: List[str] = []
        # opcode sets by source
        self.opcodes_all: List[str] = []
        self.opcodes_capture: List[str] = []
        self.opcodes_defs: List[str] = []


class _ControlHandler(socketserver.StreamRequestHandler):
    prompt = b"proxy> "

    def setup(self):
        super().setup()
        self.authed = False
        self._history: List[str] = []
        self._history_idx: int | None = None
        self._render_width: int = 0
        self._first_prompt: bool = True

    def handle(self):
        if not self.server.enabled:
            return

        self._negotiate_telnet()

        if self.server.username:
            if not self._authenticate():
                return
            self.authed = True

        self.wfile.write(b"BinaryPacketsDSL control (telnet). Type 'help' for commands.\r\n")
        while True:
            line = self._readline()
            if line is None:
                break
            line = line.strip()
            if not line:
                continue

            try:
                lines, close = self.server.process_command(line)
            except Exception as exc:  # pragma: no cover - defensive
                lines, close = [f"error: {exc}"], False

            for ln in lines:
                if ln == "__CLEAR__":
                    # Clear screen and move cursor to top-left
                    self.wfile.write(b"\x1b[2J\x1b[H")
                else:
                    self.wfile.write((ln + "\r\n").encode())
            try:
                self.wfile.flush()
            except Exception:
                pass

            if close:
                break

    # ------------------------------------------------------------------ #
    def _readline(self) -> str | None:
        """Read a line with basic history navigation (up/down)."""
        buf: List[str] = []
        cursor = 0
        self._history_idx = None
        if self._first_prompt:
            self._first_prompt = False
            self._write(self.prompt)
        else:
            self._write(b"\r\n" + self.prompt)

        while True:
            ch = self.rfile.read(1)
            if not ch:
                return None

            # Telnet negotiation (IAC sequences) — ignore fully
            if ch == b"\xff":  # IAC
                if self._handle_iac():
                    continue
                else:
                    return None

            if ch in (b"\r", b"\n"):
                self._write(b"\r\n")
                line = "".join(buf)
                if line and (not self._history or self._history[-1] != line):
                    self._history.append(line)
                return line

            if ch in (b"\x7f", b"\b"):  # backspace
                if cursor > 0:
                    del buf[cursor - 1]
                    cursor -= 1
                    self._render(buf, cursor)
                continue

            if ch == b"\x1b":  # ESC sequences (arrows/delete) or lone ESC to clear
                seq = self.rfile.read(2)
                if not seq:
                    buf = []
                    cursor = 0
                    self._render(buf, cursor)
                    continue
                if seq == b"[A":  # up
                    buf = self._history_prev(buf)
                    cursor = len(buf)
                    self._render(buf, cursor)
                elif seq == b"[B":  # down
                    buf = self._history_next(buf)
                    cursor = len(buf)
                    self._render(buf, cursor)
                elif seq == b"[C":  # right
                    if cursor < len(buf):
                        cursor += 1
                        self._render(buf, cursor)
                elif seq == b"[D":  # left
                    if cursor > 0:
                        cursor -= 1
                        self._render(buf, cursor)
                elif seq == b"[3":  # delete key sends ESC [ 3 ~
                    trailing = self.rfile.read(1)
                    if trailing == b"~" and cursor < len(buf):
                        del buf[cursor]
                        self._render(buf, cursor)
                else:
                    # lone ESC or unhandled sequence → clear line
                    buf = []
                    cursor = 0
                    self._render(buf, cursor)
                continue
            if ch == b"\t":
                buf, cursor = self._handle_tab(buf, cursor)
                continue

            try:
                c = ch.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if not c.isprintable():
                continue
            buf.insert(cursor, c)
            cursor += 1
            self._render(buf, cursor)

    def _render(self, buf: List[str], cursor: int) -> int:
        """
        Re-render the input line and position cursor.
        """
        text = "".join(buf)
        base = self.prompt + text.encode()
        # Clear line and write
        out = b"\r\x1b[2K" + base
        # Move cursor to correct position (from end back to cursor)
        move_left = len(text) - cursor
        if move_left > 0:
            out += f"\x1b[{move_left}D".encode()
        self._write(out)
        return len(text)

    def _write(self, data: bytes) -> None:
        try:
            self.wfile.write(data)
        except OSError:
            pass

    def _history_prev(self, current: List[str]) -> List[str]:
        if not self._history:
            return current
        if self._history_idx is None:
            self._history_idx = len(self._history) - 1
        else:
            self._history_idx = max(0, self._history_idx - 1)
        return list(self._history[self._history_idx])

    # ------------------------------------------------------------------ #
    # Telnet negotiation helpers (simple but explicit responses)
    # ------------------------------------------------------------------ #
    def _negotiate_telnet(self) -> None:
        """
        Send a minimal set of telnet options to request server-side echo and suppress GA.
        """
        seq = bytes(
            [
                self.server.IAC,
                self.server.WILL,
                self.server.ECHO,
                self.server.IAC,
                self.server.WILL,
                self.server.SGA,
                self.server.IAC,
                self.server.DO,
                self.server.SGA,
                self.server.IAC,
                self.server.DO,
                self.server.LINEMODE,
            ]
        )
        try:
            self.request.sendall(seq)
        except Exception:
            pass

    def _handle_iac(self) -> bool:
        """Process a telnet IAC sequence. Returns False if the stream ended."""
        cmd = self.rfile.read(1)
        if not cmd:
            return False

        if cmd in (bytes([self.server.WILL]), bytes([self.server.WONT])):
            opt = self.rfile.read(1)
            if not opt:
                return False
            if opt in (
                bytes([self.server.ECHO]),
                bytes([self.server.SGA]),
                bytes([self.server.LINEMODE]),
            ):
                reply = bytes([self.server.IAC, self.server.DO, opt[0]])
            else:
                reply = bytes([self.server.IAC, self.server.DONT, opt[0]])
            try:
                self.request.sendall(reply)
            except Exception:
                pass
            return True

        if cmd in (bytes([self.server.DO]), bytes([self.server.DONT])):
            opt = self.rfile.read(1)
            if not opt:
                return False
            if opt in (
                bytes([self.server.ECHO]),
                bytes([self.server.SGA]),
                bytes([self.server.LINEMODE]),
            ):
                reply_cmd = self.server.WILL if cmd == bytes([self.server.DO]) else self.server.WONT
            else:
                reply_cmd = self.server.WONT
            reply = bytes([self.server.IAC, reply_cmd, opt[0]])
            try:
                self.request.sendall(reply)
            except Exception:
                pass
            return True

        if cmd == b"\xfa":  # SB ... IAC SE
            # consume until IAC SE
            while True:
                b1 = self.rfile.read(1)
                if not b1:
                    return False
                if b1 == b"\xff":
                    b2 = self.rfile.read(1)
                    if b2 == b"\xf0":
                        break
            return True

        return True

    def _negotiate_telnet(self) -> None:
        """
        Send a minimal set of telnet options to request server-side echo and suppress GA.
        This helps avoid client-echoed escape sequences (e.g. arrow keys).
        """
        IAC = 255
        WILL = 251
        DO = 253
        ECHO = 1
        SUPPRESS_GO_AHEAD = 3
        LINEMODE = 34

        seq = bytes(
            [
                IAC,
                WILL,
                ECHO,  # server will echo
                IAC,
                WILL,
                SUPPRESS_GO_AHEAD,
                IAC,
                DO,
                SUPPRESS_GO_AHEAD,
                IAC,
                DO,
                LINEMODE,
            ]
        )
        try:
            self.request.sendall(seq)
        except Exception:
            pass

    def _history_next(self, current: List[str]) -> List[str]:
        if self._history_idx is None:
            return []
        self._history_idx += 1
        if self._history_idx >= len(self._history):
            self._history_idx = None
            return []
        return list(self._history[self._history_idx])

    def _split_prefix(self, text: str) -> Tuple[str, str]:
        if not text:
            return "", ""
        if " " not in text:
            return "", text
        base, _, prefix = text.rpartition(" ")
        return base + " ", prefix

    def _handle_tab(self, buf: List[str], cursor: int) -> Tuple[List[str], int]:
        text = "".join(buf[:cursor])
        trailing_space = text.endswith(" ")
        tokens = text.split(" ")
        if trailing_space:
            tokens.append("")
        # collapse multiple trailing empties (protocol  -> ["protocol", ""])
        while len(tokens) >= 2 and tokens[-1] == "" and tokens[-2] == "":
            tokens.pop()
        if tokens == [""]:
            tokens = []
        if not tokens:
            # list base commands when nothing typed
            self._write(b"\r\n")
            for m in self.server.command_completions:
                self._write(m.encode() + b"\r\n")
            self._write(b"\r\n" + self.prompt)
            self._render(buf, cursor)
            try:
                self.wfile.flush()
            except Exception:
                pass
            return buf, cursor

        cmd = tokens[0]
        sub = tokens[1] if len(tokens) > 1 else ""
        arg = tokens[2] if len(tokens) > 2 else ""
        pos = len(tokens)  # token position (1-based)

        def choose(matches: List[str], prefix: str) -> Tuple[List[str], str]:
            if prefix == "":
                return matches, ""
            filtered = [m for m in matches if m.upper().startswith(prefix.upper())]
            return filtered, prefix

        # Determine candidate list based on position
        candidates: List[str] = []
        prefix = tokens[-1]

        if pos == 1:
            candidates, prefix = choose(self.server.command_completions, tokens[0] if tokens[0] else "")
        else:
            if cmd == "protocol":
                if pos == 2:
                    candidates, prefix = choose(["add", "rm", "list", "view", "sync"], sub)
                elif pos == 3 and sub in ("add", "rm"):
                    candidates, prefix = choose(self.server.opcodes_capture, arg)
                elif pos == 3 and sub == "view":
                    candidates, prefix = choose(["def", "debug", "json"], arg)
                elif pos == 4 and sub == "view":
                    candidates, prefix = choose(self.server.opcodes_defs, tokens[3])
            elif cmd == "promot":
                if pos == 2:
                    candidates, prefix = choose(["this", "delete"], sub)
                elif pos == 3 and sub in ("this", "delete"):
                    candidates, prefix = choose(self.server.opcodes_capture if sub == "this" else self.server.opcodes_defs, arg)
            elif cmd == "dump":
                if pos == 2:
                    candidates, prefix = choose(["on", "off"], sub)
            elif cmd == "raw":
                if pos == 2:
                    candidates, prefix = choose(["on", "off"], sub)
            elif cmd == "debug":
                if pos == 2:
                    candidates, prefix = choose(["on", "off"], sub)
            elif cmd == "focus":
                if pos == 2:
                    candidates, prefix = choose(["on", "off", "add", "rm", "clear", "list"], sub)
                elif pos == 3 and sub in ("add", "rm"):
                    candidates, prefix = choose(self.server.opcodes_all, arg)
            elif cmd == "filter":
                if pos == 2:
                    candidates, prefix = choose(["add", "remove", "rm", "del", "clear", "list", "ignore", "whitelist"], sub)
                elif pos == 3 and sub in ("add", "remove", "rm", "del"):
                    candidates, prefix = choose(self.server.opcodes_all, arg)
                elif pos >= 3 and sub in ("ignore", "whitelist"):
                    action = arg if pos == 3 else tokens[2]
                    if action in ("add", "rm", "remove", "del"):
                        target_prefix = tokens[3] if pos >= 4 else ""
                        candidates, prefix = choose(self.server.opcodes_all, target_prefix)
                    elif action in ("clear", "list"):
                        candidates, prefix = choose([action], action)
            elif cmd == "capture":
                if pos == 2:
                    candidates, prefix = choose(["delete"], sub)
                elif pos == 3 and sub == "delete":
                    candidates, prefix = choose(["all"], arg)
                elif pos == 3 and sub in ("add", "remove", "rm", "del"):
                    candidates, prefix = choose(self.server.opcodes_all, arg)

        # Fallback: if still empty and last token has uppercase, show opcodes; otherwise commands.
        if not candidates:
            if any(ch.isupper() for ch in prefix):
                candidates, prefix = choose(self.server.opcodes_all, prefix)
            elif pos == 1:
                candidates, prefix = choose(self.server.command_completions, prefix)

        if not candidates:
            return buf, cursor

        # If no prefix at this level, list all candidates immediately.
        if prefix == "":
            self._write(b"\r\n")
            for m in candidates:
                self._write(m.encode() + b"\r\n")
            self._write(self.prompt)
            self._render(buf, cursor)
            try:
                self.wfile.flush()
            except Exception:
                pass
            return buf, cursor

        if len(candidates) == 1:
            completion = candidates[0]
            # rebuild line with completed token
            tokens[-1] = completion
            completed = " ".join(tokens).strip()
            if not completed.endswith(" "):
                completed += " "
            buf = list(completed)
            cursor = len(buf)
            self._render(buf, cursor)
            return buf, cursor

        # multi-match: extend common prefix
        common = os.path.commonprefix([c.upper() for c in candidates])
        if common and prefix and len(common) > len(prefix):
            tokens[-1] = candidates[0][: len(common)]
            completed = " ".join(tokens)
            buf = list(completed)
            cursor = len(buf)
            self._render(buf, cursor)
            return buf, cursor

        # list matches
        self._write(b"\r\n")
        for m in candidates:
            self._write(m.encode() + b"\r\n")
        self._write(b"\r\n" + self.prompt)
        self._render(buf, cursor)
        try:
            self.wfile.flush()
        except Exception:
            pass
        return buf, cursor

    # ------------------------------------------------------------------ #
    def _authenticate(self) -> bool:
        username = self.server.username
        password = self.server.password
        if not username and not password:
            return True

        self.wfile.write(b"Username: ")
        try:
            self.wfile.flush()
        except Exception:
            pass
        u = self._read_auth_line(echo=True)
        if u is None:
            return False
        self.wfile.write(b"\r\nPassword: ")
        try:
            self.wfile.flush()
        except Exception:
            pass
        p = self._read_auth_line(echo=False)
        if p is None:
            return False
        if (username and u != username) or (password and p != password):
            self.wfile.write(b"Authentication failed\r\n")
            return False
        return True

    def _read_auth_line(self, *, echo: bool = False) -> str | None:
        """
        Read a line for authentication, skipping telnet IAC sequences.
        If echo is True, characters are echoed back; otherwise input stays hidden.
        """
        buf: List[str] = []
        while True:
            ch = self.rfile.read(1)
            if not ch:
                return None
            if ch == b"\xff":  # IAC
                if not self._handle_iac():
                    return None
                continue
            if ch in (b"\r", b"\n"):
                # consume trailing LF/NUL if CRLF or CRNUL
                if ch == b"\r":
                    nxt = self.rfile.peek(1) if hasattr(self.rfile, "peek") else b""
                    if nxt and nxt[:1] in (b"\n", b"\x00"):
                        self.rfile.read(1)
                return "".join(buf).strip()
            try:
                c = ch.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if c.isprintable():
                buf.append(c)
                if echo:
                    try:
                        self.wfile.write(ch)
                        self.wfile.flush()
                    except Exception:
                        pass


class ControlServer:
    """Starts a TCP control server for telnet clients."""

    def __init__(self, control_state: ControlState, host: str = "127.0.0.1", port: int = 1337, *, enabled: bool = True, username: str | None = None, password: str | None = None) -> None:
        self.control_state = control_state
        self.host = host
        self.port = port
        self.enabled = enabled
        self.username = username or None
        self.password = password or None
        self._server: _ControlTCPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start the control server in a daemon thread."""
        if not self.enabled:
            Logger.info("[Control] Disabled in config")
            return

        if self._server:
            return

        servers: List[_ControlTCPServer] = []

        def bind_server(host: str, family: int) -> _ControlTCPServer | None:
            cls = _ControlTCPServer
            cls.address_family = family  # type: ignore[attr-defined]
            try:
                srv = cls((host, self.port), _ControlHandler, control_state=self.control_state)
                if family == socket.AF_INET6:
                    try:
                        srv.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                    except Exception:
                        pass
                srv.process_command = self._process_command  # type: ignore[attr-defined]
                srv.username = self.username
                srv.password = self.password
                srv.enabled = self.enabled
                return srv
            except Exception as exc:
                Logger.error(f"[Control] Failed to bind {host}:{self.port} ({'IPv6' if family==socket.AF_INET6 else 'IPv4'}): {exc}")
                return None

        # Primary binding
        primary_family = socket.AF_INET6 if (":" in self.host) else socket.AF_INET
        primary = bind_server(self.host, primary_family)
        if primary:
            cmd_comp, opcode_all, opcode_cap, opcode_defs = self._build_completions()
            primary.command_completions = cmd_comp
            primary.opcodes_all = opcode_all
            primary.opcodes_capture = opcode_cap
            primary.opcodes_defs = opcode_defs
            servers.append(primary)

        # Optional IPv6 listener on ::1 to avoid telnet localhost::1 refusal when using IPv4 host
        if socket.has_ipv6 and primary_family != socket.AF_INET6:
            if self.host in ("127.0.0.1", "0.0.0.0", "localhost"):
                secondary = bind_server("::1", socket.AF_INET6)
                if secondary:
                    secondary.command_completions = primary.command_completions
                    secondary.opcodes_all = primary.opcodes_all
                    secondary.opcodes_capture = primary.opcodes_capture
                    secondary.opcodes_defs = primary.opcodes_defs
                    servers.append(secondary)

        if not servers:
            Logger.error("[Control] No control servers started (bind failed)")
            return

        # Start all servers
        for idx, srv in enumerate(servers):
            name = "ControlServer" if idx == 0 else f"ControlServer-v6-{idx}"
            threading.Thread(target=srv.serve_forever, name=name, daemon=True).start()

        self._server = servers[0]
        self._thread = None  # not used when multiple servers
        bound_hosts = ", ".join(f"{'IPv6' if s.address_family==socket.AF_INET6 else 'IPv4'}@{s.server_address[0]}:{s.server_address[1]}" for s in servers)
        Logger.info(f"[Control] Listening on {bound_hosts} (telnet)")

    def _build_completions(self) -> Tuple[List[str], List[str], List[str], List[str]]:
        """Gather commands + opcode names for tab completion."""
        commands = [
            "clear",
            "status",
            "dump",
            "raw",
            "debug",
            "focus",
            "filter",
            "protocol",
            "capture",
            "promot",
            "help",
            "quit",
            "exit",
        ]
        opcodes_all: set[str] = set()
        opcodes_capture: set[str] = set()
        opcodes_defs: set[str] = set()
        try:
            cfg = ConfigLoader.load_config()
            program = cfg["program"]
            version = cfg["version"]
            # From captures/debug
            for p in Path("misc/captures/debug").glob("*.json"):
                opcodes_capture.add(p.stem)
                opcodes_all.add(p.stem)
            # From promoted def files
            def_dir = Path("protocols") / program / version / "def"
            for p in def_dir.glob("*.def"):
                opcodes_defs.add(p.stem)
                opcodes_all.add(p.stem)
        except Exception:
            pass

        # Always include all known opcodes from loaders for focus/filter completion
        try:
            c_auth, s_auth, _ = load_auth_opcodes()
            c_world, s_world, _ = load_world_opcodes()
            opcodes_all |= {*(c_auth.values()), *(s_auth.values()), *(c_world.values()), *(s_world.values())}
        except Exception:
            pass

        return (
            commands,
            sorted(opcodes_all, key=str.upper),
            sorted(opcodes_capture, key=str.upper),
            sorted(opcodes_defs, key=str.upper),
        )

    # ------------------------------------------------------------------ #
    def _process_command(self, cmd: str) -> Tuple[List[str], bool]:
        """Handle a single command string. Returns (lines, close_connection)."""
        parts = cmd.strip().split()
        if not parts:
            return [], False

        op = parts[0].lower()
        args = parts[1:]

        if op in ("quit", "exit", "bye"):
            return ["bye"], True

        if op == "help":
            return self._help(), False

        if op == "clear":
            return ["__CLEAR__"], False

        if op == "status":
            return self.control_state.status_lines(), False

        if op == "dump" and len(args) == 1:
            val = args[0].lower()
            if val in ("on", "1", "true"):
                self.control_state.set_dump(True)
                return ["dump: on"], False
            if val in ("off", "0", "false"):
                self.control_state.set_dump(False)
                return ["dump: off"], False
            return ["usage: dump on|off"], False

        if op == "raw" and len(args) == 1:
            val = args[0].lower()
            if val in ("on", "1", "true"):
                self.control_state.set_show_raw(True)
                return ["raw: on"], False
            if val in ("off", "0", "false"):
                self.control_state.set_show_raw(False)
                return ["raw: off"], False
            return ["usage: raw on|off"], False

        if op == "debug" and len(args) == 1:
            val = args[0].lower()
            if val in ("on", "1", "true"):
                self.control_state.set_show_debug(True)
                return ["debug: on"], False
            if val in ("off", "0", "false"):
                self.control_state.set_show_debug(False)
                return ["debug: off"], False
            return ["usage: debug on|off"], False

        if op == "focus":
            return self._handle_focus(args), False

        if op == "filter":
            return self._handle_filter(args), False

        if op == "promot":
            # backward compatibility
            return self._handle_promot(args), False

        if op == "protocol":
            return self._handle_protocol(args), False

        if op == "capture":
            return self._handle_capture(args), False

        if op == "reset":
            self.control_state.reset_defaults()
            return ["state reset to defaults"], False

        return [f"unknown command: {op}", "type 'help' for a list"], False

    # ------------------------------------------------------------------ #
    def _handle_focus(self, args: List[str]) -> List[str]:
        if not args:
            return ["usage: focus on|off|add <opcode>|rm <opcode>|clear|list"]

        sub = args[0].lower()
        if sub == "on":
            self.control_state.focus_on()
            return ["focus: on"]
        if sub == "off":
            self.control_state.focus_off()
            return ["focus: off"]
        if sub == "clear":
            self.control_state.focus_clear()
            self.control_state.focus_on()
            return ["focus: cleared"]
        if sub == "list":
            snap = self.control_state.snapshot()
            if snap.focus is None:
                return ["focus: off"]
            return ["focus: on"] + [f" - {op}" for op in sorted(snap.focus)]
        if sub in ("add", "+") and len(args) >= 2:
            op_name = " ".join(args[1:])
            self.control_state.focus_add(op_name)
            return [f"focus added: {op_name}"]
        if sub in ("rm", "del", "-") and len(args) >= 2:
            op_name = " ".join(args[1:])
            self.control_state.focus_rm(op_name)
            return [f"focus removed: {op_name}"]

        return ["usage: focus on|off|add <opcode>|rm <opcode>|clear|list"]

    # ------------------------------------------------------------------ #
    def _handle_filter(self, args: List[str]) -> List[str]:
        if not args:
            return ["usage: filter add <pattern> | filter remove <pattern> | filter clear | filter list | filter ignore add|rm|clear|list <opcode> | filter whitelist add|rm|clear|list <opcode>"]

        sub = args[0].lower()
        if sub == "add" and len(args) >= 2:
            pat = " ".join(args[1:])
            self.control_state.filter_add(pat)
            return [f"filter added: {pat}"]
        if sub in ("remove", "rm", "del") and len(args) >= 2:
            pat = " ".join(args[1:])
            self.control_state.filter_remove(pat)
            return [f"filter removed: {pat}"]
        if sub == "clear":
            self.control_state.filter_clear()
            return ["filters cleared"]
        if sub == "list":
            snap = self.control_state.snapshot()
            if not snap.filters:
                lines = ["filters: off (show all)"]
            else:
                lines = ["filters:"] + [f" - {p}" for p in sorted(snap.filters)]
            lines += ["ignore:"] + ([f" - {o}" for o in sorted(snap.ignore)] or [" - none"])
            lines += ["whitelist:"] + ([f" - {o}" for o in sorted(snap.whitelist)] or [" - inherit/config"])
            return lines

        if sub == "ignore":
            if len(args) < 2:
                return ["usage: filter ignore add|rm|clear|list <opcode>"]
            action = args[1].lower()
            if action == "add" and len(args) >= 3:
                op = " ".join(args[2:])
                self.control_state.ignore_add(op)
                return [f"ignore added: {op}"]
            if action in ("rm", "del", "remove") and len(args) >= 3:
                op = " ".join(args[2:])
                self.control_state.ignore_remove(op)
                return [f"ignore removed: {op}"]
            if action == "clear":
                self.control_state.ignore_clear()
                return ["ignore cleared"]
            if action == "list":
                snap = self.control_state.snapshot()
                return ["ignore:"] + ([f" - {o}" for o in sorted(snap.ignore)] or [" - none"])
            return ["usage: filter ignore add|rm|clear|list <opcode>"]

        if sub == "whitelist":
            if len(args) < 2:
                return ["usage: filter whitelist add|rm|clear|list <opcode>"]
            action = args[1].lower()
            if action == "add" and len(args) >= 3:
                op = " ".join(args[2:])
                self.control_state.whitelist_add(op)
                return [f"whitelist added: {op}"]
            if action in ("rm", "del", "remove") and len(args) >= 3:
                op = " ".join(args[2:])
                self.control_state.whitelist_remove(op)
                return [f"whitelist removed: {op}"]
            if action == "clear":
                self.control_state.whitelist_clear()
                return ["whitelist cleared"]
            if action == "list":
                snap = self.control_state.snapshot()
                return ["whitelist:"] + ([f" - {o}" for o in sorted(snap.whitelist)] or [" - none"])
            return ["usage: filter whitelist add|rm|clear|list <opcode>"]

        return ["usage: filter add <pattern> | filter remove <pattern> | filter clear | filter list | filter ignore add|rm|clear|list <opcode> | filter whitelist add|rm|clear|list <opcode>"]

    # ------------------------------------------------------------------ #
    def _help(self) -> List[str]:
        return [
            "commands:",
            "  clear                    clear screen",
            "  status                   show current state",
            "  dump on | off            toggle dumping",
            "  raw on  | off            toggle raw payload logging",
            "  debug on | off           toggle decoded JSON logging",
            "  focus on | off           enable/disable focus filtering",
            "  focus add <op>           add opcode name to focus",
            "  focus rm  <op>           remove opcode name from focus",
            "  focus clear              empty focus list (leaves focus on)",
            "  focus list               list focused opcodes",
            "  filter add <pat>         show only packets matching pattern (e.g. CMSG_*)",
            "  filter remove <pat>      remove a filter pattern",
            "  filter clear             remove all filters (show all)",
            "  filter list              list active filters",
            "  filter ignore add | rm | clear | list <op>    blacklist opcodes at runtime",
            "  filter whitelist add | rm | clear | list <op>  override whitelist at runtime",
            "  protocol add <op>        promote capture into protocols",
            "  protocol rm  <op>        remove promoted files for opcode",
            "  protocol sync            sync protocol debug/json from captures",
            "  protocol list            list promoted protocols (DEF)",
            "  protocol view def | debug | json <op>  view a promoted artifact",
            "  promot <op>              (legacy) promote capture into protocols",
            "  promot delete <op>       (legacy) remove promoted files for opcode",
            "  capture delete all       remove all captures and recreate folders",
            "  reset                    reset runtime state to defaults",
            "  help                     show this help",
            "  quit                     close connection",
        ]

    # ------------------------------------------------------------------ #
    def _handle_promot(self, args: List[str]) -> List[str]:
        if not args:
            return ["usage: promot <opcode> | promot delete <opcode>"]

        # optional "this" keyword to keep opcode at third token position
        if args and args[0].lower() == "this":
            args = args[1:]
            if not args:
                return ["usage: promot this <opcode>"]

        sub = args[0].lower()
        if sub == "delete" and len(args) == 2:
            return promoter.delete_opcode(args[1])
        opcode = " ".join(args)
        return promoter.promote_opcode(opcode)

    # ------------------------------------------------------------------ #
    def _handle_protocol(self, args: List[str]) -> List[str]:
        if not args:
            return ["usage: protocol add <op> | protocol rm <op> | protocol list | protocol view def|debug|json <op> | protocol sync"]

        sub = args[0].lower()
        if sub == "add" and len(args) >= 2:
            return promoter.promote_opcode(" ".join(args[1:]))
        if sub == "rm" and len(args) >= 2:
            return promoter.delete_opcode(" ".join(args[1:]))
        if sub == "sync":
            return promoter.sync_protocols_from_captures()
        if sub == "list":
            search = " ".join(args[1:]) if len(args) > 1 else None
            return promoter.list_protocols(search=search)
        if sub == "view" and len(args) >= 3:
            kind = args[1]
            name = " ".join(args[2:])
            return promoter.view_protocol(kind, name)

        return ["usage: protocol add <op> | protocol rm <op> | protocol list | protocol view def|debug|json <op>"]

    # ------------------------------------------------------------------ #
    def _handle_capture(self, args: List[str]) -> List[str]:
        if len(args) >= 2 and args[0].lower() == "delete" and args[1].lower() == "all":
            return promoter.delete_all_captures()
        return ["usage: capture delete all"]


__all__ = ["ControlServer"]
