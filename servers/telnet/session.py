# telnet/session.py

from cli.parser import parse_command, CommandError
from cli.help import render_help


class TelnetLineIO:
    def __init__(self, sock):
        self.sock = sock
        self.buffer = b""

    def write(self, text: str):
        self.sock.sendall(text.encode("utf-8", errors="replace"))

    def read_line(self):
        while b"\n" not in self.buffer:
            data = self.sock.recv(1024)
            if not data:
                if self.buffer:
                    break
                return None
            self.buffer += data

        line, _, rest = self.buffer.partition(b"\n")
        self.buffer = rest
        return line.rstrip(b"\r").decode(errors="replace")


class TelnetSession:
    def __init__(self, sock, state):
        self.io = TelnetLineIO(sock)
        self.state = state

    def run(self):
        self.io.write("Entropy control socket (raw TCP)\n")
        self.io.write("Type 'help' for commands\n\n")

        while not self.state.shutdown:
            self.io.write("> ")
            line = self.io.read_line()
            if line is None:
                break

            line = line.strip()
            if not line:
                continue

            try:
                action, args = parse_command(line)
            except CommandError as exc:
                self.io.write(str(exc) + "\n")
                continue

            result = action(self.state, args)

            if isinstance(result, tuple):
                intent, payload = result

                if intent == "__help__":
                    for row in render_help(payload):
                        self.io.write(row + "\n")
                    continue

                if intent == "__exit__":
                    self.io.write("Bye.\n")
                    break

                self.io.write(f"Unknown intent: {intent}\n")
                continue

            if isinstance(result, str):
                self.io.write(result + "\n")
            elif isinstance(result, list):
                for row in result:
                    self.io.write(row + "\n")

        self.io.write("Connection closed.\n")