# cli/repl.py

from cli.editor import LineEditor
from cli.parser import parse_command, CommandError
from cli.help import render_help
from cli.completion import complete


class StdIO:
    """
    Local adapter that matches TelnetIO semantics (bytes).
    """
    def read_byte(self):
        ch = input()
        if ch == "":
            return None
        return ch.encode()

    def write(self, data: bytes):
        print(data.decode(errors="replace"), end="", flush=True)


def run_repl_old(state, io, interactive=True):
    editor = None
    if interactive:
        editor = LineEditor(
            io=io,
            prompt=b"> ",
            completer=complete,
        )

    while True:
        line = editor.read_line()
        if line is None:
            io.write(b"Bye.\r\n")
            break

        line = line.strip()
        if not line:
            continue

        try:
            action, args = parse_command(line)
        except CommandError as exc:
            io.write(str(exc).encode() + b"\r\n")
            continue

        result = action(state, args)

        # ---- intent dispatch ----
        if isinstance(result, tuple):
            intent, payload = result

            if intent == "__help__":
                for row in render_help(payload):
                    io.write(row.encode() + b"\r\n")
                continue

            if intent == "__exit__":
                io.write(b"Bye.\r\n")
                break

            io.write(b"Unknown intent\r\n")
            continue

        # ---- normal output ----
        if isinstance(result, str):
            io.write(result.encode() + b"\r\n")

        elif isinstance(result, list):
            for row in result:
                io.write(row.encode() + b"\r\n")


def run_repl(state, editor):
    editor.completer = complete  
    
    try:
        while True:
            line = editor.read_line()

            if line is None:
                break

            line = line.strip()
            if not line:
                continue

            try:
                action, args = parse_command(line)
            except CommandError as exc:
                editor.io.write(str(exc).encode() + b"\r\n")
                continue

            result = action(state, args)

            if isinstance(result, tuple):
                intent, payload = result

                if intent == "__help__":
                    for row in render_help(payload):
                        editor.io.write(row.encode() + b"\r\n")
                    continue

                if intent == "__exit__":
                    editor.io.write(b"Bye.\r\n")
                    break

                editor.io.write(f"Unknown intent: {intent}\r\n".encode())
                continue

            if isinstance(result, str):
                editor.io.write(result.encode() + b"\r\n")
            elif isinstance(result, list):
                for row in result:
                    editor.io.write(row.encode() + b"\r\n")

    except (BrokenPipeError, OSError):
        pass