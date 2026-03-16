import sys
import termios
import tty


LEFT = "\x1b[D"
RIGHT = "\x1b[C"
UP = "\x1b[A"
DOWN = "\x1b[B"


class LineEditor:
    def __init__(self, prompt="> ", completer=None, io=None):
        self.prompt = prompt
        self.completer = completer
        self.io = io
        self.buffer = []
        self.cursor = 0

        # History
        self.history = []
        self.history_index = None
        self.draft = []

    def _split_tokens(self):
        text = "".join(self.buffer[:self.cursor])
        if " " not in text:
            return "", text
        base, _, prefix = text.rpartition(" ")
        return base + " ", prefix
    
    def _redraw(self):
        # Clear entire line
        sys.stdout.write("\r\x1b[2K")

        # Write prompt + full buffer
        sys.stdout.write(self.prompt + "".join(self.buffer))

        # Move cursor back to correct position
        back = len(self.buffer) - self.cursor
        if back > 0:
            sys.stdout.write(f"\x1b[{back}D")

        sys.stdout.flush()

    def _set_buffer(self, text):
        self.buffer = list(text)
        self.cursor = len(self.buffer)
        self._redraw()

    def read_line(self):
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)

        # Reset per-line state
        self.buffer = []
        self.cursor = 0
        self.history_index = None
        self.draft = []

        try:
            tty.setraw(fd)
            sys.stdout.write(self.prompt)
            sys.stdout.flush()

            while True:
                ch = sys.stdin.read(1)

                # ENTER
                if ch in ("\r", "\n"):
                    line = "".join(self.buffer)
                    sys.stdout.write("\n")

                    if line:
                        self.history.append(line)

                    return line

                # Escape sequences
                if ch == "\x1b":
                    seq = ch + sys.stdin.read(2)

                    if seq == LEFT and self.cursor > 0:
                        self.cursor -= 1
                        self._redraw()

                    elif seq == RIGHT and self.cursor < len(self.buffer):
                        self.cursor += 1
                        self._redraw()

                    elif seq == UP:
                        if self.history:
                            if self.history_index is None:
                                self.draft = self.buffer.copy()
                                self.history_index = len(self.history) - 1
                            elif self.history_index > 0:
                                self.history_index -= 1

                            self._set_buffer(self.history[self.history_index])

                    elif seq == DOWN:
                        if self.history_index is not None:
                            if self.history_index < len(self.history) - 1:
                                self.history_index += 1
                                self._set_buffer(self.history[self.history_index])
                            else:
                                self.history_index = None
                                self._set_buffer("".join(self.draft))

                    continue

                # ESC or arrow keys
                if ch == "\x1b":
                    next1 = sys.stdin.read(1)

                    if next1 == "[":
                        next2 = sys.stdin.read(1)
                        seq = "\x1b[" + next2

                        if seq == LEFT and self.cursor > 0:
                            self.cursor -= 1
                            self._redraw()
                        elif seq == RIGHT and self.cursor < len(self.buffer):
                            self.cursor += 1
                            self._redraw()
                        elif seq == UP:
                            if self.history:
                                if self.history_index is None:
                                    self.draft = self.buffer.copy()
                                    self.history_index = len(self.history) - 1
                                elif self.history_index > 0:
                                    self.history_index -= 1
                                self._set_buffer(self.history[self.history_index])
                        elif seq == DOWN:
                            if self.history_index is not None:
                                if self.history_index < len(self.history) - 1:
                                    self.history_index += 1
                                    self._set_buffer(self.history[self.history_index])
                                else:
                                    self.history_index = None
                                    self._set_buffer("".join(self.draft))

                    else:
                        # ESC pressed alone → clear line
                        self.buffer = []
                        self.cursor = 0
                        self.history_index = None
                        self._redraw()

                    continue

                # Backspace
                if ch == "\x7f":
                    if self.cursor > 0:
                        self.buffer.pop(self.cursor - 1)
                        self.cursor -= 1
                        self._redraw()
                    continue
                # TAB
                if ch == "\t" and self.completer:
                    text = "".join(self.buffer)
                    matches = self.completer(text)

                    base, prefix = self._split_tokens()

                    if len(matches) == 1:
                        completed = base + matches[0] + " "
                        self._set_buffer(completed)

                    elif len(matches) > 1:
                        sys.stdout.write("\n")
                        sys.stdout.write("  ".join(matches))
                        sys.stdout.write("\n")
                        self._redraw()

                    continue

                # Printable char
                if ch.isprintable():
                    self.buffer.insert(self.cursor, ch)
                    self.cursor += 1
                    self._redraw()

        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)