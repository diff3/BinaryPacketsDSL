class LineEditor:
    def __init__(self, io, prompt=b"> ", completer=None):
        self.io = io
        self.prompt = prompt
        self.completer = completer

        self.buffer = []
        self.cursor = 0

        self.history = []
        self.history_index = None
        self.draft = []

    # ----------------------------
    # Rendering
    # ----------------------------

    def _render(self):
        out = bytearray()

        # CR + clear line
        out += b"\r\x1b[2K"

        # prompt + buffer
        out += self.prompt
        out += "".join(self.buffer).encode()

        # move cursor back if needed
        back = len(self.buffer) - self.cursor
        if back > 0:
            out += f"\x1b[{back}D".encode()

        self.io.write(bytes(out))

    def _set_buffer(self, text):
        self.buffer = list(text)
        self.cursor = len(self.buffer)
        self._render()

    # ----------------------------
    # Main loop
    # ----------------------------

    def _split_tokens(self):
        text = "".join(self.buffer[:self.cursor])
        if " " not in text:
            return "", text
        base, _, prefix = text.rpartition(" ")
        return base + " ", prefix


    def read_line(self):
        self.buffer = []
        self.cursor = 0
        self.history_index = None
        self.draft = []

        self.io.write(self.prompt)

        while True:
            ch = self.io.read_byte()
            if ch is None:
                return None

            # ENTER
            if ch in (b"\r", b"\n"):
                self.io.write(b"\r\n")
                line = "".join(self.buffer)
                if line:
                    self.history.append(line)
                return line

            # BACKSPACE
            if ch in (b"\x7f", b"\b"):
                if self.cursor > 0:
                    self.buffer.pop(self.cursor - 1)
                    self.cursor -= 1
                    self._render()
                continue

            # ESC sequences
            if ch == b"\x1b":
                b2 = self.io.read_byte()
                if b2 != b"[":
                    # lone ESC
                    self.buffer = []
                    self.cursor = 0
                    self._render()
                    continue

                b3 = self.io.read_byte()
                if b3 == b"D" and self.cursor > 0:        # left
                    self.cursor -= 1
                elif b3 == b"C" and self.cursor < len(self.buffer):  # right
                    self.cursor += 1
                elif b3 == b"A":                          # up
                    self._history_up()
                elif b3 == b"B":                          # down
                    self._history_down()

                self._render()
                continue

            # TAB
            if ch == b"\t" and self.completer:
                before = "".join(self.buffer[:self.cursor])  # 👈 viktigt: före cursor
                base, prefix = self._split_tokens()

                matches = self.completer(before)

                # 👇 Specialfall: exact match av kommando (t.ex. "routes")
                # Då vill vi gå ner en nivå ("routes " -> ["show"])
                if (
                    len(matches) == 1
                    and prefix
                    and matches[0] == prefix
                    and not before.endswith(" ")
                ):
                    descended = self.completer(before + " ")
                    if descended:
                        base = before + " "
                        prefix = ""
                        matches = descended

                if len(matches) == 1:
                    completed = base + matches[0] + " "
                    self._set_buffer(completed)

                elif len(matches) > 1:
                    self.io.write(b"\r\n")
                    for m in matches:
                        self.io.write(m.encode() + b"\r\n")
                    self._render()

                continue

            # Printable
            try:
                c = ch.decode()
            except Exception:
                continue

            if c.isprintable():
                self.buffer.insert(self.cursor, c)
                self.cursor += 1
                self._render()

    # ----------------------------
    # History helpers
    # ----------------------------

    def _history_up(self):
        if not self.history:
            return
        if self.history_index is None:
            self.draft = self.buffer.copy()
            self.history_index = len(self.history) - 1
        elif self.history_index > 0:
            self.history_index -= 1
        self._set_buffer(self.history[self.history_index])

    def _history_down(self):
        if self.history_index is None:
            return
        if self.history_index < len(self.history) - 1:
            self.history_index += 1
            self._set_buffer(self.history[self.history_index])
        else:
            self.history_index = None
            self._set_buffer("".join(self.draft))