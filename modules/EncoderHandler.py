# modules/EncoderHandler.py

from utils.Logger import Logger
from modules.Session import get_session


class EncoderHandler:

    @staticmethod
    def encode_payload(case_name: str, data: dict) -> bytes:
        """
        Encode a packet using the parsed DSL definition.
        Mirrors DecoderHandler.decode_payload, but in reverse.
        """

        session = get_session()

        if "definition" not in session or not session["definition"]:
            raise RuntimeError("No parsed DSL definition available for encode")

        # Spara indata i session.values
        session["values"] = dict(data)

        output = bytearray()

        try:
            EncoderHandler._encode_nodes(
                session["definition"]["data"], session, output
            )
        except Exception as e:
            Logger.error(f"Failed to encode {case_name}: {e}")
            raise

        return bytes(output)

    # ------------------------------------------------------------------

    @staticmethod
    def _encode_nodes(nodes, session, output: bytearray):
        """
        Rekursivt encode av alla nodtyper:
           field / loop / group / skip
        """

        for node in nodes:
            ntype = node["type"]

            if ntype == "field":
                EncoderHandler._encode_field(node, session, output)

            elif ntype == "loop":
                count_expr = node["count"]         # t.ex. "€num_items"
                count = EncoderHandler._resolve_value(session, count_expr)
                for _ in range(count):
                    EncoderHandler._encode_nodes(node["children"], session, output)

            elif ntype == "group":
                EncoderHandler._encode_nodes(node["children"], session, output)

            elif ntype == "skip":
                output.extend(b"\x00" * node["amount"])

            else:
                Logger.warning(f"Unknown node type during encode: {ntype}")

    # ------------------------------------------------------------------

    @staticmethod
    def _encode_field(node, session, output: bytearray):
        """
        Encode av ett enskilt fält.
        Format:
            B     byte
            H     uint16
            I     uint32
            Ns    fixed N string/byte array
            sM    nullterminerad string
            sMU   exakt byte-array
        """

        fmt = node["fmt"]
        name = node["name"]

        value = EncoderHandler._resolve_value(session, name)

        # ---- Integers ----
        if fmt == "B":
            output.append(value & 0xFF)
            return

        if fmt == "H":
            output.extend(value.to_bytes(2, "little"))
            return

        if fmt == "I":
            output.extend(value.to_bytes(4, "little"))
            return

        # ---- Fixed-size byte/string: "32s" ----
        if fmt.endswith("s") and fmt[:-1].isdigit():
            size = int(fmt[:-1])
            raw = value if isinstance(value, (bytes, bytearray)) else value.encode()
            raw = raw[:size].ljust(size, b"\x00")
            output.extend(raw)
            return

        # ---- sM: nullterminerad ----
        if fmt == "sM":
            raw = value.encode() if isinstance(value, str) else value
            output.extend(raw)
            output.append(0)
            return

        # ---- sMU: raw bytes exakt ----
        if fmt == "sMU":
            raw = value if isinstance(value, (bytes, bytearray)) else value.encode()
            output.extend(raw)
            return

        raise RuntimeError(f"Unsupported encode format: {fmt}")

    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_value(session, name):
        """
        Hämtar DSL-värde.
        - Direkta namn → session['values'][name]
        - Expressions som €field → session['values'][field]
        """

        if isinstance(name, int):
            return name

        if isinstance(name, str):
            if name.startswith("€"):
                ref = name[1:]
                return session["values"].get(ref)

            return session["values"].get(name)

        raise RuntimeError(f"Cannot resolve DSL value: {name}")