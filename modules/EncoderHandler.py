#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct
import copy

from modules.Processor import load_case
from modules.NodeTreeParser import NodeTreeParser
from modules.Session import get_session
from utils.ConfigLoader import ConfigLoader


class EncoderHandler:
    """
    High-level encoder:
    encode_packet("REALM_LIST_S", fields) → RAW BYTES
    """

    # ------------------------------------------------------------------
    # PUBLIC API
    # ------------------------------------------------------------------
    @staticmethod
    def encode_packet(def_name: str, fields: dict) -> bytes:
        """
        def_name: t.ex. "AUTH_LOGON_CHALLENGE_S"
        fields:   dict med fältnamn → värde
        """
        cfg = ConfigLoader.load_config()
        program = cfg["program"]
        version = cfg["version"]

        case_name, def_lines, _, expected = load_case(program, version, def_name)

        session = get_session()
        session.reset()

        # Bygger samma nod-träd som decodern använder, men utan raw_data
        NodeTreeParser.parse((case_name, def_lines, b"", expected))

        nodes = copy.deepcopy(session.fields)
        encode_fn = EncoderHandler._compile(nodes)
        return encode_fn(fields)

    # ------------------------------------------------------------------
    # INTERNAL COMPILER
    # ------------------------------------------------------------------
    @staticmethod
    def _compile(nodes):
        def encode(fields: dict) -> bytes:
            endian = "<"
            flat = EncoderHandler._flatten_blocks(nodes)
            flat = EncoderHandler._expand_loops(flat, fields)
            cleaned = EncoderHandler._cleanup(flat)
            return EncoderHandler._encode_cleaned(cleaned, fields, endian)

        return encode

    # ------------------------------------------------------------------
    # 1. FLATTEN block nodes
    # ------------------------------------------------------------------
    @staticmethod
    def _flatten_blocks(nodes):
        flat = []
        for n in nodes:
            if getattr(n, "interpreter", None) == "block":
                flat.extend(n.children)
            else:
                flat.append(n)
        return flat

    # ------------------------------------------------------------------
    # 2. EXPAND LOOPS
    # ------------------------------------------------------------------
    @staticmethod
    def _expand_loops(flat, fields):
        expanded = []

        for n in flat:
            if getattr(n, "interpreter", None) != "loop":
                expanded.append(n)
                continue

            count_key = n.count_from.lstrip("€")
            count = fields.get(count_key, 0)

            list_name = n.target
            items = fields.get(list_name, [])

            if not isinstance(items, (list, tuple)):
                raise TypeError(f"Loop '{list_name}' expects list/tuple, got {type(items)}")

            if len(items) < count:
                raise ValueError(
                    f"Loop '{list_name}' expects {count} items, got {len(items)}"
                )

            # expand children into real nodes
            for i in range(count):
                entry = items[i]
                if not isinstance(entry, dict):
                    raise TypeError(f"Loop '{list_name}' item #{i} must be dict, got {type(entry)}")

                for child in n.children:
                    clone = copy.deepcopy(child)
                    cname = clone.name
                    if cname not in entry:
                        raise KeyError(f"Loop '{list_name}' item #{i} missing field '{cname}'")

                    clone.value = entry[cname]
                    # markera som loop-barn så encodern vet att den ska använda node.value
                    setattr(clone, "__is_loop_child", True)
                    expanded.append(clone)

        return expanded

    # ------------------------------------------------------------------
    # 3. CLEANUP
    # ------------------------------------------------------------------
    @staticmethod
    def _cleanup(nodes):
        cleaned = []
        underscore_counter = 0

        for n in nodes:
            name = getattr(n, "name", None)
            fmt = getattr(n, "format", None)
            interp = getattr(n, "interpreter", None)

            # Släng rent DSL-skräp
            if name == "endian":
                continue
            if interp in ("var", "slice", "append"):
                continue
            if fmt is None:
                continue

            base_fmt = fmt.split(",")[0].strip()

            # Makron
            if base_fmt == "IH":
                base_fmt = "I"

            # dynamisk sträng-längd → "s" vid encode
            if base_fmt.startswith("€") and base_fmt.endswith("s"):
                base_fmt = "s"

            # helt dynamiska numeriska fält (t.ex. €size) skippar vi här
            if base_fmt.startswith("€") and not base_fmt.endswith("s"):
                continue

            # "_" i .def → mappar till _1, _2, ... i fields
            if name == "_":
                underscore_counter += 1
                name = f"_{underscore_counter}"

            cleaned.append((n, name, base_fmt))

        return cleaned

    # ------------------------------------------------------------------
    # 4. ENCODE CLEANED NODES
    # ------------------------------------------------------------------
    @staticmethod
    def _encode_cleaned(cleaned, fields, endian):
        out = bytearray()

        for node, name, fmt in cleaned:

            # LOOP-BARN: använd node.value direkt
            if getattr(node, "__is_loop_child", False):
                value = node.value
            else:
                # vanliga fält → hämta från fields
                if name not in fields:
                    continue
                value = fields[name]

            # C-string
            if fmt == "S":
                if isinstance(value, str):
                    value = value.encode("ascii")
                out.extend(value)
                out.append(0)
                continue

            # raw bytes or dynamic s
            if fmt.endswith("s"):
                if isinstance(value, str):
                    value = value.encode("ascii")
                out.extend(value)
                continue

            # numbers
            # numbers with optional endian override
            mods = getattr(node, "modifiers", [])

            if "E" in mods:
                # field wants big-endian regardless of packet endian
                be = ModifierInterPreter.to_big_endian(value, fmt)
                out.extend(be)
                continue

            # normal LE encode
            out.extend(struct.pack(endian + fmt, value))

        return bytes(out)