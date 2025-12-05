#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct
import copy
import zlib
import re

from modules.Processor import load_case
from modules.NodeTreeParser import NodeTreeParser
from modules.Session import get_session
from modules.ModifierMapping import ModifierInterPreter
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
            cleaned = EncoderHandler._cleanup(flat, fields)
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
    def _cleanup(nodes, context=None):
        cleaned = []
        underscore_counter = 0

        for n in nodes:
            name = getattr(n, "name", None)
            fmt = getattr(n, "format", None)
            interp = getattr(n, "interpreter", None)

            if interp == "if":
                # Evaluate condition against fields; include matching branch only.
                context = context or {}
                cond = getattr(n, "condition", "")
                branch = None
                if cond and EncoderHandler._eval_condition(cond, context):
                    branch = getattr(n, "true_branch", [])
                else:
                    elifs = getattr(n, "elif_branches", None) or []
                    for c, bnodes in elifs:
                        if EncoderHandler._eval_condition(c, context):
                            branch = bnodes
                            break
                    if branch is None:
                        branch = getattr(n, "false_branch", []) or []

                # Propagate context to nested cleanup
                branch = branch or []
                cleaned.extend(EncoderHandler._cleanup(branch, context))
                continue
            if interp == "bitmask":
                cleaned.append((n, None, "__bitmask__"))
                continue
            if interp == "padding":
                cleaned.append((n, None, "__padding__"))
                continue
            if interp == "seek":
                cleaned.append((n, None, "__seek__"))
                continue
            if interp == "bits" or ("bits" in (n.modifiers if hasattr(n, "modifiers") else [])):
                cleaned.append((n, name, "__bits__"))
                continue

            # Släng rent DSL-skräp
            if name == "endian":
                continue
            if interp in ("var", "slice", "append"):
                continue
            if interp == "uncompress":
                cleaned.append((n, None, "__uncompress__"))
                continue
            if interp == "packed_guid":
                cleaned.append((n, None, "__packed_guid__"))
                continue
            if interp == "randseq":
                cleaned.append((n, None, "__randseq__"))
                continue
            if interp == "dynamic" and fmt and fmt.endswith("'s"):
                cleaned.append((n, name, "__dyn_str__"))
                continue
            if fmt == "R":
                cleaned.append((n, name, "__rest__"))
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
            # men låt dem passera så att vi kan encoda om värdet finns i fields
            if base_fmt.startswith("€"):
                base_fmt = base_fmt.lstrip("€")

            # Ogiltiga formatsträngar hoppar vi över här
            if not re.match(r"^\d*[xcbB?hHiIlLqQnNefdspPS]$", base_fmt) and base_fmt not in ("R",):
                continue

            # "_" i .def → mappar till _1, _2, ... i fields
            if name == "_":
                underscore_counter += 1
                name = f"_{underscore_counter}"

            cleaned.append((n, name, base_fmt))

        return cleaned

    # ------------------------------------------------------------------
    # Helpers for conditionals
    # ------------------------------------------------------------------
    @staticmethod
    def _eval_condition(cond: str, context: dict) -> bool:
        try:
            return bool(eval(cond, {}, context))
        except Exception:
            return False

    # ------------------------------------------------------------------
    # 4. ENCODE CLEANED NODES
    # ------------------------------------------------------------------
    @staticmethod
    def _apply_modifiers_encode(value, mods):
        """
        Minimal encoder-side support for common text modifiers so we mirror decode behavior.
        """
        if not mods:
            return value

        for mod in mods:
            if mod in ("E", "W"):
                continue  # handled elsewhere
            if mod == "M":
                value = ModifierInterPreter.to_mirror(value)
            elif mod == "N":
                value = ModifierInterPreter.to_capitalized(value)
            elif mod == "U":
                value = ModifierInterPreter.to_upper(value)
            elif mod == "u":
                value = ModifierInterPreter.to_lower(value)
            elif mod == "t":
                value = ModifierInterPreter.to_trimmed(value)
            elif mod == "s":
                # best-effort string decode if bytes
                value = ModifierInterPreter.to_string(value)
            elif mod == "Q":
                value = ModifierInterPreter.to_bytes(value)
            elif mod == "0":
                value = ModifierInterPreter.to_null_terminated(value)
        return value

    # ------------------------------------------------------------------
    # 4. ENCODE CLEANED NODES
    # ------------------------------------------------------------------
    @staticmethod
    def _encode_cleaned(cleaned, fields, endian):
        out = bytearray()
        bit_buf = 0
        bit_count = 0
        bit_mode_lsb = False

        def flush_bits():
            nonlocal bit_buf, bit_count, bit_mode_lsb
            if bit_count > 0:
                if bit_mode_lsb:
                    out.append(bit_buf & 0xFF)
                else:
                    out.append((bit_buf << (8 - bit_count)) & 0xFF)
                bit_buf = 0
                bit_count = 0

        for node, name, fmt in cleaned:

            # Align any pending bits when switching to non-bits field
            if fmt != "__bits__" and bit_count > 0:
                flush_bits()

            if fmt == "__uncompress__":
                flush_bits()
                child_nodes = EncoderHandler._flatten_blocks(node.children)
                child_nodes = EncoderHandler._expand_loops(child_nodes, fields)
                child_clean = EncoderHandler._cleanup(child_nodes, fields)
                chunk = EncoderHandler._encode_cleaned(child_clean, fields, endian)

                algo = (getattr(node, "algo", "") or "").lower()
                if algo != "zlib":
                    raise ValueError(f"Unsupported compress algo: {algo}")
                comp = zlib.compress(chunk)
                out.extend(comp)
                continue

            if fmt == "__randseq__":
                flush_bits()
                size = getattr(node, "count_from", 0)
                if isinstance(size, str):
                    size = size.lstrip("€")
                    size = fields.get(size, 0)
                size = int(size or 0)

                buf = bytearray(b"\x00" * max(0, size))

                for child in getattr(node, "children", []) or []:
                    cfmt = (getattr(child, "format", "") or "").strip()
                    if not cfmt:
                        continue

                    range_match = re.fullmatch(r"(\d+)-(\d+)'?", cfmt)
                    if range_match:
                        start = int(range_match.group(1))
                        end = int(range_match.group(2))
                        length = max(0, end - start)
                        val = fields.get(child.name, getattr(child, "value", 0))

                        val_bytes = b""
                        if isinstance(val, (bytes, bytearray)):
                            val_bytes = bytes(val)
                        elif isinstance(val, str):
                            try:
                                val_bytes = bytes.fromhex(val)
                            except Exception:
                                try:
                                    intval = int(val)
                                    val_bytes = intval.to_bytes(length or 1, "little", signed=False)
                                except Exception:
                                    val_bytes = val.encode("utf-8")
                        else:
                            try:
                                val_bytes = int(val).to_bytes(length or 1, "little", signed=False)
                            except Exception:
                                val_bytes = b""

                        if length and len(val_bytes) < length:
                            val_bytes = val_bytes.ljust(length, b"\x00")
                        if length:
                            buf[start:start + length] = val_bytes[:length]
                        continue

                    try:
                        positions = [int(x) for x in cfmt.split()]
                    except Exception:
                        continue

                    val = fields.get(child.name, getattr(child, "value", b""))
                    if isinstance(val, (bytes, bytearray)):
                        val_bytes = bytes(val)
                    elif isinstance(val, str):
                        try:
                            val_bytes = bytes.fromhex(val)
                        except Exception:
                            val_bytes = val.encode("utf-8")
                    elif isinstance(val, int):
                        val_bytes = val.to_bytes(max(1, len(positions)), "little", signed=False)
                    else:
                        try:
                            val_bytes = bytes(val)
                        except Exception:
                            val_bytes = b""

                    if len(val_bytes) < len(positions):
                        val_bytes = val_bytes.ljust(len(positions), b"\x00")

                    for idx, pos in enumerate(positions):
                        if 0 <= pos < len(buf):
                            buf[pos] = val_bytes[idx]

                out.extend(buf)

                # Special-case addon_data immediately following this randseq
                addon_data = fields.get("addon_data") or fields.get("addon_data_raw")
                if addon_data is not None:
                    if isinstance(addon_data, str):
                        try:
                            addon_bytes = bytes.fromhex(addon_data)
                        except Exception:
                            addon_bytes = addon_data.encode("utf-8")
                    elif isinstance(addon_data, (bytes, bytearray)):
                        addon_bytes = bytes(addon_data)
                    else:
                        addon_bytes = b""
                    out.extend(addon_bytes)
                continue

            if fmt == "__bitmask__":
                flush_bits()
                child_nodes = EncoderHandler._flatten_blocks(node.children)
                child_nodes = EncoderHandler._expand_loops(child_nodes, fields)
                child_clean = EncoderHandler._cleanup(child_nodes, fields)
                chunk = EncoderHandler._encode_cleaned(child_clean, fields, endian)
                out.extend(chunk)
                continue

            if fmt == "__packed_guid__":
                flush_bits()
                value = fields.get(node.name)
                if isinstance(value, bytes):
                    guid_bytes = value.ljust(8, b"\x00")[:8]
                elif isinstance(value, int):
                    guid_bytes = value.to_bytes(8, "little", signed=False)
                else:
                    raise TypeError(f"packed_guid expects int or bytes for {node.name}")

                mask = 0
                packed = bytearray()
                for i, b in enumerate(guid_bytes):
                    if b != 0:
                        mask |= (1 << i)
                        packed.append(b)

                out.append(mask)
                out.extend(packed)
                continue

            if fmt == "__padding__":
                flush_bits()
                size = getattr(node, "size", 0) or getattr(node, "value", 0) or 0
                out.extend(b"\x00" * size)
                continue

            if fmt == "__seek__":
                flush_bits()
                target = getattr(node, "offset", 0) or getattr(node, "value", 0) or 0
                if target > len(out):
                    out.extend(b"\x00" * (target - len(out)))
                continue

            if fmt == "__rest__":
                flush_bits()
                value = fields.get(name, getattr(node, "value", b"") or b"")
                if isinstance(value, str):
                    value = value.encode("utf-8")
                out.extend(value)
                continue

            if fmt == "__dyn_str__":
                flush_bits()
                value = fields.get(name, getattr(node, "value", b"") or b"")
                if isinstance(value, str):
                    value = value.encode("utf-8")
                dep = getattr(node, "depends_on", "") or ""
                if dep.startswith("€"):
                    dep = dep[1:]
                expected_len = fields.get(dep)
                if expected_len is None:
                    expected_len = len(value)
                    fields[dep] = expected_len
                value = value[:expected_len].ljust(expected_len, b"\x00")
                out.extend(value)
                continue

            if fmt == "__bits__":
                mods = getattr(node, "modifiers", []) or []
                bit_len = None
                direction = "B"
                for m in mods:
                    match = re.fullmatch(r"(\d+)([Bb])?", m)
                    if match:
                        bit_len = int(match.group(1))
                        if match.group(2):
                            direction = match.group(2)
                        break
                if bit_len is None:
                    continue

                bit_mode_lsb = direction == "b"
                val = fields.get(name, getattr(node, "value", 0))
                if isinstance(val, list):
                    v_int = 0
                    for b in val:
                        v_int = (v_int << 1) | int(b)
                    val = v_int

                if bit_mode_lsb:
                    for i in range(bit_len):
                        bit = (int(val) >> i) & 1
                        bit_buf |= (bit << bit_count)
                        bit_count += 1
                        if bit_count == 8:
                            out.append(bit_buf & 0xFF)
                            bit_buf = 0
                            bit_count = 0
                else:
                    for i in reversed(range(bit_len)):
                        bit = (int(val) >> i) & 1
                        bit_buf = (bit_buf << 1) | bit
                        bit_count += 1
                        if bit_count == 8:
                            out.append(bit_buf & 0xFF)
                            bit_buf = 0
                            bit_count = 0
                continue

            if getattr(node, "__is_loop_child", False):
                value = node.value
            else:
                value = fields.get(name, getattr(node, "value", None))

            mods_enc = getattr(node, "encode_modifiers", []) or getattr(node, "modifiers", []) if hasattr(node, "modifiers") else []
            value = EncoderHandler._apply_modifiers_encode(value, mods_enc)

            if fmt == "S":
                flush_bits()
                if isinstance(value, str):
                    value = value.encode("ascii")
                out.extend(value)
                out.append(0)
                continue

            if fmt.endswith("s"):
                flush_bits()
                if value is None:
                    value = b""
                if "W" in mods_enc:
                    import socket
                    if isinstance(value, str):
                        value = socket.inet_aton(value)
                if isinstance(value, str):
                    # Auto-convert hex strings to raw bytes if they look like hex
                    try:
                        if re.fullmatch(r"[0-9a-fA-F]+", value) and len(value) % 2 == 0:
                            value = bytes.fromhex(value)
                        else:
                            value = value.encode("utf-8")
                    except Exception:
                        value = value.encode("utf-8")
                try:
                    count = int(fmt[:-1]) if fmt[:-1] else None
                except ValueError:
                    count = None
                if count is not None:
                    value = struct.pack(endian + fmt, value)
                out.extend(value)
                continue

            mods = mods_enc

            # Special-case modifier for IPv4 strings → bytes
            if "W" in mods and isinstance(value, str):
                import socket
                value = socket.inet_aton(value)

            if "E" in mods:
                flush_bits()
                be = ModifierInterPreter.to_big_endian(value, fmt)
                out.extend(be)
                continue

            count = None
            base_fmt = fmt
            repeat_match = re.match(r"^(\d+)([xcbB?hHiIlLqQnNefdspP])$", fmt)
            if repeat_match:
                count = int(repeat_match.group(1))
                base_fmt = repeat_match.group(2)

            if count and count > 1:
                if value is None:
                    value = [0] * count
                if isinstance(value, (bytes, bytearray)):
                    value = list(value)
                if not isinstance(value, (list, tuple)):
                    if isinstance(value, int):
                        try:
                            value = list(value.to_bytes(count, "little"))
                        except Exception:
                            value = [value] * count
                    else:
                        value = [value] * count
                packed = struct.pack(endian + fmt, *value)
                out.extend(packed)
            else:
                if value is None:
                    value = 0
                out.extend(struct.pack(endian + fmt, value))

        flush_bits()
        return bytes(out)
