#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct
import copy
import zlib
import re
import ast

from modules.dsl.Processor import load_case
from modules.dsl.NodeTreeParser import NodeTreeParser
from modules.dsl.Session import get_session
from modules.dsl.ModifierMapping import ModifierInterPreter
from utils.ConfigLoader import ConfigLoader
from modules.dsl.bitsHandler import BitWriter
from utils.Logger import Logger


def preprocess_condition(expr: str) -> str:
    """
    Minimal normalisering av DSL-villkor:
    - tar bort '€'
    - gör foo[i].bar → foo[i]["bar"]
    """
    if not isinstance(expr, str):
        return expr

    e = expr.replace("€", "")

    e = re.sub(r"(\w+\[[^\]]+\])\.(\w+)", r'\1["\2"]', e)

    return e


def _split_print_args(expr: str) -> list[str]:
    if not isinstance(expr, str):
        return []
    s = expr.strip()
    if not s:
        return []
    parts = []
    buf = []
    depth = 0
    in_str = False
    quote = ""
    escape = False
    for ch in s:
        if in_str:
            buf.append(ch)
            if escape:
                escape = False
                continue
            if ch == "\\":
                escape = True
                continue
            if ch == quote:
                in_str = False
            continue
        if ch in ("'", '"'):
            in_str = True
            quote = ch
            buf.append(ch)
            continue
        if ch in "([{":
            depth += 1
            buf.append(ch)
            continue
        if ch in ")]}":
            depth = max(0, depth - 1)
            buf.append(ch)
            continue
        if ch == "," and depth == 0:
            part = "".join(buf).strip()
            if part:
                parts.append(part)
            buf = []
            continue
        buf.append(ch)
    if buf:
        part = "".join(buf).strip()
        if part:
            parts.append(part)
    return parts


def _eval_print_expr(expr: str, context: dict):
    if not isinstance(expr, str) or not expr.strip():
        return ""
    expr_eval = preprocess_condition(expr.strip())
    ctx = dict(context or {})

    def eval_ast(node):
        if isinstance(node, ast.Expression):
            return eval_ast(node.body)
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Num):
            return node.n
        if hasattr(ast, "Str") and isinstance(node, ast.Str):
            return node.s
        if isinstance(node, ast.Name):
            val = ctx.get(node.id, 0)
            return 0 if val is None else val
        if isinstance(node, ast.BinOp):
            left = eval_ast(node.left)
            right = eval_ast(node.right)
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Mult):
                return left * right
            if isinstance(node.op, ast.Div):
                return left / right
            if isinstance(node.op, ast.Mod):
                return left % right
            raise ValueError(f"Unsupported operator: {type(node.op).__name__}")
        if isinstance(node, ast.UnaryOp):
            val = eval_ast(node.operand)
            if isinstance(node.op, ast.UAdd):
                return +val
            if isinstance(node.op, ast.USub):
                return -val
            raise ValueError(f"Unsupported unary operator: {type(node.op).__name__}")
        if isinstance(node, ast.Subscript):
            target = eval_ast(node.value)
            slc = eval_ast(node.slice)
            return target[slc]
        if isinstance(node, ast.Slice):
            lower = eval_ast(node.lower) if node.lower is not None else None
            upper = eval_ast(node.upper) if node.upper is not None else None
            step = eval_ast(node.step) if node.step is not None else None
            return slice(lower, upper, step)
        if hasattr(ast, "Index") and isinstance(node, ast.Index):
            return eval_ast(node.value)
        if isinstance(node, ast.List):
            return [eval_ast(elt) for elt in node.elts]
        if isinstance(node, ast.Tuple):
            return tuple(eval_ast(elt) for elt in node.elts)
        if isinstance(node, ast.Dict):
            return {eval_ast(k): eval_ast(v) for k, v in zip(node.keys, node.values)}
        raise ValueError(f"Unsupported expression node: {type(node).__name__}")

    tree = ast.parse(expr_eval, mode="eval")
    return eval_ast(tree)


def _log_print_message(level: str, msg: str):
    lvl = (level or "debug").strip().lower()
    if lvl in ("info", "i"):
        Logger.info(msg)
    elif lvl in ("warn", "warning", "w"):
        Logger.warning(msg)
    elif lvl in ("error", "err", "e"):
        Logger.error(msg)
    elif lvl in ("success", "ok", "s"):
        Logger.success(msg)
    elif lvl in ("anticheat", "anti", "a"):
        Logger.anticheat(msg)
    elif lvl in ("script", "sc"):
        Logger.script(msg)
    else:
        Logger.debug(msg)

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
        expansion = cfg.get("expansion")
        version = cfg["version"]

        case_name, def_lines, _, expected, _ = load_case(
            program,
            version,
            def_name,
            expansion=expansion,
        )

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
            # Auto-fill loop counters from list lengths when count_from references €foo
            EncoderHandler._autofill_loop_counts(nodes, fields)
            flat = EncoderHandler._flatten_blocks(nodes)
            flat = EncoderHandler._expand_loops(flat, fields)
            cleaned = EncoderHandler._cleanup(flat, fields)
            return EncoderHandler._encode_cleaned(cleaned, fields, endian, buffers=None, buffer_seq={})

        return encode

    # ------------------------------------------------------------------
    # 1. FLATTEN block nodes
    # ------------------------------------------------------------------

    @staticmethod
    def _autofill_loop_counts(nodes, fields):
        """If a loop count references €foo and foo is missing/zero in fields but the target list exists,
        set fields[foo] = len(list). Recurses into child nodes.
        """
        for n in nodes:
            if getattr(n, "interpreter", None) == "loop":
                count_expr = getattr(n, "count_from", "")
                target = getattr(n, "target", None)
                if isinstance(count_expr, str) and count_expr.startswith("€") and isinstance(target, str):
                    key = count_expr.lstrip("€")
                    items = fields.get(target)
                    if isinstance(items, (list, tuple)):
                        fields[key] = len(items)
                children = getattr(n, "children", []) or []
                if children:
                    EncoderHandler._autofill_loop_counts(children, fields)
            else:
                children = getattr(n, "children", []) or []
                if children:
                    EncoderHandler._autofill_loop_counts(children, fields)

    @staticmethod

    @staticmethod
    def _resolve_ref(expr, fields, local_ctx=None):
        """Resolve a simple €ref or €list[i].attr using provided contexts."""
        if not isinstance(expr, str):
            return None
        ctx = local_ctx or {}
        m = re.fullmatch(r"(\w+)\[i\]\.(\w+)", expr)
        if m:
            base, attr = m.groups()
            try:
                idx = int(ctx.get("i", 0))
            except Exception:
                idx = 0
            lst = fields.get(base)
            if isinstance(lst, (list, tuple)) and 0 <= idx < len(lst):
                item = lst[idx]
                if isinstance(item, dict) and attr in item:
                    return item.get(attr)
        if expr in ctx:
            return ctx.get(expr)
        return fields.get(expr)

    @staticmethod
    def _should_emit(node) -> bool:
        """
        Decide if a node should produce payload bytes.
        Rules:
          - '-' prefix sets payload=False → never emit
          - '+' prefix forces emit
          - otherwise only fields with has_io=True are emitted
        """
        if getattr(node, "payload", True) is False and getattr(node, "visibility_prefix", None) != "+":
            return False
        if getattr(node, "visibility_prefix", None) == "+":
            return True
        return bool(getattr(node, "has_io", True))

    @staticmethod
    def _resolve_length_expr(expr, fields, local_ctx=None):
        if expr is None:
            return None
        cleaned = str(expr).strip()
        if cleaned.endswith("B"):
            cleaned = cleaned[:-1]
        if not cleaned:
            return None
        if cleaned.startswith("€"):
            cleaned = cleaned[1:]
        try:
            return int(cleaned)
        except Exception:
            pass
        val = EncoderHandler._resolve_ref(cleaned, fields, local_ctx or fields)
        try:
            return int(val)
        except Exception:
            return None

    @staticmethod
    def _coerce_to_bytes(value, size=None):
        if value is None:
            value = b""
        if isinstance(value, (bytes, bytearray)):
            b = bytes(value)
        elif isinstance(value, str):
            v = value.strip()
            try:
                if re.fullmatch(r"[0-9a-fA-F]+", v) and len(v) % 2 == 0:
                    b = bytes.fromhex(v)
                else:
                    b = v.encode("utf-8")
            except Exception:
                b = value.encode("utf-8")
        elif isinstance(value, int):
            length = size or 1
            b = int(value).to_bytes(length, "little", signed=False)
        elif isinstance(value, (list, tuple)):
            try:
                b = bytes(int(x) & 0xFF for x in value)
            except Exception:
                b = bytes()
        else:
            try:
                b = bytes(value)
            except Exception:
                b = bytes(str(value), "utf-8")

        if size:
            if len(b) < size:
                b = b.ljust(size, b"\x00")
            else:
                b = b[:size]
        return b

    @staticmethod
    def _parse_decimal_concat(s: str, count: int) -> list[int] | None:
        """
        Parse a string of digits as a concatenation of decimal byte values (0-255),
        producing exactly `count` numbers if possible.
        """
        memo = {}

        def backtrack(idx, used):
            key = (idx, used)
            if key in memo:
                return memo[key]

            if used > count:
                memo[key] = None
                return None
            if used == count:
                memo[key] = [] if idx == len(s) else None
                return memo[key]
            if idx >= len(s):
                memo[key] = None
                return None

            for span in (3, 2, 1):
                nxt = idx + span
                if nxt > len(s):
                    continue
                part = s[idx:nxt]
                try:
                    val = int(part)
                except Exception:
                    continue
                if 0 <= val <= 255:
                    tail = backtrack(nxt, used + 1)
                    if tail is not None:
                        memo[key] = [val] + tail
                        return memo[key]

            memo[key] = None
            return None

        return backtrack(0, 0)

    @staticmethod
    def _buffer_from_fields(name, fields, size_hint=0):
        val = fields.get(name)
        buf: list[int | None] = []

        # Collect per-index fallbacks like digest[0], digest[3]
        index_vals = {}
        pattern = re.compile(rf"^{re.escape(name)}\[(\d+)\]$")
        for k, v in fields.items():
            m = pattern.match(str(k))
            if m:
                try:
                    idx = int(m.group(1))
                except Exception:
                    continue
                index_vals[idx] = v

        def to_byte(x):
            if x is None:
                return None
            if isinstance(x, int):
                return x & 0xFF
            if isinstance(x, (bytes, bytearray)):
                return x[0] if len(x) > 0 else 0
            if isinstance(x, str):
                try:
                    return int(x, 0) & 0xFF
                except Exception:
                    try:
                        b = bytes.fromhex(x)
                        return b[0] if b else 0
                    except Exception:
                        return 0
            try:
                return int(x) & 0xFF
            except Exception:
                return None

        if val is None and index_vals:
            max_idx = max(index_vals.keys())
            buf = [None] * max(max_idx + 1, size_hint)
            for idx, v in index_vals.items():
                byte_val = to_byte(v)
                if idx >= len(buf):
                    buf.extend([None] * (idx + 1 - len(buf)))
                buf[idx] = byte_val

        elif val is None:
            buf = [None] * max(0, size_hint)
        elif isinstance(val, (bytes, bytearray)):
            buf = [b for b in val]
        elif isinstance(val, str):
            parsed = None
            if val.isdigit() and size_hint:
                parsed = EncoderHandler._parse_decimal_concat(val, size_hint)
            if parsed is not None:
                buf = parsed
            else:
                try:
                    b = bytes.fromhex(val)
                except Exception:
                    b = val.encode("utf-8")
                buf = [x for x in b]
        elif isinstance(val, list):
            buf = [to_byte(x) for x in val]
        else:
            try:
                buf = [to_byte(x) for x in val]
            except Exception:
                buf = [None] * max(0, size_hint)

        if size_hint and len(buf) < size_hint:
            buf.extend([None] * (size_hint - len(buf)))
        return buf

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

            list_name = getattr(n, "target", None)
            items = fields.get(list_name, [])

            if not isinstance(items, (list, tuple)):
                raise TypeError(f"Loop '{list_name}' expects list/tuple, got {type(items)}")

            count_expr = getattr(n, "count_from", "0")
            if isinstance(count_expr, str):
                expr = count_expr.strip()
                if expr == "until_end":
                    # encode-sida: använd hela listan vi fått in
                    count = len(items)
                else:
                    key = expr.lstrip("€")
                    if "." in key or "[" in key:
                        val = EncoderHandler._resolve_ref(key, fields)
                        if val is None:
                            count = len(items)
                        else:
                            count = int(val or 0)
                    else:
                        if key not in fields:
                            count = len(items)
                            fields[key] = count
                        else:
                            count = fields.get(key, 0)
            else:
                count = int(count_expr or 0)

            if len(items) < count:
                raise ValueError(
                    f"Loop '{list_name}' expects {count} items, got {len(items)}"
                )

            for i in range(count):
                entry = items[i]
                if not isinstance(entry, dict):
                    raise TypeError(
                        f"Loop '{list_name}' item #{i} must be dict, got {type(entry)}"
                    )

                for child in n.children:
                    clone = copy.deepcopy(child)

                    setattr(clone, "__loop_entry", entry)
                    setattr(clone, "__loop_index", i)

                    if getattr(clone, "interpreter", None) == "if":
                        expanded.append(clone)
                        continue

                    cname = getattr(clone, "name", None)
                    if cname not in entry:
                        raise KeyError(f"Loop '{list_name}' item #{i} missing field '{cname}'")

                    clone.value = entry[cname]
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

            # ------------------------------
            # Bygg lokalt context
            # ------------------------------
            local_ctx = dict(context or {})

            loop_entry = getattr(n, "__loop_entry", None)
            loop_idx = getattr(n, "__loop_index", None)

            if isinstance(loop_entry, dict):
                local_ctx.update(loop_entry)

            if loop_idx is not None:
                local_ctx["i"] = loop_idx

            # koppla värdet om det finns i contextet
            if name and name in local_ctx:
                n.value = local_ctx[name]
                setattr(n, "__is_loop_child", True)

            should_emit = EncoderHandler._should_emit(n)
            if getattr(n, "optional", False) and name:
                if name in local_ctx:
                    if local_ctx.get(name) is None:
                        continue
                elif getattr(n, "value", None) is None:
                    continue

            if interp == "print":
                expr = getattr(n, "print_expr", "") or ""
                level = getattr(n, "print_level", "") or "debug"
                parts = _split_print_args(expr)
                values = []
                for part in parts:
                    try:
                        val = _eval_print_expr(part, local_ctx)
                    except Exception:
                        val = part
                    values.append(str(val))
                msg = " ".join(values) if values else ""
                _log_print_message(level, msg)
                continue

            # ============================================================
            #  IF-BLOCK – med stöd för loop-villkor
            # ============================================================
            if interp == "if":
                cond_raw = getattr(n, "condition", "") or ""
                cond = preprocess_condition(cond_raw)

                # kan inte evalueras → skippa hela blocket
                if ("chars_meta" in cond or "[i]" in cond) and "i" not in local_ctx:
                    continue

                branch = None
                try:
                    if cond and EncoderHandler._eval_condition(cond, local_ctx):
                        branch = getattr(n, "true_branch", [])
                    else:
                        elifs = getattr(n, "elif_branches", None) or []
                        for c_raw, bnodes in elifs:
                            c = preprocess_condition(c_raw or "")
                            try:
                                if EncoderHandler._eval_condition(c, local_ctx):
                                    branch = bnodes
                                    break
                            except Exception:
                                continue
                        if branch is None:
                            branch = getattr(n, "false_branch", []) or []
                except Exception:
                    # kunde ej evalueras → skippa blocket helt
                    continue

                # recurse
                cleaned.extend(EncoderHandler._cleanup(branch or [], local_ctx))
                continue
            # ============================================================
            # NESTADE LOOPAR (t.ex. equipment inne i chars-loop)
            # ============================================================
            if interp == "loop":
                count_expr = getattr(n, "count_from", "0")

                # Räkna ut antal iterationer
                if isinstance(count_expr, str):
                    expr = count_expr.strip()
                    if expr == "until_end":
                        # ej stödd i encodern ännu – hoppa över
                        continue
                    elif expr.startswith("€"):
                        key = expr.lstrip("€")
                        merged_ctx = dict(context or {})
                        merged_ctx.update(local_ctx)
                        if "." in key or "[" in key:
                            val = EncoderHandler._resolve_ref(key, merged_ctx, merged_ctx)
                        else:
                            val = merged_ctx.get(key, 0)
                        try:
                            count = int(val or 0)
                        except Exception:
                            count = 0
                    else:
                        try:
                            count = int(expr or 0)
                        except Exception:
                            count = 0
                else:
                    try:
                        count = int(count_expr or 0)
                    except Exception:
                        count = 0

                if count <= 0:
                    continue

                list_name = getattr(n, "target", None)
                items = None

                if isinstance(list_name, str) and list_name:
                    # Först: lokalt loop-entry-context (t.ex. chars[i].equipment)
                    if isinstance(local_ctx, dict) and list_name in local_ctx:
                        items = local_ctx[list_name]
                    # Fallback: globalt fields-context
                    elif isinstance(context, dict) and list_name in context:
                        items = context[list_name]

                if not isinstance(items, (list, tuple)):
                    raise TypeError(f"Nested loop '{name}' expects list/tuple for '{list_name}', got {type(items)}")

                if count <= 0:
                    count = len(items)

                if count <= 0:
                    continue

                if len(items) < count:
                    raise ValueError(
                        f"Nested loop '{name}' expects {count} items in '{list_name}', got {len(items)}"
                    )

                for idx in range(count):
                    entry = items[idx]
                    if not isinstance(entry, dict):
                        raise TypeError(
                            f"Nested loop '{name}' item #{idx} in '{list_name}' must be dict, got {type(entry)}"
                        )

                    # Bygg per-entry context: ärv lokalt context + entry-data
                    inner_ctx = dict(local_ctx)
                    inner_ctx.update(entry)

                    for child in n.children:
                        clone = copy.deepcopy(child)
                        # recurse så att if/dynamic/etc hanteras som vanligt
                        cleaned.extend(EncoderHandler._cleanup([clone], inner_ctx))

                continue

            # ============================================================
            # SPECIALNODER
            # ============================================================
            if interp == "buffer_alloc":
                cleaned.append((n, name, "__buffer_alloc__"))
                continue

            if interp == "buffer_io":
                if not should_emit:
                    continue
                cleaned.append((n, name, "__buffer_io__"))
                continue

            if interp == "buffer_assign":
                if not should_emit:
                    continue
                cleaned.append((n, name, "__buffer_assign__"))
                continue

            if interp == "slice":
                if not should_emit:
                    continue
                cleaned.append((n, name, "__slice__"))
                continue

            if interp == "bitmask":
                if not should_emit:
                    continue
                cleaned.append((n, None, "__bitmask__"))
                continue

            if interp == "padding":
                if not should_emit:
                    continue
                cleaned.append((n, None, "__padding__"))
                continue

            if interp == "seek":
                if not should_emit:
                    continue
                cleaned.append((n, None, "__seek__"))
                continue

            # ============================================================
            # BITFÄLT – flaggas som __bits__ och tas om hand i _encode_cleaned
            # ============================================================
            if interp == "bits" or fmt == "bits":
                if not should_emit:
                    continue
                cleaned.append((n, name, "__bits__"))
                continue

            if name == "endian":
                # endian hanteras bara logiskt, inget faktiskt fält
                continue

            if interp in ("var", "slice", "append"):
                # var/slice/append är bara logik, inte egna struct-fält
                continue

            if interp == "uncompress":
                if not should_emit:
                    continue
                cleaned.append((n, None, "__uncompress__"))
                continue

            if interp == "packed_guid":
                if not should_emit:
                    continue
                cleaned.append((n, None, "__packed_guid__"))
                continue

            if interp == "dynamic" and fmt and fmt.endswith("'s"):
                if not should_emit:
                    continue
                cleaned.append((n, name, "__dyn_str__"))
                continue

            if fmt == "R":
                if not should_emit:
                    continue
                cleaned.append((n, name, "__rest__"))
                continue

            if fmt is None:
                continue

            # ============================================================
            # NORMALA STRUCT-FORMAT
            # ============================================================
            base_fmt = fmt.split(",")[0].strip()

            if base_fmt == "IH":
                base_fmt = "I"

            if base_fmt.startswith("€") and base_fmt.endswith("s"):
                base_fmt = "s"

            if base_fmt.startswith("€"):
                base_fmt = base_fmt.lstrip("€")

            if not re.match(r"^\d*[xcbB?hHiIlLqQnNefdspPS]$", base_fmt) and base_fmt not in ("R",):
                # okänt / icke-struct-format → hoppa över
                continue

            if name == "_":
                underscore_counter += 1
                name = f"_{underscore_counter}"

            if not should_emit:
                continue

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
        """Apply encode modifiers used on *non-bit* fields."""
        if not mods:
            return value

        # ------------------------------------------------------------------
        # BITSAFETY: bitfält får inte modifieras av textmodifiers
        # ------------------------------------------------------------------
        # Om value är int → vi är i ett bitfält → ignorera allt utom Q (bytes)
        if isinstance(value, int):
            mods = [m for m in mods if m == "Q"]

        for mod in mods:
            if mod in ("E", "W"):
                continue
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
                value = ModifierInterPreter.to_string(value)
            elif mod == "Q":
                value = ModifierInterPreter.to_bytes(value)
            elif mod == "0":
                value = ModifierInterPreter.to_null_terminated(value)

        return value
    
    @staticmethod
    def _encode_cleaned(cleaned, fields, endian, buffers=None, buffer_seq=None):
        out = bytearray()
        bitwriter = BitWriter()
        buffers = buffers or {}

        def flush_bits_into_out():
            nonlocal bitwriter, out
            # flush till hel byte i BitWriter
            bitwriter.flush_to_byte()
            # hämta nuvarande bit-buffer
            bit_bytes = bitwriter.getvalue()
            if bit_bytes:
                out.extend(bit_bytes)
                # börja ny tom bitbuffer för nästa bit-block
                bitwriter = BitWriter()

        for entry in cleaned:
            # entry kan vara:
            # (node, name, fmt) eller (node, name, "__bits__", server_mods, encode_mods)
            if len(entry) == 3:
                node, name, fmt = entry
                server_mods = getattr(node, "modifiers", []) or []
                encode_mods = getattr(node, "encode_modifiers", []) or []
            elif len(entry) == 5:
                node, name, fmt, server_mods, encode_mods = entry
            else:
                raise RuntimeError(f"Unexpected cleaned entry: {entry!r}")

            # -----------------------------------------------------
            # BITFÄLT – skrivs via BitWriter
            # -----------------------------------------------------
            if fmt == "__bits__":
                bitlen = None
                is_le = False  # 'b' = little-endian bit-order, 'B' = MSB-first

                for m in server_mods:
                    m = str(m)
                    match = re.fullmatch(r"(\d+)([Bb])", m)
                    if match:
                        bitlen = int(match.group(1))
                        is_le = (match.group(2) == "b")
                        break

                if bitlen is None:
                    raise ValueError(f"Bitfield {name} saknar bitlängd i modifiers={server_mods}")

                val = fields.get(name, getattr(node, "value", 0))

                # Gör om till int på ett robust sätt
                if isinstance(val, (bytes, bytearray)):
                    val = int.from_bytes(val, "little", signed=False)
                elif isinstance(val, str):
                    try:
                        val = int(val, 0)
                    except Exception:
                        val = 0
                elif isinstance(val, (list, tuple)):
                    v = 0
                    for b in val:
                        v = (v << 1) | (1 if b else 0)
                    val = v

                try:
                    ival = int(val)
                except Exception:
                    ival = 0

                # välj rätt bit-ordning
                if is_le:
                    bitwriter.write_bits_le(ival, bitlen)
                else:
                    bitwriter.write_bits(ival, bitlen)

                continue

            # -----------------------------------------------------
            # ALLT SOM INTE ÄR BITAR → BYTE-ALIGNA & FLUSHA BITAR
            # -----------------------------------------------------
            flush_bits_into_out()

            # -----------------------------------------------------
            # SPECIALFORMAT
            # -----------------------------------------------------

            if fmt == "__buffer_alloc__":
                size_expr = getattr(node, "alloc_size_expr", None) or getattr(node, "format", "")
                size = EncoderHandler._resolve_length_expr(size_expr, fields, fields)
                try:
                    size = int(size or 0)
                except Exception:
                    size = 0
                size = max(0, size)
                buf_list = EncoderHandler._buffer_from_fields(node.name, fields, size)
                if len(buf_list) < size:
                    buf_list.extend([None] * (size - len(buf_list)))
                elif size and len(buf_list) > size:
                    buf_list = buf_list[:size]
                buffers[node.name] = buf_list
                continue

            if fmt == "__buffer_io__":
                buf_name = getattr(node, "buffer_name", node.name)
                start_idx = getattr(node, "index_start", 0) or 0
                end_idx = getattr(node, "index_end", start_idx) or start_idx
                default_len = max(1, end_idx - start_idx + 1)
                size_expr = getattr(node, "io_size_expr", None)
                size = EncoderHandler._resolve_length_expr(size_expr, fields, fields)
                try:
                    size = int(size) if size is not None else default_len
                except Exception:
                    size = default_len
                size = max(1, size)

                buf = buffers.get(buf_name)
                if buf is None:
                    buf = EncoderHandler._buffer_from_fields(buf_name, fields, start_idx + size)
                if len(buf) < start_idx + size:
                    buf.extend([None] * (start_idx + size - len(buf)))

                val = buf[start_idx] if start_idx < len(buf) else None
                if val is None:
                    val_int = 0
                elif isinstance(val, int):
                    val_int = val & 0xFF
                elif isinstance(val, (bytes, bytearray)) and len(val) > 0:
                    val_int = val[0]
                elif isinstance(val, str):
                    try:
                        val_int = int(val, 0) & 0xFF
                    except Exception:
                        val_int = 0
                else:
                    try:
                        val_int = int(val) & 0xFF
                    except Exception:
                        val_int = 0

                buf[start_idx] = val_int
                buffers[buf_name] = buf
                out.extend(bytes([val_int]))
                continue

            if fmt == "__buffer_assign__":
                buf_name = getattr(node, "buffer_name", node.name)
                start_idx = getattr(node, "index_start", 0) or 0
                end_idx = getattr(node, "index_end", start_idx) or start_idx
                try:
                    size = struct.calcsize(endian + (getattr(node, "format", "") or "B"))
                except struct.error:
                    size = EncoderHandler._resolve_length_expr(getattr(node, "io_size_expr", None), fields, fields) or 1
                size = max(1, int(size or 0))

                buf = buffers.get(buf_name)
                if buf is None:
                    buf = EncoderHandler._buffer_from_fields(buf_name, fields, start_idx + size)
                if len(buf) < start_idx + size:
                    buf.extend([None] * (start_idx + size - len(buf)))

                val = buf[start_idx] if start_idx < len(buf) else None
                if val is None:
                    val_int = 0
                elif isinstance(val, int):
                    val_int = val & 0xFF
                elif isinstance(val, (bytes, bytearray)) and len(val) > 0:
                    val_int = val[0]
                elif isinstance(val, str):
                    try:
                        val_int = int(val, 0) & 0xFF
                    except Exception:
                        val_int = 0
                else:
                    try:
                        val_int = int(val) & 0xFF
                    except Exception:
                        val_int = 0

                buf[start_idx] = val_int
                buffers[buf_name] = buf
                out.extend(bytes([val_int]))
                continue

            if fmt == "__uncompress__":
                child_nodes = EncoderHandler._flatten_blocks(node.children)
                child_nodes = EncoderHandler._expand_loops(child_nodes, fields)
                child_clean = EncoderHandler._cleanup(child_nodes, fields)
                chunk = EncoderHandler._encode_cleaned(child_clean, fields, endian, buffers, buffer_seq)
                comp = zlib.compress(chunk)
                out.extend(comp)
                continue

            if fmt == "__bitmask__":
                child_nodes = EncoderHandler._flatten_blocks(node.children)
                child_nodes = EncoderHandler._expand_loops(child_nodes, fields)
                child_clean = EncoderHandler._cleanup(child_nodes, fields)
                chunk = EncoderHandler._encode_cleaned(child_clean, fields, endian, buffers, buffer_seq)
                out.extend(chunk)
                continue

            if fmt == "__slice__":
                flush_bits_into_out()
                val = fields.get(name, getattr(node, "value", b""))
                b = EncoderHandler._coerce_to_bytes(val)

                expr = getattr(node, "slice_expr", "") or ""
                start = 0
                end = None

                def eval_part(s):
                    if not s:
                        return None
                    clean = s.replace("€", "").strip()
                    try:
                        return int(eval(clean, {}, fields))
                    except Exception:
                        pass
                    try:
                        return int(fields.get(clean, 0))
                    except Exception:
                        return None

                if ":" in expr:
                    left, right = expr.split(":", 1)
                    start = eval_part(left) or 0
                    end = eval_part(right)
                elif expr:
                    start = eval_part(expr) or 0

                if end is not None and end < start:
                    end = start
                if end is not None:
                    b = b[: max(0, end - start)]

                if start > len(out):
                    out.extend(b"\x00" * (start - len(out)))

                out.extend(b)
                continue

            if fmt == "__packed_guid__":
                # Support both minimal masks (only non-zero bytes) and explicit mask override.
                # Accepted input:
                #   - int guid
                #   - bytes guid (length <= 8)
                #   - tuple (guid, mask)
                #   - dict {"value"/"guid": <guid>, "mask": <mask>}
                value = fields.get(node.name, getattr(node, "value", None))
                mask_override = fields.get(f"{node.name}_mask") or getattr(node, "mask", None)

                # tuple variant: (guid, mask)
                if isinstance(value, tuple) and len(value) == 2:
                    value, mask_override = value

                # dict variant: {"value"/"guid": ..., "mask": ...}
                if isinstance(value, dict):
                    mask_override = value.get("mask", mask_override)
                    if "value" in value:
                        value = value["value"]
                    elif "guid" in value:
                        value = value["guid"]
                    else:
                        value = value.get("val", None)

                # Allow reuse of captured raw_data as fallback (e.g. encode_debug reference)
                if value is None and isinstance(getattr(node, "raw_data", None), (bytes, bytearray)):
                    raw_guid = getattr(node, "raw_data")
                    if raw_guid:
                        if mask_override is None:
                            mask_override = raw_guid[0]
                        mask_raw = int(mask_override) & 0xFF
                        payload = raw_guid[1:]
                        tmp = [0] * 8
                        pos = 0
                        for i in range(8):
                            if mask_raw & (1 << i) and pos < len(payload):
                                tmp[i] = payload[pos]
                                pos += 1
                        value = int.from_bytes(bytes(tmp), "little")

                if isinstance(value, (bytes, bytearray)):
                    guid_bytes = bytes(value).ljust(8, b"\x00")[:8]
                elif isinstance(value, int):
                    guid_bytes = value.to_bytes(8, "little", signed=False)
                else:
                    raise TypeError(f"packed_guid expects int or bytes for {node.name}")

                mask = None
                if mask_override is not None:
                    try:
                        mask = int(mask_override) & 0xFF
                    except Exception:
                        mask = None

                # Try to keep the original mask from raw_data when available
                if mask is None and isinstance(getattr(node, "raw_data", None), (bytes, bytearray)):
                    raw_guid = getattr(node, "raw_data")
                    if raw_guid:
                        mask = raw_guid[0]

                packed = bytearray()

                if mask is None:
                    # Minimal encoding: include only non-zero bytes
                    mask = 0
                    for i, b in enumerate(guid_bytes):
                        if b != 0:
                            mask |= (1 << i)
                            packed.append(b)
                else:
                    # Explicit mask: include bytes in ascending index order, even if zero
                    for i in range(8):
                        if mask & (1 << i):
                            packed.append(guid_bytes[i])

                out.append(mask)
                out.extend(packed)
                continue

            if fmt == "__padding__":
                size = getattr(node, "size", 0) or getattr(node, "value", 0) or 0
                out.extend(b"\x00" * size)
                continue

            if fmt == "__seek__":
                target = getattr(node, "offset", 0) or getattr(node, "value", 0) or 0
                if target > len(out):
                    out.extend(b"\x00" * (target - len(out)))
                continue

            if fmt == "__rest__":
                value = fields.get(name, getattr(node, "value", b""))
                if isinstance(value, str):
                    try:
                        value = bytes.fromhex(value)
                    except Exception:
                        value = value.encode("utf-8")
                if value is None:
                    value = b""
                out.extend(value)
                continue

            if fmt == "__dyn_str__":
                value = fields.get(name, getattr(node, "value", b"") or b"")
                if value is None:
                    value = b""
                if isinstance(value, str):
                    value = value.encode("utf-8")

                dep = getattr(node, "depends_on", "") or ""
                if dep.startswith("€"):
                    dep = dep[1:]

                expected_len = fields.get(dep)
                try:
                    expected_len = int(expected_len)
                except Exception:
                    expected_len = len(value)
                    fields[dep] = expected_len

                if expected_len < 0:
                    expected_len = 0

                if len(value) < expected_len:
                    value = value.ljust(expected_len, b"\x00")
                else:
                    value = value[:expected_len]

                out.extend(value)
                continue

            # --------------------------------------------------
            # NORMALA STRUCT-FÄLT
            # --------------------------------------------------
            if getattr(node, "__is_loop_child", False):
                value = node.value
            else:
                value = fields.get(name, getattr(node, "value", None))

            mods_enc = getattr(node, "encode_modifiers", []) or getattr(node, "modifiers", []) if hasattr(node, "modifiers") else []
            value = EncoderHandler._apply_modifiers_encode(value, mods_enc)

            if fmt == "S":
                if isinstance(value, str):
                    value = value.encode("ascii")
                out.extend(value)
                out.append(0)
                continue

            if fmt.endswith("s"):
                if value is None:
                    value = b""
                if "W" in mods_enc:
                    import socket
                    if isinstance(value, str):
                        value = socket.inet_aton(value)
                if isinstance(value, str):
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

            if value is None:
                value = 0

            count = None
            repeat_match = re.match(r"^(\d+)([xcbB?hHiIlLqQnNefdspP])$", fmt)
            if repeat_match:
                count = int(repeat_match.group(1))
                base_fmt = repeat_match.group(2)

            if count and count > 1:
                if isinstance(value, (bytes, bytearray)):
                    value = list(value)
                elif not isinstance(value, (list, tuple)):
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
                out.extend(struct.pack(endian + fmt, value))

        # sista chans: om paketet slutar med bitar
        flush_bits_into_out()

        return bytes(out)
