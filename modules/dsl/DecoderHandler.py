#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from modules.dsl.Session import BaseNode, get_session
from modules.dsl.Session import VariableNode
from modules.dsl.ModifierMapping import modifiers_operation_mapping
import ast
import struct
import json
from utils.Logger import Logger
import re
from modules.dsl.bitsHandler import BitState
from utils.DebugHelper import DebugHelper
import zlib


session = get_session()


class DecodeState:
    """
    Holds both the full decode context (including hidden/internal fields)
    and the public result that should be returned.
    """
    def __init__(self):
        self.all: dict = {}
        self.public: dict = {}
        self.buffer_visibility: dict[str, bool] = {}

    def remember_buffer(self, field, value, public_value=None):
        name = getattr(field, "name", None)
        if not name:
            return
        self.buffer_visibility[name] = DecoderHandler.is_visible(field)
        self.set_field(field, value, public_value=public_value)

    def update_buffer(self, name: str, buf, *, force_visible=None):
        if not name:
            return
        # Normalize to list of ints/None
        if isinstance(buf, (bytes, bytearray)):
            norm = [b for b in buf]
        elif isinstance(buf, list):
            norm = list(buf)
        else:
            try:
                norm = list(buf)
            except Exception:
                norm = []
        self.all[name] = norm
        session.scope.set(name, norm)

        visible = self.buffer_visibility.get(name, True)
        if force_visible is not None:
            visible = force_visible
        self.buffer_visibility[name] = visible

        if visible:
            self.public[name] = DecoderHandler.present_buffer(norm)
        else:
            self.public.pop(name, None)

    def set_field(self, field, value, *, public_value=None):
        name = getattr(field, "name", None)
        if not name or getattr(field, "ignore", False):
            return

        self.all[name] = value
        session.scope.set(name, value)

        if DecoderHandler.is_visible(field):
            if public_value is not None:
                self.public[name] = public_value
            else:
                self.public[name] = value
        else:
            self.public.pop(name, None)


def preprocess_condition(cond: str):
    """
    Normalize DSL conditions to Python-like expressions:
    - remove '€'
    - convert foo[i].bar → foo[i]["bar"]
    - convert foo.bar → foo["bar"]
    """
    if not isinstance(cond, str) or not cond:
        return cond
    cond = cond.replace("€", "")
    cond = re.sub(r"(\w+\[[^\]]+\])\.(\w+)", r'\1["\2"]', cond)
    cond = re.sub(r"\b([A-Za-z_]\w*)\.(\w+)", r'\1["\2"]', cond)
    return cond

def _lookup_scope_value(scope: dict, key: str):
    """Lookup helper that prefers provided scope but falls back to session.scope."""
    if scope and key in scope:
        return scope.get(key)
    return session.scope.get(key)


def eval_expr(expr: str, scope: dict, raw=None):
    """
    Universal DSL expression evaluator.
    - €variables
    - arithmetic
    - produces slice instructions for SliceNode
    """

    expr = expr.strip()

    # --- Detect slice syntax ---
    m = re.fullmatch(r"raw\[\s*(.+?)\s*:\s*(.+?)\s*\]", expr)
    if m:
        start_expr, end_expr = m.groups()

        start = eval_expr(start_expr, scope, raw)
        end   = eval_expr(end_expr, scope, raw)

        if not isinstance(start, int) or not isinstance(end, int):
            raise ValueError(f"Invalid slice bounds: {expr}")

        # Return slice instruction — NOT bytes
        return ("slice", start, end, None)

    # --- Pure variable reference (supports [idx] and .key) ---
    if expr.startswith("€") and re.fullmatch(r"€\w+(?:\[\w+\])?(?:\.\w+)?", expr):
        return DecoderHandler.resolve_variable(expr, scope)

    def eval_ast(node, ctx):
        if isinstance(node, ast.Expression):
            return eval_ast(node.body, ctx)
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Num):  # py<3.8
            return node.n
        if isinstance(node, ast.Name):
            val = ctx.get(node.id, 0)
            return 0 if val is None else val
        if isinstance(node, ast.BinOp):
            left = eval_ast(node.left, ctx)
            right = eval_ast(node.right, ctx)
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
            val = eval_ast(node.operand, ctx)
            if isinstance(node.op, ast.UAdd):
                return +val
            if isinstance(node.op, ast.USub):
                return -val
            raise ValueError(f"Unsupported unary operator: {type(node.op).__name__}")
        if isinstance(node, ast.Subscript):
            target = eval_ast(node.value, ctx)
            slc = eval_ast(node.slice, ctx)
            return target[slc]
        if isinstance(node, ast.Slice):
            lower = eval_ast(node.lower, ctx) if node.lower is not None else None
            upper = eval_ast(node.upper, ctx) if node.upper is not None else None
            step = eval_ast(node.step, ctx) if node.step is not None else None
            return slice(lower, upper, step)
        if hasattr(ast, "Index") and isinstance(node, ast.Index):  # py<3.9
            return eval_ast(node.value, ctx)
        raise ValueError(f"Unsupported expression node: {type(node).__name__}")

    expr_eval = preprocess_condition(expr)
    ctx = DecoderHandler._build_eval_context(scope)
    try:
        tree = ast.parse(expr_eval, mode="eval")
    except SyntaxError as e:
        raise ValueError(f"Invalid expression: {expr}") from e

    return eval_ast(tree, ctx)




class DecoderHandler:

    @staticmethod
    def is_visible(field) -> bool:
        return bool(getattr(field, "visible", True)) and not getattr(field, "ignore", False)

    @staticmethod
    def present_buffer(buf):
        out = []
        for b in buf:
            if b is None:
                out.append("??")
            elif isinstance(b, int):
                out.append(f"{b & 0xFF:02X}")
            elif isinstance(b, (bytes, bytearray)) and len(b) > 0:
                out.append(f"{b[0] & 0xFF:02X}")
            else:
                try:
                    out.append(f"{int(b) & 0xFF:02X}")
                except Exception:
                    out.append("??")
        return "".join(out)

    # ===================================================================
    # PROCESS FIELD
    # ===================================================================
    @staticmethod
    def _process_field(field, raw_data, bitstate, endian, state: DecodeState):
        """
        Shared logic for all field types.
        Always returns: (field, stored, endian)
        """
        scope = state.all
        if getattr(field, "optional", False) and getattr(field, "has_io", True):
            if bitstate.offset >= len(raw_data):
                field.value = None
                field.raw_offset = bitstate.offset
                field.raw_length = 0
                field.raw_data = b""
                state.set_field(field, None)
                field.processed = True
                return field, True, endian

        # ---------------------------------------------------------
        # Slice node
        # ---------------------------------------------------------
        if field.interpreter == "slice":
            try:
                spec = field.slice_expr or ""
                parts = spec.split(":")

                if len(parts) not in (2, 3):
                    raise ValueError(f"Invalid slice spec: {spec}")

                def eval_part(s):
                    s = s.strip()
                    if not s:
                        return None
                    # använd DSL-eval här
                    return eval_expr(s, scope, raw_data)

                start = eval_part(parts[0])
                end   = eval_part(parts[1]) if len(parts) >= 2 else None
                step  = eval_part(parts[2]) if len(parts) == 3 else None

                if start is not None and not isinstance(start, int):
                    raise ValueError(f"start is not int: {start!r}")
                if end is not None and not isinstance(end, int):
                    raise ValueError(f"end is not int: {end!r}")
                if step is not None and not isinstance(step, int):
                    raise ValueError(f"step is not int: {step!r}")

                sl = slice(start, end, step)
                bytes_slice = raw_data[sl]

                field.value = bytes_slice
                field.raw_data = bytes_slice
                field.raw_length = len(bytes_slice)
                field.raw_offset = start or 0
                field.processed = True

                state.set_field(field, bytes_slice, public_value=bytes_slice.hex())

                # flytta läspositionen fram till end om det finns
                if end is not None:
                    bitstate.advance_to(end, 0)

                return field, True, endian

            except Exception as e:
                Logger.error(f"slice failed: {e}")
                field.value = None
                field.processed = True
                return field, True, endian

        # ---------------------------------------------------------
        # Variable assignment (VariableNode)
        # ---------------------------------------------------------
        if isinstance(field, VariableNode):
            raw_expr = field.raw_value

            try:
                val = eval_expr(raw_expr, scope, raw_data)
            except Exception as e:
                Logger.error(f"Failed evaluating variable '{field.name}' = {raw_expr}: {e}")
                val = None

            field.value = val
            state.set_field(field, val)
            field.processed = True

            return field, True, endian

        # ---------------------------------------------------------
        # Debug print (no IO / no result impact)
        # ---------------------------------------------------------
        if field.interpreter == "print":
            field.processed = True
            return field, True, endian

        # ---------------------------------------------------------
        # var fields (interpreter = "var")
        # ---------------------------------------------------------
        if field.interpreter == "var":
            expr = getattr(field, "raw_value", None) or field.format

            if expr is None:
                field.value = None
                field.processed = True
                return field, True, endian

            expr = expr.strip()

            try:
                # kör nya DSL-eval istället för gamla evaluate_expr
                val = eval_expr(expr, scope, raw_data)
            except Exception as e:
                Logger.error(f"Failed evaluating expr for field '{field.name}' = {expr}: {e}")
                val = None

            for mod in getattr(field, "modifiers", []) or []:
                func = modifiers_operation_mapping.get(mod)
                if func is not None:
                    try:
                        val = func(val)
                    except Exception:
                        pass

            field.value = val
            state.set_field(field, val)
            field.processed = True
            return field, True, endian

        # ---------------------------------------------------------
        # Buffer allocation / buffer IO
        # ---------------------------------------------------------
        if field.interpreter == "buffer_alloc":
            field = DecoderHandler.handle_buffer_alloc(field, bitstate, state)
            return field, True, endian

        if field.interpreter == "buffer_io":
            field = DecoderHandler.handle_buffer_io(field, raw_data, bitstate, state)
            return field, True, endian

        if field.interpreter == "buffer_assign":
            field = DecoderHandler.handle_buffer_assign(field, raw_data, bitstate, state, endian)
            return field, True, endian

        # ---------------------------------------------------------
        # Padding
        # ---------------------------------------------------------
        if field.interpreter == 'padding':
            if getattr(field, "value", 0) == 0:
                bitstate.align_to_byte()
            else:
                bitstate.offset += field.value
            field.processed = True
            return field, True, endian

        # ---------------------------------------------------------
        # Seek
        # ---------------------------------------------------------
        if field.interpreter == 'seek_match':
            bitstate.align_to_byte()
            pattern = getattr(field, "pattern", b"")
            start = bitstate.offset
            if not pattern:
                if not getattr(field, "optional", False):
                    Logger.warning("seek next: empty pattern")
                    bitstate.advance_to(len(raw_data), 0)
                field.processed = True
                return field, True, endian

            idx = raw_data.find(pattern, start)
            if idx == -1:
                if not getattr(field, "optional", False):
                    Logger.warning(f"seek next: pattern not found ({getattr(field, 'pattern_desc', '')})")
                    bitstate.advance_to(len(raw_data), 0)
                field.processed = True
                return field, True, endian

            bitstate.advance_to(idx, 0)
            field.processed = True
            return field, True, endian

        if field.interpreter == 'seek':
            bitstate.offset = field.value
            field.processed = True
            return field, True, endian

        # ---------------------------------------------------------
        # Endian switch
        # ---------------------------------------------------------
        if field.name == 'endian':
            endian = '<' if field.format == 'little' else '>'
            field.processed = True
            return field, True, endian

        # ---------------------------------------------------------
        # combine (GUID synthesis)
        # ---------------------------------------------------------
        if field.interpreter == "combine":
            mask_name = field.format
            mask = DecoderHandler.resolve_variable(mask_name, scope)

            combined = DecoderHandler.combine_generic(
                target_name=field.name,
                mask=mask,
                values=scope,
                result=scope
            )

            field.value = combined
            state.set_field(field, combined)
            field.processed = True
            return field, True, endian

        # ---------------------------------------------------------
        # Dynamic → convert to struct
        # ---------------------------------------------------------
        if field.interpreter == 'dynamic':
            length = DecoderHandler.resolve_variable(field.format, scope)
            if length is None:
                Logger.warning(f"Failed to resolve dynamic field: {field.name}")
                return field, True, endian

            field.interpreter = 'struct'
            field.format = f"{length}s"

        # ---------------------------------------------------------
        # String read
        # ---------------------------------------------------------
        if field.format == 'S':
            field = DecoderHandler.resolve_string_format(field, raw_data, bitstate.offset)

        # ---------------------------------------------------------
        # R = read rest of payload
        # ---------------------------------------------------------
        if field.format == 'R':
            field = DecoderHandler.handle_read_rest(field, raw_data, bitstate)
            val = DecoderHandler.apply_modifiers(field)
            state.set_field(field, val)
            return field, True, endian

        # ---------------------------------------------------------
        # bits
        # ---------------------------------------------------------
        if field.interpreter == 'bits':
            bits_required = 0
            for mod in getattr(field, "modifiers", []) or []:
                m = re.fullmatch(r"(\d+)([Bb])", mod)
                if m:
                    bits_required += int(m.group(1))
            remaining_bits = (len(raw_data) - bitstate.offset) * 8 - bitstate.bit_pos
            if getattr(field, "optional", False) and bits_required > remaining_bits:
                field.value = None
                field.raw_offset = bitstate.offset
                field.raw_length = 0
                field.raw_data = b""
                state.set_field(field, None)
                field.processed = True
                return field, True, endian
            field = DecoderHandler.decode_bits_field(field, raw_data, bitstate)
            state.set_field(field, field.value)
            field.processed = True
            return field, True, endian

        # ---------------------------------------------------------
        # loop
        # ---------------------------------------------------------
        
        if field.interpreter == 'loop':
            DecoderHandler.handle_loop(field, raw_data, bitstate, endian, state)
            field.processed = True
            return field, True, endian

        # ---------------------------------------------------------
        # bitmask
        # ---------------------------------------------------------
        if field.interpreter == "bitmask":
            DecoderHandler.handle_bitmask(field, raw_data, bitstate, endian, state)
            field.processed = True
            return field, True, endian

        # ---------------------------------------------------------
        # if
        # ---------------------------------------------------------
        if field.interpreter == "if":
            DecoderHandler.handle_if(field, raw_data, bitstate, endian, state)
            field.processed = True
            return field, True, endian

        # ---------------------------------------------------------
        # packed_guid
        # ---------------------------------------------------------
        if field.interpreter == "packed_guid":
            DecoderHandler.handle_packed_guid(field, raw_data, bitstate, state)
            field.processed = True
            return field, True, endian

        # ---------------------------------------------------------
        # uncompress block
        # ---------------------------------------------------------
        if field.interpreter == "uncompress":
            DecoderHandler.handle_uncompress(field, raw_data, bitstate, endian, state)
            field.processed = True
            return field, True, endian

        # ---------------------------------------------------------
        # append / struct
        # ---------------------------------------------------------
        if field.interpreter == "append":
            field, _, _ = DecoderHandler.decode_struct(field, raw_data, bitstate, endian)
            value = DecoderHandler.apply_modifiers(field)

            prev = state.all.get(field.name)

            if prev is None:
                state.set_field(field, value)
            elif isinstance(prev, list):
                prev.append(value)
            else:
                state.set_field(field, [prev, value])

            field.processed = True
            return field, True, endian

        # ---------------------------------------------------------
        # struct default
        # ---------------------------------------------------------
        field, value, _ = DecoderHandler.decode_struct(field, raw_data, bitstate, endian)

        if getattr(field, "modifiers", None):
            value = DecoderHandler.apply_modifiers(field)

        field.value = value

        state.set_field(field, value)

        field.processed = True
        return field, True, endian

    # ===================================================================
    # MAIN DECODE
    # ===================================================================
    @staticmethod
    def decode(case, silent=False):
        fields = session.fields
        raw_data = case[2]

        bitstate = BitState()
        state = DecodeState()
        endian = '<'
        debug_msg = []

        # Reset DSL variable environment (GlobalScope instance on session)
        session.scope.global_vars.clear()
        session.scope.scope_stack.clear()

        # ============================================
        # DEBUG: RAW NODE TREE BEFORE DECODING
        # ============================================
        
        Logger.debug("\n[RAW NODE TREE BEFORE DECODING]\n")

        for idx, field in enumerate(session.fields, start=1):
            Logger.debug(f"[{idx}] {field.__class__.__name__}  name='{field.name}'  interp='{field.interpreter}' fmt='{field.format}' ignore={field.ignore}")
            
            # Visa ALLA attribut i BaseNode
            Logger.debug("    " + ", ".join(f"{k}={v!r}" for k,v in field.__dict__.items() if k not in ("children","nodes")))

            # Visa children om noden är LoopNode, IfNode, Bitmask, BlockDefinition, RandSeq
            if hasattr(field, "children"):
                Logger.debug("    CHILDREN:")
                for cidx, child in enumerate(field.children, start=1):
                    Logger.debug(f"        [{cidx}] {child.__class__.__name__} name='{child.name}' fmt='{child.format}' interp='{child.interpreter}'")

        i = 0
        while i < len(fields):
            field = fields[i]

            if getattr(field, "processed", False):
                i += 1
                continue

            needs_io = getattr(field, "has_io", True)
            if needs_io and bitstate.offset >= len(raw_data):
                if getattr(field, "optional", False):
                    field, _, endian = DecoderHandler._process_field(
                        field, raw_data, bitstate, endian, state
                    )
                    fields[i] = field
                    i += 1
                    continue
                Logger.warning(f"Ran out of raw data before field '{getattr(field, 'name', '?')}'")
                break
            
            field, _, endian = DecoderHandler._process_field(
                field, raw_data, bitstate, endian, state
            )

            fields[i] = field
            DebugHelper.trace_field(field, bitstate, label_prefix=field.name)
            Logger.to_log('')
            i += 1

        try:
            json_output = json.dumps(state.public, indent=4)
            if not silent:
                Logger.success(f"{case[0]}\n{json_output}")
        except TypeError:
            Logger.error("FAILED RESULT (non-serializable type)")

        # ===============================================================
        # FULL ENVIRONMENT DUMP AFTER COMPLETE PARSE
        # ===============================================================
        Logger.debug("[FINAL STATE DUMP]")

        # 1. Dump all global vars
        if session.scope.global_vars:
            Logger.debug("Global Vars:")
            for k, v in session.scope.global_vars.items():
                Logger.debug(f"    {k} = {v}")
        else:
            Logger.debug("Global Vars: (empty)")

        # 2. Dump all local scopes
        if session.scope.scope_stack:
            Logger.debug("Local Scopes:")
            for idx, frame in enumerate(session.scope.scope_stack):
                Logger.debug(f"  Frame {idx}:")
                for k, v in frame.items():
                    Logger.debug(f"      {k} = {v}")
        else:
            Logger.debug("Local Scopes: (empty)")

        # 3. Dump the RESULT dict (this is the real parsed data)
        if state.public:
            Logger.debug("Result Fields:")
            for k, v in state.public.items():
                Logger.debug(f"    {k} = {v}")
        else:
            Logger.debug("Result Fields: (empty)")

        Logger.debug("===================================================")

        return state.public

    


    @staticmethod
    def substitute_vars(expr: str, scope: dict):
        def repl(m):
            var = m.group(1)
            return str(scope.get(var, 0))
        return re.sub(r"€([A-Za-z_]\w*)", repl, expr)
    
    @staticmethod
    def parse_slice_spec(spec: str):
        parts = spec.split(":")

        if len(parts) == 2:
            start, end = parts
            step = None
        elif len(parts) == 3:
            start, end, step = parts
        else:
            raise ValueError(f"Invalid slice spec: {spec}")

        def conv(x):
            x = x.strip()
            return int(x) if x else None

        return conv(start), conv(end), conv(step)

    # ===================================================================
    # MODIFIERS
    # ===================================================================
    @staticmethod
    def apply_modifiers(field):
        if not getattr(field, "modifiers", None):
            return field.value

        value = field.raw_data

        for mod in field.modifiers:
            func = modifiers_operation_mapping.get(mod)
            if not func:
                continue
            if mod == "E":
                value = func(value, field.format)
            else:
                value = func(value)

        return value

    # ===================================================================
    # STRING HANDLING
    # ===================================================================
    @staticmethod
    def resolve_string_format(field, raw_data, offset):
        end = offset
        while end < len(raw_data) and raw_data[end] != 0:
            end += 1

        raw = raw_data[offset:end]
        try:
            val = raw.decode("ascii")
        except UnicodeDecodeError:
            val = raw.hex()

        length = (end - offset) + 1
        field.value = val
        field.format = f"{length}s"
        field.interpreter = "struct"
        field.raw_length = length

        return field

    # ===================================================================
    # READ REST
    # ===================================================================
    @staticmethod
    def handle_read_rest(field, raw_data, bitstate):
        start = bitstate.offset
        end = len(raw_data)

        raw = raw_data[start:end]
        try:
            value = raw.decode("utf-8")
        except UnicodeDecodeError:
            value = raw.hex()

        field.value = value
        field.raw_length = end - start
        field.raw_data = raw
        field.format = f"{end - start}s"
        field.interpreter = "raw"

        bitstate.offset = end
        field.processed = True
        return field

    # ===================================================================
    # STRUCT DECODING
    # ===================================================================
    @staticmethod
    def decode_struct(field, raw_data, bitstate, endian):
        bitstate.align_to_byte()
        fmt = field.format
        start = bitstate.offset

        try:
            size = struct.calcsize(f"{endian}{fmt}")
            if getattr(field, "optional", False) and start + size > len(raw_data):
                field.value = None
                field.raw_offset = start
                field.raw_length = 0
                field.raw_data = b""
                return field, None, endian

            if 's' not in fmt:
                # Normal struct unpack
                value = struct.unpack_from(f"{endian}{fmt}", raw_data, start)

                # NEW: unwrap single-value tuple → return pure scalar
                if isinstance(value, tuple) and len(value) == 1:
                    value = value[0]

            else:
                # String format → unpack gives bytes as value[0]
                value = struct.unpack_from(f"{endian}{fmt}", raw_data, start)[0]

        except struct.error as e:
            Logger.warning("Struct unpack error")
            Logger.debug(f"fmt={fmt} error={e}")
            field.value = None
            field.raw_offset = start
            field.raw_length = 0
            field.raw_data = b""
            return field, None, endian

        # Convert bytes → string/hex
        if isinstance(value, bytes):
            try:
                value = value.decode("utf-8").strip("\x00")
            except UnicodeDecodeError:
                value = value.hex()

        field.value = value
        field.raw_offset = start
        field.raw_length = size
        field.raw_data = raw_data[start:start + size]

        bitstate.advance_to(start + size, 0)
        return field, value, size

    # ===================================================================
    # VARIABLE RESOLUTION (via session.scope)
    # ===================================================================
    @staticmethod
    def resolve_variable(key: str, result: dict):
        scope = session.scope
        orig_key = key

        if not isinstance(key, str):
            return None

        if key.endswith("'s"):
            key = key[:-2]

        if key.startswith("€"):
            key = key[1:]

            m = re.match(r"^(\w+)(?:\[(\w+)\])?(?:\.(\w+))?$", key)
            if not m:
                Logger.debug(f"[resolve_variable] regex miss: {orig_key}")
                return None

            base, index, subkey = m.groups()
            Logger.debug(f"[resolve_variable] key={orig_key} → base={base}, index={index}, subkey={subkey}")

            val = scope.get(base, result.get(base))
            if val is None:
                return None

            if index is not None:
                if index == "i":
                    idx = scope.get("i")
                elif index.isdigit():
                    idx = int(index)
                else:
                    idx = scope.get(index, result.get(index))

                Logger.debug(f"[resolve_variable] index={index!r} → {idx!r}")
                if not isinstance(idx, int):
                    return None

                try:
                    val = val[idx]
                except Exception:
                    Logger.debug(f"[resolve_variable] index error {base}[{idx}]")
                    return None

            if subkey is not None:
                try:
                    val = val[subkey]
                except Exception:
                    Logger.debug(f"[resolve_variable] subkey error {base}.{subkey}")
                    return None

            Logger.debug(f"[resolve_variable] resolved {orig_key!r} → {val!r}")
            return val

        try:
            return int(key)
        except ValueError:
            pass

        try:
            return float(key)
        except ValueError:
            return None
    
    # ===================================================================
    # BUFFER HELPERS
    # ===================================================================
    @staticmethod
    def _resolve_length_expr(expr, scope):
        if expr is None:
            return None
        cleaned = str(expr).strip()
        if cleaned.endswith("B"):
            cleaned = cleaned[:-1]
        if not cleaned:
            return None
        try:
            return int(cleaned)
        except ValueError:
            pass
        try:
            return DecoderHandler.resolve_variable(cleaned, scope)
        except Exception:
            return None

    @staticmethod
    def handle_buffer_alloc(field, bitstate, state: DecodeState):
        raw_expr = getattr(field, "alloc_size_expr", None) or getattr(field, "format", "") or ""
        size = DecoderHandler._resolve_length_expr(raw_expr, state.all)
        try:
            size = int(size or 0)
        except Exception:
            size = 0
        size = max(0, size)

        buf = [None] * size
        field.value = buf
        field.raw_offset = bitstate.offset
        field.raw_length = 0
        field.raw_data = b""
        field.processed = True

        state.remember_buffer(field, buf, public_value=DecoderHandler.present_buffer(buf))
        return field

    @staticmethod
    def handle_buffer_io(field, raw_data, bitstate, state: DecodeState):
        buffer_name = getattr(field, "buffer_name", getattr(field, "name", ""))
        start_idx = getattr(field, "index_start", 0) or 0
        end_idx = getattr(field, "index_end", start_idx) or start_idx
        default_len = max(1, end_idx - start_idx + 1)

        size_expr = getattr(field, "io_size_expr", None)
        size = DecoderHandler._resolve_length_expr(size_expr, state.all)
        try:
            size = int(size) if size is not None else default_len
        except Exception:
            size = default_len

        size = max(1, size)

        bitstate.align_to_byte()
        start = bitstate.offset
        if getattr(field, "optional", False) and start + size > len(raw_data):
            field.value = None
            field.raw_offset = start
            field.raw_length = 0
            field.raw_data = b""
            field.processed = True
            state.set_field(field, None)
            return field
        chunk = raw_data[start:start + size]
        bitstate.advance_to(start + len(chunk), 0)

        field.raw_offset = start
        field.raw_length = len(chunk)
        field.raw_data = chunk
        val_int = chunk[0] if chunk else 0
        val_mod = val_int
        for mod in getattr(field, "modifiers", []) or []:
            func = modifiers_operation_mapping.get(mod)
            if func is not None:
                try:
                    val_mod = func(val_mod)
                except Exception:
                    pass
        field.value = val_mod
        field.processed = True

        existing = state.all.get(buffer_name)
        if isinstance(existing, list):
            buf = existing
        elif isinstance(existing, (bytes, bytearray)):
            buf = [b for b in existing]
        else:
            buf = []

        required_len = start_idx + 1
        if required_len > len(buf):
            buf.extend([None] * (required_len - len(buf)))
        buf[start_idx] = val_mod

        state.update_buffer(buffer_name, buf, force_visible=None)

        # Optionally expose the IO operation itself
        pub_val = val_mod if getattr(field, "visibility_prefix", None) == "+" else f"{val_int & 0xFF:02X}"
        state.set_field(field, val_mod, public_value=pub_val)
        return field

    @staticmethod
    def handle_buffer_assign(field, raw_data, bitstate, state: DecodeState, endian="<"):
        buffer_name = getattr(field, "buffer_name", getattr(field, "name", ""))
        start_idx = getattr(field, "index_start", 0) or 0
        end_idx = getattr(field, "index_end", start_idx) or start_idx
        default_len = max(1, end_idx - start_idx + 1)

        size_expr = getattr(field, "io_size_expr", None)
        size = DecoderHandler._resolve_length_expr(size_expr, state.all)
        try:
            size = int(size) if size is not None else default_len
        except Exception:
            size = default_len

        size = max(1, size)

        bitstate.align_to_byte()
        start = bitstate.offset
        if getattr(field, "optional", False) and start + size > len(raw_data):
            field.value = None
            field.raw_offset = start
            field.raw_length = 0
            field.raw_data = b""
            field.processed = True
            state.set_field(field, None)
            return field
        chunk = raw_data[start:start + size]
        bitstate.advance_to(start + len(chunk), 0)

        field.raw_offset = start
        field.raw_length = len(chunk)
        field.raw_data = chunk
        val_int = chunk[0] if chunk else 0
        val_mod = val_int
        for mod in getattr(field, "modifiers", []) or []:
            func = modifiers_operation_mapping.get(mod)
            if func is not None:
                try:
                    val_mod = func(val_mod)
                except Exception:
                    pass
        field.value = val_mod
        field.processed = True

        existing = state.all.get(buffer_name)
        if isinstance(existing, list):
            buf = existing
        elif isinstance(existing, (bytes, bytearray)):
            buf = [b for b in existing]
        else:
            buf = []

        required_len = start_idx + size
        if required_len > len(buf):
            buf.extend([None] * (required_len - len(buf)))
        for i, b in enumerate(chunk):
            buf[start_idx + i] = val_mod if i == 0 else b

        state.update_buffer(buffer_name, buf, force_visible=None)

        # Optionally expose the IO operation itself
        pub_val = val_mod if getattr(field, "visibility_prefix", None) == "+" else f"{val_int & 0xFF:02X}"
        state.set_field(field, val_mod, public_value=pub_val)
        return field
    
    # ===================================================================
    # BITS
    # ===================================================================
    @staticmethod
    def decode_bits_field(field, raw_data, bitstate):
        raw_start = None
        raw_end = None

        for mod in field.modifiers:
            m = re.fullmatch(r"(\d+)([Bb])", mod)
            if m:
                func = modifiers_operation_mapping[m.group(2)]
                if raw_start is None:
                    raw_start = bitstate.offset

                bits, new_offset, bit_pos = func(
                    raw_data, bitstate.offset, bitstate.bit_pos, int(m.group(1))
                )

                raw_end = new_offset + (1 if bit_pos > 0 else 0)
                field.value = bits
                bitstate.advance_to(new_offset, bit_pos)
                continue

            func = modifiers_operation_mapping.get(mod)
            if func and field.value is not None:
                field.value = func(field.value)

        if raw_start is not None and raw_end is not None:
            field.raw_offset = raw_start
            field.raw_length = raw_end - raw_start
            field.raw_data = raw_data[raw_start:raw_end]

        return field


    # ===================================================================
    # LOOP — robust implementation
    # ===================================================================
    def handle_loop(field, raw_data, bitstate, endian, state: DecodeState):
        scope = session.scope
        target_name = field.name

        # ================================================================
        # MODE 1: loop until end-of-data
        # ================================================================
        if field.count_from == "until_end":
            out_all = []
            out_public = []

            while bitstate.offset < len(raw_data):
                before_offset = bitstate.offset
                before_bit = bitstate.bit_pos

                entry_state = DecodeState()
                success = True

                scope.push()
                scope.set("i", len(out_all))

                try:
                    # process children
                    for child_template in field.children:
                        child = child_template.copy()
                        child, _, _ = DecoderHandler._process_field(
                            child, raw_data, bitstate, endian, entry_state
                        )

                        # if decode failed (None) → stop scanning
                        if child.value is None:
                            success = False
                            break
                finally:
                    scope.pop()

                # did we fail?
                if not success:
                    # restore position just in case
                    bitstate.offset = before_offset
                    bitstate.bit_pos = before_bit
                    break

                # did offset fail to advance?
                if bitstate.offset == before_offset and bitstate.bit_pos == before_bit:
                    # nothing consumed → infinite loop prevention
                    break

                out_all.append(entry_state.all)
                out_public.append(entry_state.public)

            state.set_field(field, out_all, public_value=out_public)
            field.value = out_all
            field.processed = True
            return field, True, endian

        # ================================================================
        # MODE 2: normal loop with count
        # ================================================================
        loop_count = DecoderHandler.resolve_variable(field.count_from, state.all)

        # SAFETY: default to 0 on None, invalid, negative, etc.
        if not isinstance(loop_count, int) or loop_count < 0:
            Logger.debug(f"[handle_loop] Invalid count '{field.count_from}' → using 0")
            loop_count = 0

        out_all = []
        out_public = []
        
        for idx in range(loop_count):
            scope.push()
            scope.set("i", idx)

            entry_state = DecodeState()

            for child_template in field.children:
                child = child_template.copy()

                child, _, _ = DecoderHandler._process_field(
                    child, raw_data, bitstate, endian, entry_state
                )

            out_all.append(entry_state.all)
            out_public.append(entry_state.public)
            scope.pop()

        state.set_field(field, out_all, public_value=out_public)
        field.value = out_all
        field.processed = True
        return field, True, endian

    # ===================================================================
    # BITMASK
    # ===================================================================
    @staticmethod
    def handle_bitmask(field, raw_data, bitstate, endian, state: DecodeState):
        start_off = bitstate.offset
        start_bit = bitstate.bit_pos
        total_bits = getattr(field, "size", 0)

        end_abs = start_off * 8 + start_bit + total_bits
        end_off = end_abs // 8
        end_bit = end_abs % 8

        child_state = BitState()
        child_state.offset = start_off
        child_state.bit_pos = start_bit

        tmp_state = DecodeState()
        for child_template in field.children:
            child = child_template.copy()
            DecoderHandler._process_field(child, raw_data, child_state, endian, tmp_state)
            DebugHelper.trace_field(field, bitstate, label_prefix=field.name)

        bitstate.advance_to(end_off, end_bit)

        field.raw_offset = start_off
        field.raw_length = end_off - start_off + (1 if end_bit > 0 else 0)
        field.raw_data = raw_data[start_off:start_off + field.raw_length]
        field.value = tmp_state.public
        state.set_field(field, tmp_state.public)

        return field, True, endian

    # ===================================================================
    # IF — uses session.scope
    # ===================================================================

    @staticmethod
    def _build_eval_context(state_data: dict) -> dict:
        ctx: dict = {}
        if isinstance(state_data, dict):
            ctx.update(state_data)
        scope = session.scope
        if getattr(scope, "global_vars", None):
            ctx.update(scope.global_vars)
        for frame in getattr(scope, "scope_stack", []):
            ctx.update(frame)
        return ctx

    @staticmethod
    def _eval_condition(cond: str, state_data: dict) -> bool:
        """
        Python-like condition evaluation with AND/OR support.
        Mirrors encoder semantics (eval with local context).
        """
        cond = preprocess_condition((cond or "").strip())
        if not cond:
            return False
        ctx = DecoderHandler._build_eval_context(state_data)
        try:
            return bool(eval(cond, {}, ctx))
        except Exception:
            return False

    @staticmethod
    def handle_if(field, raw_data, bitstate, endian, state: DecodeState):
        scope = session.scope

        branch = None

        # huvud-villkoret
        if DecoderHandler._eval_condition(field.condition, state.all):
            branch = field.true_branch
        else:
            # ev. elif-grenar
            if field.elif_branches:
                for cond, nodes in field.elif_branches:
                    if DecoderHandler._eval_condition(cond, state.all):
                        branch = nodes
                        break

            # annars else-grenen
            if branch is None:
                branch = field.false_branch or []

        scope.push()
        try:
            for child_template in (branch or []):
                child = child_template.copy()
                DecoderHandler._process_field(
                    child, raw_data, bitstate, endian, state
                )
                DebugHelper.trace_field(child, bitstate)
        finally:
            scope.pop()

        return field, True, endian

    # ===================================================================
    # COMBINE
    # ===================================================================
    @staticmethod
    def combine_generic(target_name: str, mask, values: dict, result: dict):
        """
        Combine GUID-like structures.
        """
        scope = session.scope
        i = scope.get("i")
        if i is None:
            return 0

        try:
            meta = result["chars_meta"][i]
        except Exception:
            return 0

        if isinstance(mask, list):
            mask_list = mask
        else:
            prefix = target_name.rstrip("_")
            regex = re.compile(rf"^{prefix}_?(\d+)_mask$", re.IGNORECASE)
            mask_list = [
                int(m.group(1)) for k, v in meta.items()
                if (m := regex.match(k)) and v
            ]

        guid = 0
        prefix = target_name.rstrip("_")

        for bit_index in mask_list:
            for k in (f"{target_name}_{bit_index}",
                      f"{prefix}_{bit_index}",
                      f"{prefix}{bit_index}"):
                if k in values:
                    guid |= (values[k] & 0xFF) << (bit_index * 8)
                    break

        return guid

    # ===================================================================
    # PACKED GUID
    # ===================================================================
    @staticmethod
    def handle_packed_guid(field, raw_data, bitstate, state: DecodeState):
        bitstate.align_to_byte()
        start = bitstate.offset
        if start >= len(raw_data):
            Logger.error("packed_guid: no data")
            return field, True, '<'

        mask = raw_data[start]
        offset = start + 1

        guid_bytes = [0] * 8
        for i in range(8):
            if mask & (1 << i):
                if offset >= len(raw_data):
                    Logger.error("packed_guid: out of data")
                    break
                guid_bytes[i] = raw_data[offset]
                offset += 1

        bitstate.advance_to(offset, 0)
        guid = int.from_bytes(bytes(guid_bytes), "little")

        field.value = guid
        field.raw_offset = start
        field.raw_length = offset - start
        field.raw_data = raw_data[start:offset]
        setattr(field, "mask", mask)

        state.set_field(field, guid)
        mask_field = BaseNode(
            name=f"{field.name}_mask",
            format="B",
            interpreter="struct",
            ignore=getattr(field, "ignore", False),
            visible=getattr(field, "visible", True),
            payload=getattr(field, "payload", True),
        )
        state.set_field(mask_field, mask)

        return field, True, '<'

    # ===================================================================
    # UNCOMPRESS
    # ===================================================================
    @staticmethod
    def handle_uncompress(field, raw_data, bitstate, endian, state: DecodeState):
        algo = (field.algo or "").lower()
        length_expr = field.length_expr

        length = None
        if length_expr:
            expr = length_expr.strip()
            if expr.startswith("€"):
                expr = expr[1:]
            if expr.endswith("B"):
                expr = expr[:-1]
            try:
                length = int(expr)
            except ValueError:
                length = DecoderHandler.resolve_variable(expr, state.all)

        if length is None:
            length = len(raw_data) - bitstate.offset

        comp = raw_data[bitstate.offset:bitstate.offset + length]
        bitstate.advance_to(bitstate.offset + length, 0)

        if algo != "zlib":
            Logger.error(f"uncompress: unsupported algorithm {algo}")
            return field, True, endian

        try:
            inflated = zlib.decompress(comp)
        except Exception as e:
            Logger.error(f"uncompress failed: {e}")
            return field, True, endian

        child_state = BitState()
        for child_template in field.children:
            child = child_template.copy()
            DecoderHandler._process_field(child, inflated, child_state, endian, state)
            DebugHelper.trace_field(field, bitstate, label_prefix=field.name)

        field.raw_data = comp
        field.value = inflated
        return field, True, endian
