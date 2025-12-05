#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from modules.Session import VariableNode, get_session
from modules.ModifierMapping import modifiers_operation_mapping
import struct
import json
from utils.Logger import Logger
import re
from modules.bitsHandler import BitState
from utils.DebugHelper import DebugHelper
from modules.RandseqHandler import handle_randseq, handle_randseq_bits
import zlib
import ast

# GLOBALS
session = get_session()


class DecoderHandler(): 
    @staticmethod
    def _process_field(field, raw_data, bitstate, endian, result, target_dict):
        """
        Shared field processor for both top-level decode and loop children.
        Returns (updated_field, stored, endian) where:
          - stored: True if the value has already been placed into target_dict/result
          - endian: updated endianness (may change via endian field)
        """
        # Padding
        if field.interpreter == 'padding':
            if field.value == 0:
                # Special meaning: just align to next byte
                bitstate.align_to_byte()
                Logger.debug(f"[Padding] align_to_byte() because size=0")
            else:
                # Normal padding: skip bytes as-is
                Logger.debug(f"[Padding] Advancing offset by {field.value} bytes (no forced align)")
                bitstate.offset += field.value

            field.processed = True
            return field, True, endian

        # Seek
        if field.name == 'seek':
            bitstate.offset = field.value
            field.processed = True
            return field, True, endian

        if field.name == "bit_offset":
            field.processed = True
            return field, True, endian

        # Endian switch
        if field.name == 'endian':
            endian = '<' if field.format == 'little' else '>'
            field.processed = True
            return field, True, endian

        # Resolve variable refs
        if field.interpreter == 'var':
            value = DecoderHandler.resolve_variable(field.format, result)

            if isinstance(value, str):
                if value.endswith("raw"):
                    value = DecoderHandler.resolve_variable(value, result)

                if value.startswith("raw["):
                    slice_bytes, start, end = DecoderHandler.evaluate_slice_expression(value, result, raw_data)
                    value = slice_bytes.hex()

                    field.raw_offset = start
                    field.raw_length = end - start
                    field.raw_data = slice_bytes

                    bitstate.advance_to(end, 0)

            field.value = value

        # Dynamic length → struct
        if field.interpreter == 'dynamic':
            length = DecoderHandler.resolve_variable(field.format, result)
            if length is None:
                Logger.warning(f"Failed to resolve dynamic field: {field.name}")
                return field, True, endian
            field.interpreter = 'struct'
            field.format = f"{length}s"

        # String format
        if field.format == 'S':
            field = DecoderHandler.resolve_string_format(field, raw_data, bitstate.offset)

        # Read rest
        if field.format == 'R':
            field = DecoderHandler.handle_read_rest(field, raw_data, bitstate)
            field.value = DecoderHandler.apply_modifiers(field)
            if not getattr(field, "ignore", False):
                target_dict[field.name] = field.value
            return field, True, endian

        # Var (dynamic reference / raw slice)
        if field.interpreter == 'var':
            ref = (field.format or "").strip()
            if ref.startswith("€"):
                ref = ref[1:]

            # Already resolved in the first var pass (raw[...] etc.) → just persist and exit.
            if field.raw_data is not None or ref.startswith("raw["):
                value = field.value if field.value is not None else field.raw_data
                if not getattr(field, "ignore", False):
                    target_dict[field.name] = value
                field.processed = True
                return field, True, endian

            value = target_dict.get(ref)

            # Special-case: addon_data lives at current offset with size defined earlier.
            if value is None and field.name in ("addon_data", "addon_data_raw"):
                size = target_dict.get("addon_size")
                if size is not None:
                    start = bitstate.offset
                    value = raw_data[start:start + size]
                    # Store as hex to stay JSON-friendly
                    target_dict["addon_data_raw"] = value.hex()
                    bitstate.advance_to(start + size, 0)

            field.value = value
            if not getattr(field, "ignore", False):
                target_dict[field.name] = field.value.hex() if isinstance(field.value, (bytes, bytearray)) else field.value
            field.processed = True
            return field, True, endian

        # Bits
        if field.interpreter == 'bits':
            field = DecoderHandler.decode_bits_field(field, raw_data, bitstate)
            if not getattr(field, "ignore", False):
                target_dict[field.name] = field.value
            field.processed = True
            bitstate.debug(f"after {field.name}")
            return field, True, endian

        # Randseq (legacy)
        if field.interpreter == 'randseq_bits':
            field = handle_randseq_bits(field, raw_data, target_dict, bitstate)
            return field, True, endian

        if field.interpreter == 'randseq':
            # Fallback: if name hints at bits, route to bit-handler
            if field.name.startswith("randseq_bits"):
                field = handle_randseq_bits(field, raw_data, target_dict, bitstate)
            else:
                field = handle_randseq(field, raw_data, target_dict, bitstate)
            return field, True, endian

        # Loop
        if field.interpreter == 'loop':
            DecoderHandler.handle_loop(field, raw_data, bitstate, endian, result, target_dict)
            try:
                field.value = target_dict.get(field.target)
            except Exception:
                field.value = None
            field.processed = True
            return field, True, endian

        if field.interpreter == "bitmask":
            DecoderHandler.handle_bitmask(field, raw_data, bitstate, endian, result, target_dict)
            field.processed = True
            return field, True, endian

        if field.interpreter == "if":
            DecoderHandler.handle_if(field, raw_data, bitstate, endian, result, target_dict)
            field.processed = True
            return field, True, endian

        if field.interpreter == "packed_guid":
            DecoderHandler.handle_packed_guid(field, raw_data, bitstate, target_dict)
            field.processed = True
            return field, True, endian

        if field.interpreter == "uncompress":
            DecoderHandler.handle_uncompress(field, raw_data, bitstate, endian, result, target_dict)
            field.processed = True
            return field, True, endian

        # Struct / append / default path
        if field.interpreter == "append":
            field, _, _ = DecoderHandler.decode_struct(field, raw_data, bitstate, endian)
            value = DecoderHandler.apply_modifiers(field)

            if field.name not in target_dict or not isinstance(target_dict[field.name], list):
                target_dict[field.name] = []

            if isinstance(value, tuple):
                target_dict[field.name].extend(value)
            else:
                target_dict[field.name].append(value)

            if not field.ignore:
                # result is stored in target_dict above
                pass

            field.processed = True
            return field, True, endian

        if field.interpreter == 'struct':
            field, value, _ = DecoderHandler.decode_struct(field, raw_data, bitstate, endian)
        else:
            # Default to struct-like unpack if format is set
            if hasattr(field, "format") and field.format:
                field, value, _ = DecoderHandler.decode_struct(field, raw_data, bitstate, endian)
            else:
                value = field.value

        if field.modifiers and field.interpreter != 'bits':
            value = DecoderHandler.apply_modifiers(field)

        field.value = value
        if not field.ignore:
            target_dict[field.name] = field.value

        field.processed = True
        return field, True, endian

    @staticmethod
    def decode(case, silent=False):
        fields = session.fields
        bitstate = BitState()
        raw_data = case[2]
      
        i = 0
        offset = 0  # används bara för randseq/ev. äldre logik
        result = {}
        endian = '<'
        debug_msg = []
        bit_pos = 0
        target_dict = result

        while len(fields) > i:
            field = fields[i]
            size = 0
            
            debug_msg.append(field)
            
            if hasattr(field, "name"):
                Logger.debug(field.name.upper())
            else:
                Logger.debug(f"Unnamed field: {field}")
            Logger.debug(field)
            # använd faktiska läspositionen
            Logger.debug(raw_data[bitstate.offset:])

            if getattr(field, "processed", False):
                continue

            if bitstate.offset >= len(raw_data):
                # Special-case zero-length loops: still record empty list
                if field.interpreter == "loop":
                    try:
                        loop_count = DecoderHandler.resolve_variable(field.count_from, result)
                    except Exception:
                        loop_count = None
                    if loop_count == 0:
                        target_dict[field.target] = []
                        field.value = []
                        field.processed = True
                        i += 1
                        continue
                Logger.warning(f"Ran out of raw data before processing field '{field.name}'. Stopping decode early.")
                break

            field, _, endian = DecoderHandler._process_field(
                field, raw_data, bitstate, endian, result, result
            )

            fields[i] = field
            DebugHelper.trace_field(field, bitstate)
            Logger.to_log('')
            i += 1
        
        try:
            json_output = json.dumps(result, indent=4)
            if not silent:
                Logger.success(f"{case[0]}\n{json_output}")
                Logger.to_log(json_output)
        except TypeError as e:
            Logger.error("FAILED RESULT")
            Logger.error(e)
            Logger.to_log('')
            Logger.to_log(result)
            Logger.to_log('')

            for key, value in result.items():
                if isinstance(value, bytes):
                    Logger.warning(
                        f"Name: '{key}' values is of type bytes: {value} → not JSON serializable. "
                        "Add 's' as the first modifier in def file."
                    )
           # Logger.to_log('')
            for msg in debug_msg:
                 Logger.to_log(msg)

        return result
        
    @staticmethod
    def apply_modifiers(field):
        if not field.modifiers:
            return field.value

        value = field.raw_data

        for mod in field.modifiers:
            func = modifiers_operation_mapping.get(mod)
            if func:
                if mod == "E":
                    # packa värdet som big-endian med rätt format
                    value = func(value, field.format)
                else:
                    value = func(value)

        return value

    @staticmethod
    def resolve_string_format(field, raw_data, offset):
        # hitta nullterminator
        end = offset
        while end < len(raw_data) and raw_data[end] != 0:
            end += 1

        raw = raw_data[offset:end]   # utan null
        value = raw.decode("ascii")

        # längd med NUL
        length = (end - offset) + 1

        # uppdatera field
        field.value = value
        field.raw_length = length     # <-- SUPER VIKTIGT
        field.format = f"{length}s"   # så decode läser exakt length bytes
        field.interpreter = "struct"

        return field
    
    @staticmethod
    def handle_read_rest(field, raw_data, bitstate):
        # Current read start
        start = bitstate.offset
        end = len(raw_data)

        # Extract bytes
        raw = raw_data[start:end]

        # Try UTF-8, fallback to hex
        try:
            value = raw.decode("utf-8")
        except UnicodeDecodeError:
            value = raw.hex()

        length = end - start

        # Update node WITHOUT letting DecoderHandler try to read it again
        field.value = value
        field.raw_length = length
        field.raw_data = raw               # <-- extremely important
        field.format = f"{length}s"        # ensures no re-read
        field.interpreter = "raw"          # <-- disables struct unpack path
        field.raw_offset = start           # mark as fully consumed

        # Move bitstate forward
        bitstate.offset = end
        field.processed = True
        return field

    @staticmethod
    def decode_struct(field, raw_data, bitstate, endian):
        # Ensure we start on a byte boundary before using struct
        bitstate.align_to_byte()

        fmt = field.format
        current_offset = bitstate.offset
        value = None
        size = 0

        try:
            size = struct.calcsize(f'{endian}{fmt}')
            # current_offset already set above

            if len(fmt) > 1 and 's' not in fmt:
                value = struct.unpack_from(f'{endian}{fmt}', raw_data, current_offset)
            else:
                value = struct.unpack_from(f'{endian}{fmt}', raw_data, current_offset)[0]

        except struct.error as e:
            Logger.warning('Struct unpack error')
            Logger.debug(f'fmt: {fmt} | {e}')
            Logger.debug(f'raw_data: {raw_data[bitstate.offset:]}')
            field.raw_offset = current_offset
            field.raw_length = size
            field.raw_data = b""
            field.value = None
            field.processed = True
            return field, None, endian

        if 's' in fmt:
            try:
                value = value.decode("utf-8").strip("\x00")
            except UnicodeDecodeError:
                value = value.hex()
            except AttributeError as e:
                Logger.warning("Struct decode error")
                Logger.debug(f'fmt: {e}')

        # Uppdatera field metadata
        field.value = value
        field.raw_offset = current_offset
        field.raw_length = size
        field.raw_data = raw_data[current_offset:current_offset + size]

        # Flytta bitstate efter läsning
        bitstate.advance_to(current_offset + size, 0)

        return field, value, size

    @staticmethod
    def resolve_variable(key: str, result: dict) -> str | int | float | dict | list | None:
        """
        Resolve a variable from session.variables or result.
        Supports:
        - €key
        - €key[index]
        - €key[index].subkey
        Also supports literals like '1', '3.14'
        """
        global session

        if not isinstance(key, str) or not isinstance(result, dict):
            Logger.warning("Resolve variable failed (invalid key or result)")
            Logger.debug(f"Invalid key or result: {key}, {type(result)}")
            return None

        if key.endswith("'s"):
            key = key[:-2]

        if key.startswith("€"):
            key = key[1:]  # strip the €

            match = re.match(r"^(\w+)(?:\[(\w+)\])?(?:\.(\w+))?$", key)
            if match:
                base, index, subkey = match.groups()

                if base in session.variables:
                    var_node = session.variables[base]
                    val = var_node.value if var_node.value is not None else var_node.raw_value
                elif base in result:
                    val = result[base]
                else:
                    Logger.warning("Resolve variable failed (base not found)")
                    Logger.debug(f"Unknown reference base '{base}'")
                    return None

                if index is not None:
                    idx_val = None
                    if index.isdigit():
                        idx_val = int(index)
                    else:
                        if index in session.variables:
                            node = session.variables[index]
                            idx_val = node.value if node.value is not None else node.raw_value
                        elif index in result:
                            idx_val = result[index]
                    if not isinstance(idx_val, int):
                        Logger.warning(f"Resolve variable failed (invalid index {index})")
                        return None
                    try:
                        val = val[idx_val]
                    except (IndexError, TypeError):
                        Logger.warning(f"Resolve variable failed (invalid index {index})")
                        return None

                if subkey is not None:
                    try:
                        val = val[subkey]
                    except (KeyError, TypeError):
                        Logger.warning(f"Resolve variable failed (missing key '{subkey}')")
                        return None

                return val

            if key in session.variables:
                return session.variables[key].raw_value
            elif key in result:
                return result[key]

            Logger.warning("Resolve variable failed (fallback)")
            Logger.debug(f"Unknown reference '{key}'")
            return None

        # stöd för literals som "1" eller "3.14"
        try:
            return int(key)
        except ValueError:
            try:
                return float(key)
            except ValueError:
                return None

    @staticmethod   
    def evaluate_slice_expression(expr: str, result: dict, raw_data: bytes) -> tuple[bytes, int, int]:
        """
        Evaluates slicing expressions in the form:
        €start:€base+€offset
        €start:€base-€offset

        Returns (raw_data[start:end], start, end)
        """

        match = re.match(r"^raw\[(€\w+):(€\w+)\]$", expr.strip())
        if not match:
            raise ValueError(f"Invalid slice expression: {expr}")

        start_var, end_var = match.groups()

        start = DecoderHandler.resolve_variable(start_var, result)
        end_expr = DecoderHandler.resolve_variable(end_var, result)

        if start is None or end_expr is None:
            raise ValueError(f"Slice variables unresolved in expression: {expr}")

        if isinstance(end_expr, str):
            match = re.fullmatch(r"€(\w+)\s*([+\-*/])\s*€(\w+)", end_expr.strip())
            if match:
                left = DecoderHandler.resolve_variable(f"€{match.group(1)}", result)
                right = DecoderHandler.resolve_variable(f"€{match.group(3)}", result)
                if not all(isinstance(v, int) for v in (left, right)):
                    raise TypeError(f"Slice operands must be integers in expression: {end_expr}")

                op = match.group(2)
                if op == "+":
                    end = left + right
                elif op == "-":
                    end = left - right
                else:
                    raise ValueError(f"Unsupported operator '{op}' in slice expression: {end_expr}")

                return raw_data[start:end], start, end

            try:
                end = int(end_expr)
            except ValueError as exc:
                raise ValueError(f"Unable to evaluate slice end: {end_expr}") from exc
        else:
            end = end_expr

        if not all(isinstance(v, int) for v in (start, end)):
            raise TypeError("Slice operands must resolve to integers")

        return raw_data[start:end], start, end

    
    @staticmethod
    def decode_bits_field(field, raw_data, bitstate):
        if not field.modifiers:
            return field

        raw_start = None
        raw_end = None

        for mod in field.modifiers:
            match = re.fullmatch(r"(\d+)([Bb])", mod)
            if match:
                func = modifiers_operation_mapping[match.group(2)]
                if raw_start is None:
                    raw_start = bitstate.offset

                bits, new_offset, new_bit_pos = func(
                    raw_data,
                    bitstate.offset,
                    bitstate.bit_pos,
                    int(match.group(1))
                )

                raw_end = new_offset + (1 if new_bit_pos > 0 else 0)
                field.value = bits

                bitstate.advance_to(new_offset, new_bit_pos)
                continue

            func = modifiers_operation_mapping.get(mod)
            if func and field.value is not None:
                field.value = func(field.value)

        if raw_start is not None and raw_end is not None:
            field.raw_offset = raw_start
            field.raw_length = raw_end - raw_start
            field.raw_data = raw_data[raw_start:raw_end]

        Logger.debug(field)
        bitstate.debug(f"after {field.name}")
        return field
    
    @staticmethod
    def handle_loop(field, raw_data, bitstate, endian, result, target_dict):
        loop_count = DecoderHandler.resolve_variable(field.count_from, result)
        if isinstance(loop_count, list):
            try:
                # interpret list of bits as binary number
                loop_count = int("".join(str(b) for b in loop_count), 2)
            except Exception:
                loop_count = len(loop_count)
        name = field.target
        target_dict[name] = []

        Logger.debug(f"[Loop] Entering loop '{name}' with {loop_count} iterations")

        # Spara startpositionen för loopen (för ev. debug/info)
        field.raw_offset = bitstate.offset

        if loop_count == 0:
            field.raw_length = 0
            field.value = []
            if not getattr(field, "ignore", False):
                target_dict[name] = []
            return field, True, endian

        for n in range(loop_count):
            # Expose current loop index for formats like €arr[i].len
            session.variables["i"] = VariableNode(
                name="i", raw_value=n, value=n, interpreter="literal"
            )
            if bitstate.offset >= len(raw_data):
                Logger.warning(f"[Loop] '{name}' ran out of raw data at iteration {n}. Stopping loop early.")
                break

            tmp_dict = {}
            Logger.debug(f"[BitState] LOOP {n} START → offset={bitstate.offset}, bit_pos={bitstate.bit_pos}")

            for child_template in field.children:

                # Skapa en ren kopia av noden
                child = child_template.copy()

                child, _, endian = DecoderHandler._process_field(
                    child, raw_data, bitstate, endian, result, tmp_dict
                )
                DebugHelper.trace_field(child, bitstate)

            target_dict[name].append(tmp_dict)

            Logger.debug(f"[BitState] LOOP {n} END   → offset={bitstate.offset}, bit_pos={bitstate.bit_pos}")

        # Uppdatera loopens längd i bytes
        field.raw_length = bitstate.offset - field.raw_offset
        return field, True, endian

    @staticmethod
    def handle_bitmask(field, raw_data, bitstate, endian, result, target_dict):
        """
        Decode a bitmask block: limits child decoding to 'size' bits starting at current position.
        """
        start_offset = bitstate.offset
        start_bit = bitstate.bit_pos
        total_bits = getattr(field, "size", 0) or 0

        end_bit_index = start_offset * 8 + start_bit + total_bits
        end_offset = end_bit_index // 8
        end_bit = end_bit_index % 8

        child_state = BitState()
        child_state.offset = start_offset
        child_state.bit_pos = start_bit

        tmp = {}
        for child_template in getattr(field, "children", []):
            child = child_template.copy()
            DecoderHandler._process_field(child, raw_data, child_state, endian, result, tmp)
            DebugHelper.trace_field(child, child_state)

        bitstate.advance_to(end_offset, end_bit)

        field.raw_offset = start_offset
        field.raw_length = end_offset - start_offset + (1 if end_bit > 0 else 0)
        field.raw_data = raw_data[start_offset:start_offset + field.raw_length]
        field.value = tmp

        if not getattr(field, "ignore", False):
            target_dict[field.name] = tmp

        return field, True, endian

    @staticmethod
    def _eval_condition(condition: str, context: dict) -> bool:
        try:
            return bool(eval(condition, {}, context))
        except Exception:
            return False

    @staticmethod
    def handle_if(field, raw_data, bitstate, endian, result, target_dict):
        """
        Evaluate an IfNode and decode only the matching branch.
        """
        context = {**result, **target_dict}

        branch = None
        if field.condition and DecoderHandler._eval_condition(field.condition, context):
            branch = field.true_branch
        else:
            if field.elif_branches:
                for cond, nodes in field.elif_branches:
                    if DecoderHandler._eval_condition(cond, context):
                        branch = nodes
                        break
            if branch is None:
                branch = field.false_branch or []

        for child_template in branch or []:
            child = child_template.copy()
            DecoderHandler._process_field(child, raw_data, bitstate, endian, result, target_dict)
            DebugHelper.trace_field(child, bitstate)

        return field, True, endian

    @staticmethod
    def handle_packed_guid(field, raw_data, bitstate, target_dict):
        # align to byte
        bitstate.align_to_byte()
        start = bitstate.offset
        if start >= len(raw_data):
            Logger.error("[packed_guid] No data for mask")
            return field, True, '<'

        mask = raw_data[start]
        offset = start + 1
        guid_bytes = [0] * 8
        for i in range(8):
            if mask & (1 << i):
                if offset >= len(raw_data):
                    Logger.error("[packed_guid] Ran out of bytes while reading GUID")
                    break
                guid_bytes[i] = raw_data[offset]
                offset += 1

        bitstate.advance_to(offset, 0)

        guid_int = int.from_bytes(bytes(guid_bytes), "little", signed=False)
        field.value = guid_int
        field.raw_offset = start
        field.raw_length = offset - start
        field.raw_data = raw_data[start:offset]

        if not getattr(field, "ignore", False):
            target_dict[field.name] = guid_int

        return field, True, '<'

    @staticmethod
    def handle_uncompress(field, raw_data, bitstate, endian, result, target_dict):
        """
        Inflate a compressed segment and decode its children from the inflated buffer.
        """
        algo = (getattr(field, "algo", "") or "").lower()
        length_expr = getattr(field, "length_expr", None)

        # Resolve length (literal like 20B, number, or €var)
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
                length = DecoderHandler.resolve_variable(expr, result)

        if length is None:
            length = len(raw_data) - bitstate.offset

        comp_slice = raw_data[bitstate.offset : bitstate.offset + length]
        bitstate.advance_to(bitstate.offset + length, 0)

        if algo != "zlib":
            Logger.error(f"[uncompress] Unsupported algorithm: {algo}")
            return field, True, endian

        try:
            inflated = zlib.decompress(comp_slice)
        except Exception as exc:
            Logger.error(f"[uncompress] Decompress failed: {exc}")
            return field, True, endian

        # Decode children against inflated buffer
        child_state = BitState()
        for child_template in getattr(field, "children", []):
            child = child_template.copy()
            DecoderHandler._process_field(child, inflated, child_state, endian, result, target_dict)
            DebugHelper.trace_field(child, child_state)

        field.raw_data = comp_slice
        field.value = inflated
        return field, True, endian
