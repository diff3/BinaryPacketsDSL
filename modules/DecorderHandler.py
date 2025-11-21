#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from modules.Session import get_session
from modules.ModifierMapping import modifiers_operation_mapping
import struct
import json
from utils.Logger import Logger
import re
from modules.bitsHandler import BitState

# GLOBALS
session = get_session()


class DecoderHandler(): 
    @staticmethod
    def decode(case):
        fields = session.fields
        bitstate = BitState()
        raw_data = case[2]
      
        i = 0
        offset = 0  # används bara för randseq/ev. äldre logik
        result = {}
        endian = '<'
        debug_msg = []
        bit_pos = 0
        target_dict = dict()

        while len(fields) > i:
            field = fields[i]
            size = 0
            
            debug_msg.append(field)
            
            if hasattr(field, "name"):
                Logger.info(field.name.upper())
            else:
                Logger.info(f"Unnamed field: {field}")
            Logger.info(field)
            # använd faktiska läspositionen
            Logger.info(raw_data[bitstate.offset:])

            if bitstate.offset >= len(raw_data):
                Logger.warning(f"Ran out of raw data before processing field '{field.name}'. Stopping decode early.")
                break

            if field.interpreter == 'padding':
                bitstate.align_to_byte()
                Logger.debug(f"[Padding] Advancing offset by {field.value}")
                bitstate.offset += field.value
                i += 1
                Logger.to_log('')
                continue

            if field.interpreter == "append":
                field, _, _ = DecoderHandler.decode_struct(field, raw_data, bitstate, endian)
                value = DecoderHandler.apply_modifiers(field)

                if field.name not in target_dict or not isinstance(target_dict[field.name], list):
                    target_dict[field.name] = []

                # Lägg till alla element individuellt om det är en tuple
                if isinstance(value, tuple):
                    target_dict[field.name].extend(value)
                else:
                    target_dict[field.name].append(value)

                if not field.ignore:
                    result[field.name] = target_dict[field.name]

                i += 1
                Logger.to_log('')
                continue
            

            if field.name == 'seek':
                bitstate.offset = field.value
                i += 1
                Logger.to_log('')
                continue
                
            if field.name == 'endian':
                if field.format == 'little':
                    endian = '<'
                else:
                    endian = '>'
                
                i += 1
                Logger.to_log('')
                continue

            if field.name == "bit_offset":
                global_bit_pos = field.value  # används ev. senare

            if field.interpreter == 'var':
                value = DecoderHandler.resolve_variable(field.format, result)

                if isinstance(value, str):
                    # värdet är en variabel som själv refererar till raw-slice
                    if value.endswith("raw"):
                        value = DecoderHandler.resolve_variable(value, result)

                    # raw-slice-uttryck
                    if value.startswith("raw["):
                        slice_bytes, start, end = DecoderHandler.evaluate_slice_expression(value, result, raw_data)
                        value = slice_bytes.hex()

                        field.raw_offset = start
                        field.raw_length = end - start
                        field.raw_data = slice_bytes

                        bitstate.advance_to(end, 0)
                        offset = end  # mest legacy/logg, bitstate styr verklig position
                
                field.value = value

            if field.interpreter == 'dynamic':
                length = DecoderHandler.resolve_variable(field.format, result)
                if length is None:
                    Logger.warning(f"Failed to resolve dynamic field: {field.name}")
                    return field

                field.interpreter = 'struct'
                field.format = f"{length}s"
                    

            if field.format == 'S':
                # använd bitstate.offset som start
                field = DecoderHandler.resolve_string_format(field, raw_data, bitstate.offset)

            if field.interpreter == 'bits':
                field = DecoderHandler.decode_bits_field(field, raw_data, bitstate)

                if not getattr(field, "ignore", False):
                    fields[i] = field
                    result[field.name] = field.value

                i += 1
                Logger.debug(field)
                bitstate.debug(f"after {field.name}")
                Logger.to_log('')
                continue

            if field.interpreter == 'randseq':
                randseq_size = field.count_from

                for child in field.children:
                    fmt = child.format.strip()

                    range_match = re.fullmatch(r"(\d+)-(\d+)'?", fmt)

                    if range_match:
                        start = int(range_match.group(1))
                        end = int(range_match.group(2))
                        child.value = int.from_bytes(raw_data[start:end], byteorder="little")
                    else:
                        positions = list(map(int, fmt.split()))
                        child.value = "".join(f"{raw_data[pos]:02X}" for pos in positions)
                 
                    result[child.name] = child.value

                offset += randseq_size  # påverkar bara denna lokala offset, inte bitstate
                i += 1
                
                Logger.debug(field)
                Logger.to_log('')
                continue

            if field.interpreter == 'loop':
                DecoderHandler.handle_loop(field, raw_data, bitstate, endian, result, result)
                i += 1
                Logger.debug(field)
                Logger.to_log('')
                continue

            if field.interpreter == 'struct':
                field, value, size = DecoderHandler.decode_struct(field, raw_data, bitstate, endian)

            # using raw data to modify (bits already handled in decode_bits_field)
            if field.modifiers and field.interpreter != 'bits':
                value = DecoderHandler.apply_modifiers(field)
       
            field.value = value
            if not field.ignore:
                result[field.name] = field.value

            fields[i] = field
            Logger.debug(field)
            Logger.to_log('')

            i += 1
        
        try:
            json_output = json.dumps(result, indent=4)
            Logger.success(f"{case[0]}")
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
            Logger.to_log('')
            for msg in debug_msg:
                 Logger.to_log(msg)

        return result
    
    @staticmethod
    def apply_modifiers(field):
        # Om inga modifiers finns, returnera direkt
        if not field.modifiers:
            return field.value

        # Börja alltid från raw_data (bytes eller lista av bitar)
        value = field.raw_data

        # Applicera varje modifier i ordning
        for mod in field.modifiers:
            func = modifiers_operation_mapping.get(mod)
            if func:
                value = func(value)

        return value

    @staticmethod
    def resolve_string_format(field, raw_data, offset):
        string_data = raw_data[offset:].split(b'\x00')[0]
        length = len(string_data) + 1  # include null terminator
        field.format = f"{length}s"
        field.interpreter = 'struct'  # säkerställ rätt hantering
        return field

    @staticmethod
    def decode_struct(field, raw_data, bitstate, endian):
        # Ensure we start on a byte boundary before using struct
        bitstate.align_to_byte()

        fmt = field.format
        value = None

        try:
            size = struct.calcsize(f'{endian}{fmt}')
            current_offset = bitstate.offset  # spara innan vi flyttar på det

            if len(fmt) > 1 and 's' not in fmt:
                value = struct.unpack_from(f'{endian}{fmt}', raw_data, current_offset)
            else:
                value = struct.unpack_from(f'{endian}{fmt}', raw_data, current_offset)[0]

        except struct.error as e:
            Logger.warning('Struct unpack error')
            Logger.debug(f'fmt: {fmt} | {e}')
            Logger.info(f'raw_data: {raw_data[bitstate.offset:]}')

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

            match = re.match(r"^(\w+)(?:\[(\d+)\])?(?:\.(\w+))?$", key)
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
                    try:
                        val = val[int(index)]
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
        name = field.target
        target_dict[name] = []

        Logger.debug(f"[Loop] Entering loop '{name}' with {loop_count} iterations")

        # Spara startpositionen för loopen (för ev. debug/info)
        field.raw_offset = bitstate.offset

        for n in range(loop_count):
            if bitstate.offset >= len(raw_data):
                Logger.warning(f"[Loop] '{name}' ran out of raw data at iteration {n}. Stopping loop early.")
                break

            tmp_dict = {}
            Logger.debug(f"[BitState] LOOP {n} START → offset={bitstate.offset}, bit_pos={bitstate.bit_pos}")

            for child_template in field.children:

                # Skapa en ren kopia av noden
                child = child_template.copy()

                if child.interpreter == 'padding':
                    bitstate.align_to_byte()
                    Logger.debug(f"[Padding] Advancing offset by {child.value}")

                    if child.value and child.value > 0:
                        bitstate.offset += child.value
                    continue

                if child.interpreter == 'append':
                    child, _, _ = DecoderHandler.decode_struct(child, raw_data, bitstate, endian)
                    value = DecoderHandler.apply_modifiers(child)

                    if not child.ignore:
                        if child.name not in tmp_dict or not isinstance(tmp_dict[child.name], list):
                            tmp_dict[child.name] = []

                        if isinstance(value, tuple):
                            tmp_dict[child.name].extend(value)
                        else:
                            tmp_dict[child.name].append(value)
                    continue

                if child.interpreter == 'dynamic':
                    length = DecoderHandler.resolve_variable(child.format, result)
                    if length is None:
                        Logger.warning(f"Failed to resolve dynamic field: {child.name}")
                        continue
                    child.interpreter = 'struct'
                    child.format = f"{length}s"

                if child.format == 'S':
                    child = DecoderHandler.resolve_string_format(child, raw_data, bitstate.offset)
                    bitstate.align_to_byte()

                if child.interpreter == 'struct':
                    child, _, _ = DecoderHandler.decode_struct(child, raw_data, bitstate, endian)

                elif child.interpreter == 'bits':
                    child = DecoderHandler.decode_bits_field(child, raw_data, bitstate)

                elif child.interpreter == 'loop':
                    DecoderHandler.handle_loop(child, raw_data, bitstate, endian, result, tmp_dict)
                    child.value = tmp_dict.get(child.target)
                    continue

                # using raw data to modify (skip; bits are already converted inside decode_bits_field)
                if child.modifiers and child.interpreter != 'bits':
                    child.value = DecoderHandler.apply_modifiers(child)

                if not child.ignore:
                    tmp_dict[child.name] = child.value

                Logger.debug(child)
                bitstate.debug(f"after {child.name}")

            target_dict[name].append(tmp_dict)

            Logger.debug(f"[BitState] LOOP {n} END   → offset={bitstate.offset}, bit_pos={bitstate.bit_pos}")

        # Uppdatera loopens längd i bytes
        field.raw_length = bitstate.offset - field.raw_offset