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
        offset = 0
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
            Logger.info(raw_data[offset:])

            if field.ignore == True:
                i += 1
                ignore_size = struct.calcsize(f'{endian}{field.format}')
                offset += ignore_size
                
                # Logger.debug(field)
                Logger.to_log('')
                continue 

            if field.interpreter == 'padding':
                bitstate.align_to_byte()
                Logger.debug(f"[Padding] Advancing offset by {field.value}")
                
                if field.value > 0:
                    field.value -= 1

                bitstate.offset += field.value 
                i += 1
                Logger.to_log('')
                continue

            if field.interpreter == "append":
                field, _, _ = DecoderHandler.decode_struct(field, raw_data, bitstate, endian)
                value = DecoderHandler.apply_modifiers(field)

                if field.name not in target_dict or not isinstance(target_dict[field.name], list):
                    target_dict[field.name] = []

                # ✅ Lägg till alla element individuellt om det är en tuple
                if isinstance(value, tuple):
                    target_dict[field.name].extend(value)
                else:
                    target_dict[field.name].append(value)

                if not field.name.startswith("_"):
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
                # Logger.debug(field)
                Logger.to_log('')
                continue

            if field.name == "bit_offset":
                global_bit_pos = field.value

            if field.interpreter == 'var':
                
                # else:
                value = DecoderHandler.resolve_variable(field.format, result)

                if isinstance(value, str):
                    # Om värdet är en variabel som själv refererar till raw-slice
                    if value.endswith("raw"):
                        # Logger.debug(f"[var→indirect] Resolving value: {value}")
                        value = DecoderHandler.resolve_variable(value, result)

                    # Om värdet är ett raw-slice-uttryck
                    if value.startswith("raw["):
                        # Logger.debug(f"[var→slice] Evaluating raw slice: {value}")
                        value, size = DecoderHandler.evaluate_slice_expression(value, result, raw_data)
                        value = value.hex()

                        offset += size 
                
                field.value = value


            if field.interpreter == 'dynamic':
                length = DecoderHandler.resolve_variable(field.format, result)
                if length is None:
                    Logger.warning(f"Failed to resolve dynamic field: {field.name}")
                    return field

                field.interpreter = 'struct'
                field.format = f"{length}s"
                    

            if field.format == 'S':
                field = DecoderHandler.resolve_string_format(field, raw_data, offset)

            if field.interpreter == 'bits':
                fmt = field.format

                for mod in field.modifiers:
                    match = re.fullmatch(r"(\d+)([Bb])", mod)
                    if match:
                        # 📌 Spara offset före läsning
                        current_offset = bitstate.offset
                        current_bit_pos = bitstate.bit_pos

                        func = modifiers_operation_mapping[match.group(2)]
                        bits, new_offset, new_bit_pos = func(
                            raw_data,
                            current_offset,
                            current_bit_pos,
                            int(match.group(1))
                        )

                        consumed_bytes = (new_offset - current_offset) + (1 if new_bit_pos > 0 else 0)

                        field.raw_data = raw_data[current_offset : current_offset + consumed_bytes]
                        field.raw_offset = current_offset
                        field.raw_length = consumed_bytes
                        field.value = bits

                        # 🟢 Uppdatera bitstate
                        bitstate.advance_to(new_offset, new_bit_pos)

                    else:
                        func = modifiers_operation_mapping[mod]
                        field.value = func(field.value)

                # 🚫 Hoppa över fält som börjar med "_" eller ignore=True
                if not field.name.startswith("_") and not getattr(field, "ignore", False):
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

                offset += randseq_size
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

                # offset hanteras internt i bitstate – inget offset += size behövs

            # using raw data to modify
            if field.modifiers:
                value = DecoderHandler.apply_modifiers(field)
       
            field.value = value
            result[field.name] = field.value

            fields[i] = field
            Logger.debug(field)
            Logger.to_log('')

            i += 1
        
        try:
            json_output = json.dumps(result, indent=4)
            Logger.success("RESULT")
            Logger.to_log(json_output)
        except TypeError as e:
            Logger.error("FAILED RESULT")
            Logger.error(e)
            Logger.to_log('')
            Logger.to_log(result)
            Logger.to_log('')

            for key, value in result.items():
                if isinstance(value, bytes):
                    Logger.warning(f"Name: '{key}' values is of type bytes: {value} → not JSON serializable. Add 's' as the first modifier in def file.")
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
        fmt = field.format
        value = None

        try:
            size = struct.calcsize(f'{endian}{fmt}')
            current_offset = bitstate.offset  # 🟢 Spara innan vi flyttar på det

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

        # 🟢 Uppdatera field metadata
        field.value = value
        field.raw_offset = current_offset
        field.raw_length = size
        field.raw_data = raw_data[current_offset:current_offset + size]

        # 🟢 Flytta bitstate efter läsning
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
                    val = session.variables[base].value
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

        # 💡 Nytt: stöd för literals som "1" eller "3.14"
        try:
            return int(key)
        except ValueError:
            try:
                return float(key)
            except ValueError:
                return None

    @staticmethod   
    def evaluate_slice_expression(expr: str, result: dict, raw_data: bytes) -> bytes:
        """
        Evaluates slicing expressions in the form:
        €start:€base+€offset
        €start:€base-€offset

        Returns raw_data[start:end]
        """

        match = re.match(r"^raw\[(€\w+):(\€\w+)\]$", expr.strip())
        if not match:
            raise ValueError(f"Invalid slice expression: {expr}")

        start_var, end_var = match.groups()

        start = DecoderHandler.resolve_variable(f"{start_var}", result)
        ends = DecoderHandler.resolve_variable(f"{end_var}", result)

        # offset = DecoderHandler.resolve_variable(f"€{offset_var}", parsed_data)

        match = re.fullmatch(r"€(\w+)\s*([+\-*/])\s*€(\w+)", ends.strip())

        if match:
            var1, op, var2 = match.groups()
            left = DecoderHandler.resolve_variable(f"€{var1}", result)
            right = DecoderHandler.resolve_variable(f"€{var2}", result)

            if all(isinstance(v, int) for v in [left, right]):
                value = eval(f"{left}{op}{right}")
            else:
                Logger.warning(f"Non-integer values in expression: {expr}")

            # return value
            return raw_data[start:value], right

        """if not all(isinstance(x, int) for x in (start, base, offset)):
            raise TypeError("Slice operands must resolve to integers")

        end = base + offset if operator == "+" else base - offset"""
        return None

    
    @staticmethod
    def decode_bits_field(field, raw_data, bitstate):
        fmt = field.format

        for mod in field.modifiers:
            match = re.fullmatch(r"(\d+)([Bb])", mod)
            if match:
                func = modifiers_operation_mapping[match.group(2)]
                bits, new_offset, new_bit_pos = func(
                    raw_data,
                    bitstate.offset,
                    bitstate.bit_pos,
                    int(match.group(1))
                )

                consumed_bytes = (new_offset - bitstate.offset) + (1 if new_bit_pos > 0 else 0)

                field.raw_data = raw_data[bitstate.offset : bitstate.offset + consumed_bytes]
                field.raw_offset = bitstate.offset
                field.raw_length = consumed_bytes
                field.value = bits

                bitstate.advance_to(new_offset, new_bit_pos)

            else:
                func = modifiers_operation_mapping[mod]
                field.value = func(field.value)

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
            tmp_dict = {}
            Logger.debug(f"[BitState] LOOP {n} START → offset={bitstate.offset}, bit_pos={bitstate.bit_pos}")

            for child_template in field.children:

                # Skapa en ren kopia av noden
                child = child_template.copy()

                # ✅ Ny kod som efterliknar decode()
                if child.ignore:
                    continue

                if child.interpreter == 'padding':
                    bitstate.align_to_byte()
                    Logger.debug(f"[Padding] Advancing offset by {child.value}")

                    if child.value and child.value > 0:
                        bitstate.offset += child.value
                    continue

                if child.interpreter == 'append':
                    child, _, _ = DecoderHandler.decode_struct(child, raw_data, bitstate, endian)
                    value = DecoderHandler.apply_modifiers(child)

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

                # using raw data to modify
                if child.modifiers:
                    child.value = DecoderHandler.apply_modifiers(child)

                if not child.name.startswith("_"):
                    tmp_dict[child.name] = child.value

                Logger.debug(child)
                bitstate.debug(f"after {child.name}")

            target_dict[name].append(tmp_dict)

            Logger.debug(f"[BitState] LOOP {n} END   → offset={bitstate.offset}, bit_pos={bitstate.bit_pos}")

        # Uppdatera loopens längd i bytes
        field.raw_length = bitstate.offset - field.raw_offset