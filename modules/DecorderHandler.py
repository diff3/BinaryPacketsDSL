#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from modules.Session import get_session
from modules.ModifierMapping import modifiers_operation_mapping
import struct
import json
from utils.Logger import Logger
import re

# GLOBALS
session = get_session()


class DecoderHandler(): 

    @staticmethod
    def decode(case):
        fields = session.fields
        # raw_data = session.raw_data

        raw_data = case[2]

        i = 0
        offset = 0
        result = {}
        endian = '<'
        debug_msg = []
        bit_pos = 0

        while len(fields) > i:
            field = fields[i]
            size = 0
            
            debug_msg.append(field)
            Logger.info(field.name.upper())
            Logger.info(field)
            Logger.info(raw_data[offset:])

            if field.ignore == True:
                i += 1
                ignore_size = struct.calcsize(f'{endian}{field.format}')
                offset += ignore_size
                
                # Logger.debug(field)
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
                fmt = str(length) + "s"
                field.interpreter = 'struct'
                field.format = fmt
        

            if field.format == 'S':
                field = DecoderHandler.resolve_string_format(field, raw_data, offset)

            if field.interpreter == 'bits':
                byte_pos = offset
                fmt = field.format

                for mod in field.modifiers:
                    match = re.fullmatch(r"(\d+)([B])", mod)
                    
                    if match:
                        func = modifiers_operation_mapping[match.group(2)]
                        bits, byte_pos, bit_pos = func(raw_data, byte_pos, bit_pos, int(match.group(1)))

                        size = struct.calcsize(f'{endian}{fmt}')

                        field.raw_data = raw_data[offset:offset + size]
                        field.raw_offset = offset
                        field.raw_length = size
                        field.value = bits
                    else:
                        func = modifiers_operation_mapping[mod]
                        field.value = func(field.value)

                fields[i] = field
                result[field.name] = field.value
                i += 1

                if not fields[i].interpreter == 'bits':
                    offset = byte_pos + 1

                Logger.debug(field)
                Logger.to_log('')
                continue
            else:
                bit_pos = 0
        
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
                loop_count = DecoderHandler.resolve_variable(field.count_from, result)
                name = field.target
                result[name] = []
                loop_offset = offset  

                for n in range(loop_count):
                    t = 0
                    tmp_dict = {}
                    while t < len(field.children):
                        child = field.children[t]
                        if child.format == 'S':
                            child = DecoderHandler.resolve_string_format(child, raw_data, loop_offset)

                        child, value, size = DecoderHandler.decode_struct(child, raw_data, loop_offset, endian)
                        loop_offset += size 

                        child.value = DecoderHandler.apply_modifiers(child)
                        tmp_dict[child.name] = child.value
                        field.children[t] = child
                        t += 1
                    result[name].append(tmp_dict)

                offset = loop_offset  
                i += 1
                
                Logger.debug(field)
                Logger.to_log('')
                continue

            if field.interpreter == 'struct':
                field, value, size = DecoderHandler.decode_struct(field, raw_data, offset, endian)
                offset += size

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
        if not field.modifiers:
            return field.value

        value = field.raw_data

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
    def decode_struct(field, raw_data, offset, endian):
        fmt = field.format
        value = None

        try:
            size = struct.calcsize(f'{endian}{fmt}')
            
            if len(fmt) > 1 and not 's' in fmt:
                value = struct.unpack_from(f'{endian}{fmt}', raw_data, offset)
            else:
                value = struct.unpack_from(f'{endian}{fmt}', raw_data, offset)[0]
        except struct.error as e:
            Logger.warning('Struct unpack error')
            Logger.debug(f'fmt: {fmt} | {e}')
            Logger.info(f'raw_data: {raw_data[offset:]}')

        if 's' in fmt:
            try:
                value = value.decode("utf-8").strip("\x00")
            except UnicodeDecodeError:
                value = value.hex()
            except AttributeError as e:
                Logger.warning("Struct decode error")
                Logger.debug(f'fmt: {e}')

        field.raw_data = raw_data[offset:offset + size]
        field.raw_offset = offset
        field.raw_length = size
        field.value = value

        return field, value, size

    @staticmethod
    def resolve_variable(key: str, result: dict) -> str:
        """
        Resolve a variable value from session.variables or the result dict.
        Only supports direct variable references like '€var'.
        """
        global session

        if not isinstance(key, str) or not isinstance(result, dict):
            Logger.warning("Resolve variable failed")
            Logger.debug(f"Invalid key or result: {key}, {type(result)}")
            return None

        if not key.startswith('€'):
            return None

        if key.endswith("'s"):
            key = key[:-2]

        key = key[1:]

        if key in session.variables:
            return session.variables[key].raw_value
        elif key in result:
            return result[key]
        else:
            Logger.warning("Resolve variable failed")
            Logger.debug(f"Unknown reference '{key}'")
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

            