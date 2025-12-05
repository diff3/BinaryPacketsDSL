#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re

from utils.Logger import Logger
from modules.bitsHandler import BitInterPreter


def handle_randseq(field, raw_data, target_dict, bitstate=None):
    """
    Legacy randseq handler. Reads arbitrary positions/ranges from raw_data
    and stores values directly into target_dict.
    """
    randseq_size = field.count_from

    for child in field.children:
        fmt = child.format.strip()
        range_match = re.fullmatch(r"(\d+)-(\d+)'?", fmt)

        if range_match:
            start = int(range_match.group(1))
            end = int(range_match.group(2))
            child.value = int.from_bytes(raw_data[start:end], byteorder="little")
        else:
            try:
                positions = list(map(int, fmt.split()))
            except ValueError:
                Logger.warning(f"[RandSeq] Invalid format '{fmt}' in {child.name}")
                continue
            child.value = "".join(f"{raw_data[pos]:02X}" for pos in positions)

        target_dict[child.name] = child.value

    # Mark field as processed and note length (legacy behaviour)
    field.raw_length = randseq_size
    field.processed = True

    # Advance shared bitstate so subsequent fields read from the right offset.
    if bitstate is not None:
        bitstate.advance_to(bitstate.offset + randseq_size, 0)

    return field


def handle_randseq_bits(field, raw_data, target_dict, bitstate=None):
    """
    Bit-level randseq handler.

    Stödjer extra modifiers:
        M     = mirror hela bitlistan
        Xm    = mirror i grupper om X bitar (t.ex '8m', '16m')
    """
    if bitstate is None:
        Logger.error("[RandSeqBits] Missing bitstate")
        return field

    total_bits = field.count_from

    # --- Läs bitblock LSB-first (korrekt för WriteBits LE) ---
    value, new_offset, new_bit_pos = BitInterPreter.read_bits_le(
        raw_data, bitstate.offset, bitstate.bit_pos, total_bits
    )

    # bit_list[i] = i:e skrivna biten (LE)
    bit_list = [(value >> i) & 1 for i in range(total_bits)]

    # --- Modifier parsing ---
    mods = getattr(field, "modifiers", [])

    # 1. Mirror hela blocket ("M")
    if any(m.lower() == "m" for m in mods):
        bit_list.reverse()

    # 2. Mirror grupper ("Xm")
    for m in mods:
        if m.endswith("m") and m.lower() != "m":
            try:
                group_size = int(m[:-1])  # "8m" => 8
                if group_size > 0:
                    bit_list = mirror_in_groups(bit_list, group_size)
            except ValueError:
                Logger.warning(f"[RandSeqBits] Invalid group mirror modifier '{m}'")

    # --- Extrahera barn ---
    for child in field.children:
        fmt = child.format.strip()
        range_match = re.fullmatch(r"(\d+)-(\d+)'?", fmt)

        try:
            if range_match:
                start = int(range_match.group(1))
                end = int(range_match.group(2))
                positions = list(range(start, end + 1))
            else:
                positions = list(map(int, fmt.split()))
        except ValueError:
            Logger.warning(f"[RandSeqBits] Invalid format '{fmt}' in {child.name}")
            continue

        # ska vi returnera som lista eller numeriskt värde?
        want_list = any(mod.lower() in ("list", "l") for mod in getattr(child, "modifiers", []))

        if want_list:
            child.value = [bit_list[pos] if pos < len(bit_list) else 0 for pos in positions]
        else:
            out_val = 0
            for idx, pos in enumerate(positions):
                if pos >= len(bit_list):
                    Logger.warning(f"[RandSeqBits] Pos {pos} out of range in {child.name}")
                    continue
                out_val |= (bit_list[pos] << idx)
            child.value = out_val

        target_dict[child.name] = child.value

    # --- Avsluta ---
    field.raw_length = total_bits
    field.processed = True
    bitstate.advance_to(new_offset, new_bit_pos)

    return field


def mirror_in_groups(bits: list[int], group_size: int) -> list[int]:
    """
    Speglar listan i grupper om group_size.
    Exempel:
        bits = [0,1,2,3,4,5,6,7]
        group_size = 4
        → [3,2,1,0, 7,6,5,4]
    """
    out = []
    for i in range(0, len(bits), group_size):
        chunk = bits[i:i+group_size]
        out.extend(reversed(chunk))
    return out