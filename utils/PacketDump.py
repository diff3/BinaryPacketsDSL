#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import time
from pathlib import Path


def bytes_to_spaced_hex(data: bytes) -> str:
    h = data.hex().upper()
    return " ".join(a + b for a, b in zip(h[0::2], h[1::2]))


def bytes_to_bits(data: bytes) -> str:
    return " ".join(f"{b:08b}" for b in data)


def bytes_to_hex_offsets(data: bytes, width=16):
    out = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset+width]

        hex_part = " ".join(f"{b:02X}" for b in chunk)
        pad = "   " * (width - len(chunk))
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)

        out.append(f"{offset:04X}: {hex_part}{pad}  {ascii_part}")

    return out


def bytes_to_ascii(data: bytes) -> str:
    return "".join(chr(b) if 32 <= b <= 126 else "." for b in data)


class PacketDump:
    """Handles writing of:
       - raw bin
       - parsed json
       - debug json (hex/ascii/offsets/bits)
    """

    def __init__(self, root):
        self.root = Path(root)
        (self.root / "bin").mkdir(parents=True, exist_ok=True)
        (self.root / "json").mkdir(parents=True, exist_ok=True)
        (self.root / "debug").mkdir(parents=True, exist_ok=True)

    # -----------------------------------------------------

    def dump_bin(self, name: str, ts: int, data: bytes) -> Path:
        path = self.root / "bin" / f"{ts}_{name}.bin"
        path.write_bytes(data)
        return path

    # -----------------------------------------------------

    def dump_json(self, name: str, ts: int, decoded: dict) -> Path:
        path = self.root / "json" / f"{ts}_{name}.json"
        path.write_text(json.dumps(decoded, indent=2))
        return path

    # -----------------------------------------------------

    def dump_debug(self, name: str, ts: int, data: bytes) -> Path:
        info = {
            "name": name,
            "hex_spaced": bytes_to_spaced_hex(data),
            "hex_compact": data.hex().upper(),
            "hex_offsets": bytes_to_hex_offsets(data),
            "ascii": bytes_to_ascii(data),
            "bits": bytes_to_bits(data),
            "size_bytes": len(data),
        }

        path = self.root / "debug" / f"{ts}_{name}.json"
        path.write_text(json.dumps(info, indent=2))
        return path

    # -----------------------------------------------------

    def dump_fixed(self, case_name: str, data: bytes, decoded: dict):
        """Overwrite existing bin/json/debug using only packet name."""

        # bin
        bin_path = self.root / "bin" / f"{case_name}.bin"
        bin_path.write_bytes(data)

        # parsed JSON
        json_path = self.root / "json" / f"{case_name}.json"
        json_path.write_text(json.dumps(decoded, indent=2))

        # debug-json
        dbg = {
            "name": case_name,
            "hex_spaced": bytes_to_spaced_hex(data),
            "hex_compact": data.hex().upper(),
            "hex_offsets": bytes_to_hex_offsets(data),
            "ascii": bytes_to_ascii(data),
            "bits": bytes_to_bits(data),
            "size_bytes": len(data),
        }
        dbg_path = self.root / "debug" / f"{case_name}.json"
        dbg_path.write_text(json.dumps(dbg, indent=2))

        return bin_path, json_path, dbg_path


# ==============================================================
# CAPTURE DUMPER — always writes into ./captures/
# ==============================================================

def dump_capture(case_name: str, data: bytes, decoded: dict):
    root = Path("captures")
    (root / "bin").mkdir(parents=True, exist_ok=True)
    (root / "json").mkdir(parents=True, exist_ok=True)
    (root / "debug").mkdir(parents=True, exist_ok=True)

    bin_path = root / "bin" / f"{case_name}.bin"
    json_path = root / "json" / f"{case_name}.json"
    dbg_path = root / "debug" / f"{case_name}.json"

    # bin
    bin_path.write_bytes(data)

    # parsed JSON
    json_path.write_text(json.dumps(decoded, indent=2))

    # debug json
    dbg = {
        "name": case_name,
        "hex_spaced": bytes_to_spaced_hex(data),
        "hex_compact": data.hex().upper(),
        "hex_offsets": bytes_to_hex_offsets(data),
        "ascii": bytes_to_ascii(data),
        "bits": bytes_to_bits(data),
        "size_bytes": len(data),
    }
    dbg_path.write_text(json.dumps(dbg, indent=2))

    return bin_path, json_path, dbg_path