#!/usr/bin/env python3

import sys
from pathlib import Path
import json

# Add project root to sys.path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from utils.ConfigLoader import ConfigLoader


def bytes_to_spaced_hex(data: bytes) -> str:
    """Return bytes as spaced uppercase hex."""
    h = data.hex().upper()
    return " ".join(a + b for a, b in zip(h[0::2], h[1::2]))


def bytes_to_bits(data: bytes) -> str:
    """Return bytes as spaced 8-bit groups."""
    return " ".join(f"{b:08b}" for b in data)


def bytes_to_hex_offsets(data: bytes, width=16):
    """Return classic hexdump-style rows with offsets + ASCII column."""
    out = []
    length = len(data)

    for offset in range(0, length, width):
        chunk = data[offset:offset+width]

        # Hex bytes
        hex_part = " ".join(f"{b:02X}" for b in chunk)

        # Pad last line so ASCII lines up
        pad = "   " * (width - len(chunk))

        # ASCII printable view
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)

        # Compose line
        out.append(f"{offset:04X}: {hex_part}{pad}  {ascii_part}")

    return out



def bytes_to_ascii(data: bytes) -> str:
    """Convert bytes to printable ASCII, replace others with '.'."""
    return "".join(chr(b) if 32 <= b <= 126 else "." for b in data)


def main():
    config = ConfigLoader.get_config()
    program = config["program"]
    version = str(config["version"])

    root = Path("packets") / program / version
    bin_dir = root / "bin"
    dbg_dir = root / "debug"

    dbg_dir.mkdir(exist_ok=True)

    for f in bin_dir.glob("*.bin"):
        data = f.read_bytes()

        info = {
            "name": f.stem,
            "hex_spaced": bytes_to_spaced_hex(data),
            "hex_compact": data.hex().upper(),
            "hex_offsets": bytes_to_hex_offsets(data),
            "ascii": bytes_to_ascii(data),
            "bits": bytes_to_bits(data),
            "size_bytes": len(data),
            "program": program,
            "version": version,
        }

        out = dbg_dir / (f.stem + ".json")
        out.write_text(json.dumps(info, indent=2))
        print("wrote", out)


if __name__ == "__main__":
    main()
