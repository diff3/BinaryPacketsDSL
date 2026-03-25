#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import sys
from collections import Counter
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any

from colorama import Fore, Style, init
init(autoreset=True)


# --------------------------------------------------
# Helpers
# --------------------------------------------------

def hex_to_bytes(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str.replace(" ", "").strip())


def byte_to_ascii(b: int) -> str:
    return chr(b) if 32 <= b <= 126 else "."


def color_byte(ba, bb):
    if ba is None:
        return f"{Fore.BLACK}--{Style.RESET_ALL}"
    if ba == bb:
        return f"{Fore.GREEN}{ba:02X}{Style.RESET_ALL}"
    return f"{Fore.RED}{ba:02X}{Style.RESET_ALL}"


def color_ascii(ba, bb):
    if ba is None:
        return " "
    c = byte_to_ascii(ba)
    if ba == bb:
        return f"{Fore.GREEN}{c}{Style.RESET_ALL}"
    return f"{Fore.RED}{c}{Style.RESET_ALL}"


def load_packet(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    hex_data = (
        data.get("hex_compact")
        or data.get("hex_spaced")
        or data.get("raw_data_hex")
    )

    payload = hex_to_bytes(hex_data)

    return {
        "path": path,
        "name": data.get("name", "<unknown>"),
        "bytes": payload,
        "size": len(payload),
        "opcode": data.get("raw_opcode_int"),
        "header_mode": data.get("header_mode"),
    }


def similarity_score(a: bytes, b: bytes) -> float:
    max_len = max(len(a), len(b))
    same = sum(1 for i in range(min(len(a), len(b))) if a[i] == b[i])
    return (same / max_len) * 100.0 if max_len else 100.0


def longest_common_block(a: bytes, b: bytes):
    m = SequenceMatcher(None, a, b, autojunk=False)
    match = m.find_longest_match(0, len(a), 0, len(b))
    return match.a, match.b, match.size


# --------------------------------------------------
# Compare mode
# --------------------------------------------------

def print_header(packet_a, packet_b):
    print(f"\n{Fore.CYAN}=== PACKET SUMMARY ==={Style.RESET_ALL}\n")

    print(f"A: {packet_a['name']} ({packet_a['size']} bytes)")
    print(f"B: {packet_b['name']} ({packet_b['size']} bytes)\n")

    score = similarity_score(packet_a["bytes"], packet_b["bytes"])
    print(f"Similarity: {Fore.YELLOW}{score:.2f}%{Style.RESET_ALL}")

    a_idx, b_idx, size = longest_common_block(packet_a["bytes"], packet_b["bytes"])
    print(f"Longest common block: size={size} (A@{a_idx}, B@{b_idx})\n")


def chunk_view(packet_a, packet_b, width=16):
    a = packet_a["bytes"]
    b = packet_b["bytes"]
    max_len = max(len(a), len(b))

    print(f"\n{Fore.CYAN}=== SIDE-BY-SIDE HEX VIEW ==={Style.RESET_ALL}\n")

    for offset in range(0, max_len, width):
        row_a = []
        row_b = []
        asc_a = []
        asc_b = []

        for i in range(width):
            idx = offset + i

            ba = a[idx] if idx < len(a) else None
            bb = b[idx] if idx < len(b) else None

            row_a.append(color_byte(ba, bb))
            row_b.append(color_byte(bb, ba))

            asc_a.append(color_ascii(ba, bb))
            asc_b.append(color_ascii(bb, ba))

        print(
            f"{offset:04X}  "
            + " ".join(row_a)
            + "  "
            + "".join(asc_a)
            + " | "
            + " ".join(row_b)
            + "  "
            + "".join(asc_b)
        )


def diff_packets(packet_a, packet_b):
    a = packet_a["bytes"]
    b = packet_b["bytes"]
    max_len = max(len(a), len(b))

    print(f"\n{Fore.CYAN}=== PACKET DIFF ==={Style.RESET_ALL}\n")

    diff_count = 0

    for i in range(max_len):
        ba = a[i] if i < len(a) else None
        bb = b[i] if i < len(b) else None

        if ba != bb:
            diff_count += 1

            hex_a = f"{ba:02X}" if ba is not None else "--"
            hex_b = f"{bb:02X}" if bb is not None else "--"

            asc_a = byte_to_ascii(ba) if ba else "-"
            asc_b = byte_to_ascii(bb) if bb else "-"

            print(
                f"{i:04d}  "
                f"A:{Fore.RED}{hex_a}{Style.RESET_ALL} ({asc_a})   "
                f"B:{Fore.RED}{hex_b}{Style.RESET_ALL} ({asc_b})"
            )

    color = Fore.GREEN if diff_count == 0 else Fore.RED
    print(f"\nTotal differences: {color}{diff_count}{Style.RESET_ALL}\n")


# --------------------------------------------------
# Analyze mode (färg)
# --------------------------------------------------

def classify_offset(values):
    if any(v is None for v in values):
        return "LENGTH"
    uniq = len(set(values))
    if uniq == 1:
        return "STABLE"
    if uniq >= len(values) - 1:
        return "RANDOM"
    return "UNSTABLE"


def color_class(cls):
    return {
        "STABLE": Fore.GREEN,
        "UNSTABLE": Fore.YELLOW,
        "RANDOM": Fore.RED,
        "LENGTH": Fore.MAGENTA,
    }.get(cls, "")


def print_region(start: int, end: int, classification: str) -> None:
    length = end - start + 1
    color = color_class(classification)
    print(f"{start:04d}-{end:04d}  {color}{classification:<12}{Style.RESET_ALL} len={length}")
    
def analyze_runs(packets):
    max_len = max(p["size"] for p in packets)

    print(f"\n{Fore.CYAN}=== MULTI-RUN ANALYSIS ==={Style.RESET_ALL}\n")

    print(f"Packet count: {len(packets)}")
    print(f"Packet names: {[p['name'] for p in packets]}")
    print(f"Max length:   {max_len}\n")

    counts = Counter()

    print(f"{Fore.CYAN}=== OFFSET CLASSIFICATION ==={Style.RESET_ALL}\n")

    for i in range(max_len):
        vals = [
            p["bytes"][i] if i < p["size"] else None
            for p in packets
        ]

        cls = classify_offset(vals)
        counts[cls] += 1

        pretty = [
            f"{v:02X}" if v is not None else "--"
            for v in vals
        ]

        print(
            f"{i:04d}  "
            f"{color_class(cls)}{cls:<10}{Style.RESET_ALL} "
            + " ".join(pretty)
        )

    # --- region summary ---
    print(f"\n{Fore.CYAN}=== REGION SUMMARY ==={Style.RESET_ALL}\n")

    start = 0
    current = classify_offset([
        p["bytes"][0] if p["size"] > 0 else None for p in packets
    ])

    for i in range(1, max_len):
        vals = [
            p["bytes"][i] if i < p["size"] else None
            for p in packets
        ]
        cls = classify_offset(vals)

        if cls != current:
            print_region(start, i - 1, current)
            start = i
            current = cls

    print_region(start, max_len - 1, current)

    # --- counts ---
    print(f"\n{Fore.CYAN}=== COUNTS ==={Style.RESET_ALL}\n")

    for key in ("STABLE", "UNSTABLE", "RANDOM", "LENGTH"):
        print(f"{key:<15} {counts.get(key, 0)}")

    print()


# --------------------------------------------------
# CLI
# --------------------------------------------------

def main():
    if len(sys.argv) < 4:
        print("Usage:")
        print("  compare a.json b.json")
        print("  analyze a.json b.json c.json")
        return

    mode = sys.argv[1]

    if mode == "compare":
        a = load_packet(sys.argv[2])
        b = load_packet(sys.argv[3])

        print_header(a, b)
        chunk_view(a, b)
        diff_packets(a, b)

    elif mode == "analyze":
        packets = [load_packet(p) for p in sys.argv[2:]]
        analyze_runs(packets)


if __name__ == "__main__":
    main()