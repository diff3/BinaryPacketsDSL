#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Packet diff and batch comparison tool for WoW DSL sniffed packets.

Legacy modes remain available:
- compare a.json b.json
- analyze run1.json run2.json run3.json

New batch mode:
- packet_diff.py <pattern_a> <pattern_b> [--all] [--analyze]
"""

from __future__ import annotations

import argparse
import glob
import json
import sys
from collections import Counter
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any


# --------------------------------------------------
# Loader
# --------------------------------------------------

def hex_to_bytes(hex_str: str) -> bytes:
    """Convert spaced or compact hex string to bytes."""
    cleaned = hex_str.replace(" ", "").strip()
    return bytes.fromhex(cleaned)


def byte_to_ascii(b: int) -> str:
    """Printable ASCII or dot."""
    if 32 <= b <= 126:
        return chr(b)
    return "."


def load_packet(path: str) -> dict[str, Any]:
    """Load one packet JSON file and extract normalized metadata."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    source_key = None
    hex_data = None
    for key in ("hex_compact", "raw_data_hex", "hex_spaced"):
        value = data.get(key)
        if value:
            source_key = key
            hex_data = value
            break

    if not hex_data:
        raise ValueError(f"No hex data found in {path}")

    header_hex = str(data.get("raw_header_hex") or "").strip()
    header_len = len(hex_to_bytes(header_hex)) if header_hex else 0
    payload = hex_to_bytes(hex_data)

    return {
        "path": path,
        "path_obj": Path(path),
        "name": data.get("name") or Path(path).stem,
        "bytes": payload,
        "size": len(payload),
        "opcode": data.get("raw_opcode_int"),
        "header_mode": data.get("header_mode"),
        "source_key": source_key,
        "includes_header": source_key == "raw_data_hex",
        "header_len": header_len,
    }


def normalize_packet_bytes(
    packet: dict[str, Any],
    *,
    ignore_header: bool = False,
    offset: int = 0,
    max_bytes: int | None = None,
) -> bytes:
    """Normalize packet bytes for diffing."""
    start = max(0, int(offset or 0))
    if ignore_header and packet.get("includes_header") and packet.get("header_len"):
        start += int(packet["header_len"])

    data = bytes(packet["bytes"][start:])
    if max_bytes is not None:
        data = data[: max(0, int(max_bytes))]
    return data


def expand_glob(pattern: str) -> list[str]:
    """Expand and sort a glob pattern deterministically."""
    return sorted(glob.glob(pattern))


# --------------------------------------------------
# Diff engine
# --------------------------------------------------

def diff_bytes(a: bytes, b: bytes) -> list[int]:
    """Return byte offsets that differ between the two payloads."""
    max_len = max(len(a), len(b))
    return [
        index
        for index in range(max_len)
        if (a[index] if index < len(a) else None) != (b[index] if index < len(b) else None)
    ]


def similarity_score(a: bytes, b: bytes) -> float:
    """Return simple byte-position similarity in percent."""
    max_len = max(len(a), len(b))
    if max_len == 0:
        return 100.0

    same = 0
    for i in range(min(len(a), len(b))):
        if a[i] == b[i]:
            same += 1

    return (same / max_len) * 100.0


def longest_common_block(a: bytes, b: bytes) -> tuple[int, int, int]:
    """
    Return (a_index, b_index, size) for the longest common contiguous block.
    Useful as an alignment hint.
    """
    matcher = SequenceMatcher(None, a, b, autojunk=False)
    match = matcher.find_longest_match(0, len(a), 0, len(b))
    return match.a, match.b, match.size


def classify_comparison(packet_a: dict[str, Any], packet_b: dict[str, Any]) -> str:
    """Basic high-level classification of a comparison."""
    if packet_a["name"] != packet_b["name"]:
        return "DIFFERENT_PACKET_TYPE"

    if packet_a["size"] != packet_b["size"]:
        return "LENGTH_MISMATCH"

    score = similarity_score(packet_a["bytes"], packet_b["bytes"])

    if score == 100.0:
        return "IDENTICAL"

    if score < 10.0:
        return "RANDOM_LIKE"

    if score < 60.0:
        return "UNSTABLE"

    return "PARTIAL_MATCH"


def compare_packet_pair(
    packet_a: dict[str, Any],
    packet_b: dict[str, Any],
    *,
    ignore_header: bool = False,
    offset: int = 0,
    max_bytes: int | None = None,
) -> dict[str, Any]:
    """Compare one normalized packet pair and return a summary."""
    bytes_a = normalize_packet_bytes(
        packet_a,
        ignore_header=ignore_header,
        offset=offset,
        max_bytes=max_bytes,
    )
    bytes_b = normalize_packet_bytes(
        packet_b,
        ignore_header=ignore_header,
        offset=offset,
        max_bytes=max_bytes,
    )
    diff_positions = diff_bytes(bytes_a, bytes_b)

    return {
        "packet_a": packet_a,
        "packet_b": packet_b,
        "bytes_a": bytes_a,
        "bytes_b": bytes_b,
        "size_a": len(bytes_a),
        "size_b": len(bytes_b),
        "diff_positions": diff_positions,
        "diff_count": len(diff_positions),
        "classification": classify_comparison(
            {**packet_a, "bytes": bytes_a, "size": len(bytes_a)},
            {**packet_b, "bytes": bytes_b, "size": len(bytes_b)},
        ),
        "similarity": similarity_score(bytes_a, bytes_b),
    }


def build_comparison_pairs(
    paths_a: list[str],
    paths_b: list[str],
    *,
    cross_compare: bool = False,
    limit: int | None = None,
) -> list[tuple[str, str]]:
    """Build pairwise or cross-compare path pairs."""
    pairs: list[tuple[str, str]] = []

    if cross_compare:
        for path_a in paths_a:
            for path_b in paths_b:
                pairs.append((path_a, path_b))
                if limit is not None and len(pairs) >= limit:
                    return pairs
        return pairs

    pair_count = min(len(paths_a), len(paths_b))
    if limit is not None:
        pair_count = min(pair_count, limit)
    for index in range(pair_count):
        pairs.append((paths_a[index], paths_b[index]))
    return pairs


# --------------------------------------------------
# Analysis
# --------------------------------------------------

def classify_offset(values: list[int | None]) -> str:
    """
    Classify one byte offset across multiple runs.

    Rules:
    - all same               -> STABLE
    - values missing in some -> LENGTH_MISMATCH
    - all or almost all uniq -> RANDOM_LIKE
    - otherwise              -> UNSTABLE
    """
    if not values:
        return "UNKNOWN"

    if any(v is None for v in values):
        return "LENGTH_MISMATCH"

    uniq = len(set(values))

    if uniq == 1:
        return "STABLE"

    if uniq >= max(2, len(values) - 1):
        return "RANDOM_LIKE"

    return "UNSTABLE"


def analyze_runs(packets: list[dict[str, Any]]) -> None:
    """Analyze multiple runs of the same packet to find stable/unstable regions."""
    if len(packets) < 2:
        raise ValueError("analyze mode needs at least 2 packet files")

    names = {p["name"] for p in packets}
    if len(names) != 1:
        print("WARNING: Multi-run analysis is most useful on identical packet types.")
        print(f"Found packet names: {sorted(names)}")
        print()

    max_len = max(p["size"] for p in packets)

    print("\n=== MULTI-RUN ANALYSIS ===\n")
    print(f"Packet count: {len(packets)}")
    print(f"Packet names: {sorted(names)}")
    print(f"Max length:   {max_len}")
    print()

    per_offset: list[dict[str, Any]] = []

    for offset in range(max_len):
        values = []
        for packet in packets:
            values.append(packet["bytes"][offset] if offset < packet["size"] else None)

        cls = classify_offset(values)
        counter = Counter(values)

        per_offset.append(
            {
                "offset": offset,
                "values": values,
                "classification": cls,
                "counter": counter,
            }
        )

    print("=== OFFSET CLASSIFICATION ===\n")
    for entry in per_offset:
        offset = entry["offset"]
        cls = entry["classification"]
        values = entry["values"]

        if cls == "STABLE":
            continue

        pretty_values = []
        for value in values:
            if value is None:
                pretty_values.append("--")
            else:
                pretty_values.append(f"{value:02X}")

        print(f"{offset:04d}  {cls:<15} {' '.join(pretty_values)}")

    print()

    print("=== REGION SUMMARY ===\n")
    summarize_regions(per_offset)

    print("\n=== COUNTS ===\n")
    counts = Counter(entry["classification"] for entry in per_offset)
    for key in ("STABLE", "UNSTABLE", "RANDOM_LIKE", "LENGTH_MISMATCH"):
        print(f"{key:<15} {counts.get(key, 0)}")
    print()


def summarize_regions(per_offset: list[dict[str, Any]]) -> None:
    """Group contiguous offsets with the same classification."""
    if not per_offset:
        return

    start = per_offset[0]["offset"]
    end = start
    current = per_offset[0]["classification"]

    for entry in per_offset[1:]:
        offset = entry["offset"]
        cls = entry["classification"]

        if cls == current and offset == end + 1:
            end = offset
            continue

        print_region(start, end, current)
        start = offset
        end = offset
        current = cls

    print_region(start, end, current)


def print_region(start: int, end: int, classification: str) -> None:
    """Print one contiguous classification region."""
    length = end - start + 1
    print(f"{start:04d}-{end:04d}  {classification:<15} len={length}")


def analyze_positions(pairs: list[tuple[bytes, bytes]]) -> dict[str, list[int]]:
    """
    Return stable and variable offsets across all packet comparisons.

    A stable position is one where every comparison pair has equal bytes at
    that offset. Any mismatch or missing byte makes the offset variable.
    """
    if not pairs:
        return {"stable_positions": [], "variable_positions": []}

    max_len = max(max(len(a), len(b)) for a, b in pairs)
    stable_positions: list[int] = []
    variable_positions: list[int] = []

    for offset in range(max_len):
        stable = True
        for bytes_a, bytes_b in pairs:
            value_a = bytes_a[offset] if offset < len(bytes_a) else None
            value_b = bytes_b[offset] if offset < len(bytes_b) else None
            if value_a != value_b:
                stable = False
                break
        if stable:
            stable_positions.append(offset)
        else:
            variable_positions.append(offset)

    return {
        "stable_positions": stable_positions,
        "variable_positions": variable_positions,
    }


# --------------------------------------------------
# Output
# --------------------------------------------------

def print_header(packet_a: dict[str, Any], packet_b: dict[str, Any]) -> None:
    """Print high-level packet comparison summary."""
    print("\n=== PACKET SUMMARY ===\n")
    print(f"A: {packet_a['name']} ({packet_a['size']} bytes) [{packet_a['path']}]")
    print(f"B: {packet_b['name']} ({packet_b['size']} bytes) [{packet_b['path']}]")
    print()

    if packet_a["name"] != packet_b["name"]:
        print("WARNING: Comparing different packet types.")
        print()

    score = similarity_score(packet_a["bytes"], packet_b["bytes"])
    classification = classify_comparison(packet_a, packet_b)

    print(f"Similarity:     {score:.2f}%")
    print(f"Classification: {classification}")

    a_idx, b_idx, size = longest_common_block(packet_a["bytes"], packet_b["bytes"])
    if size > 0:
        print(
            f"Longest common block: size={size} bytes "
            f"(A@{a_idx}, B@{b_idx})"
        )
    print()


def chunk_view(packet_a: dict[str, Any], packet_b: dict[str, Any], width: int = 16) -> None:
    """Render a Wireshark-like side-by-side hex view."""
    data_a = packet_a["bytes"]
    data_b = packet_b["bytes"]
    max_len = max(len(data_a), len(data_b))

    print("\n=== SIDE-BY-SIDE HEX VIEW ===\n")

    for offset in range(0, max_len, width):
        chunk_a = data_a[offset:offset + width]
        chunk_b = data_b[offset:offset + width]

        hex_a = " ".join(f"{x:02X}" for x in chunk_a)
        hex_b = " ".join(f"{x:02X}" for x in chunk_b)

        asc_a = "".join(byte_to_ascii(x) for x in chunk_a)
        asc_b = "".join(byte_to_ascii(x) for x in chunk_b)

        marker = " <-- diff" if chunk_a != chunk_b else ""

        print(
            f"{offset:04X}  "
            f"A: {hex_a:<48} {asc_a:<16} | "
            f"B: {hex_b:<48} {asc_b:<16}{marker}"
        )

    print()


def diff_packets(packet_a: dict[str, Any], packet_b: dict[str, Any]) -> None:
    """Print byte-level differences."""
    data_a = packet_a["bytes"]
    data_b = packet_b["bytes"]
    max_len = max(len(data_a), len(data_b))

    print("\n=== PACKET DIFF ===")
    print(f"A: {packet_a['name']} ({len(data_a)} bytes)")
    print(f"B: {packet_b['name']} ({len(data_b)} bytes)")
    print()

    diff_count = 0

    for i in range(max_len):
        ba = data_a[i] if i < len(data_a) else None
        bb = data_b[i] if i < len(data_b) else None

        if ba != bb:
            diff_count += 1

            hex_a = f"{ba:02X}" if ba is not None else "--"
            hex_b = f"{bb:02X}" if bb is not None else "--"

            asc_a = byte_to_ascii(ba) if ba is not None else "-"
            asc_b = byte_to_ascii(bb) if bb is not None else "-"

            print(f"{i:04d}  A:{hex_a} ({asc_a})   B:{hex_b} ({asc_b})")

    print(f"\nTotal differences: {diff_count}\n")


def _format_position_list(values: list[int]) -> str:
    if not values:
        return "(none)"
    return ",".join(str(value) for value in values)


def print_batch_comparison(index: int, summary: dict[str, Any]) -> None:
    """Render one batch comparison summary."""
    packet_a = summary["packet_a"]
    packet_b = summary["packet_b"]
    print(f"\n=== COMPARISON {index} ===")
    print(f"A: {packet_a['path_obj'].name}")
    print(f"B: {packet_b['path_obj'].name}")
    print(f"Opcode: {packet_a['name']} vs {packet_b['name']}")
    print(f"Size: {summary['size_a']} vs {summary['size_b']}")
    print(f"Diff bytes: {summary['diff_count']}")
    print(f"Similarity: {summary['similarity']:.2f}%")
    print(f"Classification: {summary['classification']}")
    if summary["diff_positions"]:
        preview = summary["diff_positions"][:10]
        suffix = " ..." if len(summary["diff_positions"]) > 10 else ""
        print(f"Diff positions: {','.join(str(pos) for pos in preview)}{suffix}")


def print_global_analysis(comparisons: list[dict[str, Any]]) -> None:
    """Render aggregate analysis for a batch of comparisons."""
    pairs = [(item["bytes_a"], item["bytes_b"]) for item in comparisons]
    position_data = analyze_positions(pairs)
    total = len(comparisons)
    avg_diff = sum(item["diff_count"] for item in comparisons) / total if total else 0.0

    print("\n=== GLOBAL ANALYSIS ===\n")
    print(f"Total comparisons: {total}")
    print(f"Avg diff bytes: {avg_diff:.2f}")
    print("Stable bytes:")
    print(_format_position_list(position_data["stable_positions"]))
    print()
    print("Variable bytes:")
    print(_format_position_list(position_data["variable_positions"]))


# --------------------------------------------------
# CLI
# --------------------------------------------------

def usage() -> None:
    print("Usage:")
    print("  python packet_diff.py compare a.json b.json")
    print("  python packet_diff.py analyze run1.json run2.json [run3.json ...]")
    print("  python packet_diff.py <pattern_a> <pattern_b> [--all] [--analyze]")
    print()


def build_batch_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("pattern_a")
    parser.add_argument("pattern_b")
    parser.add_argument("--all", action="store_true", dest="cross_compare")
    parser.add_argument("--analyze", action="store_true")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--max-bytes", type=int, default=None)
    parser.add_argument("--ignore-header", action="store_true")
    return parser


def run_batch_mode(argv: list[str]) -> int:
    args = build_batch_parser().parse_args(argv)

    paths_a = expand_glob(args.pattern_a)
    paths_b = expand_glob(args.pattern_b)

    if not paths_a:
        print(f"ERROR: No files matched A pattern: {args.pattern_a}")
        return 1
    if not paths_b:
        print(f"ERROR: No files matched B pattern: {args.pattern_b}")
        return 1

    if not args.cross_compare and len(paths_a) != len(paths_b):
        print(
            "WARNING: Pairwise comparison count mismatch: "
            f"{len(paths_a)} vs {len(paths_b)}"
        )

    pair_paths = build_comparison_pairs(
        paths_a,
        paths_b,
        cross_compare=args.cross_compare,
        limit=args.limit,
    )
    if not pair_paths:
        print("ERROR: No comparison pairs produced.")
        return 1

    comparisons: list[dict[str, Any]] = []
    for index, (path_a, path_b) in enumerate(pair_paths, start=1):
        packet_a = load_packet(path_a)
        packet_b = load_packet(path_b)
        summary = compare_packet_pair(
            packet_a,
            packet_b,
            ignore_header=args.ignore_header,
            offset=args.offset,
            max_bytes=args.max_bytes,
        )
        comparisons.append(summary)
        print_batch_comparison(index, summary)

    if args.analyze:
        print_global_analysis(comparisons)

    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        usage()
        return 1

    mode = argv[0].strip().lower()

    if mode == "compare":
        if len(argv) != 3:
            usage()
            return 1

        packet_a = load_packet(argv[1])
        packet_b = load_packet(argv[2])

        print_header(packet_a, packet_b)
        chunk_view(packet_a, packet_b)
        diff_packets(packet_a, packet_b)
        return 0

    if mode == "analyze":
        if len(argv) < 3:
            usage()
            return 1
        packets = [load_packet(path) for path in argv[1:]]
        analyze_runs(packets)
        return 0

    return run_batch_mode(argv)


if __name__ == "__main__":
    raise SystemExit(main())
