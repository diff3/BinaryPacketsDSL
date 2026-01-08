#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Debug helpers for the DSL encoder pipeline.

This module provides a verbose view of the encoder stages and a comparison
against a reference payload when available.
"""

from __future__ import annotations

import copy
import json
import re
import struct
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from modules.dsl.DecoderHandler import DecoderHandler
from modules.dsl.EncoderHandler import EncoderHandler
from modules.dsl.NodeTreeParser import NodeTreeParser
from modules.dsl.Processor import load_case
from modules.dsl.Session import get_session
from utils.ConfigLoader import ConfigLoader
from utils.FileUtils import FileHandler
from utils.Logger import Logger

SIGNATURE_CHUNK_COUNT = 3
FIELD_WIDTH_NAME = 22
FIELD_WIDTH_FORMAT = 14
FIELD_WIDTH_VALUE = 14
FIELD_WIDTH_ENCODED = 18
FIELD_WIDTH_ORIGINAL = 18


class EncoderDebug:
    """Verbose encoder pipeline with reference comparisons."""

    @staticmethod
    def dump_encoding(
        def_name: str,
        fields: dict[str, Any],
        reference_override: bytes | None = None,
    ) -> bytes | dict[str, Any]:
        """Encode a packet and print the full debug pipeline.

        Args:
            def_name (str): Definition name to encode.
            fields (dict[str, Any]): Field values used for encoding.
            reference_override (bytes | None): Optional reference payload.

        Returns:
            bytes | dict[str, Any]: Encoded bytes or a header-only info payload.
        """
        cfg = ConfigLoader.load_config()
        program = cfg["program"]
        expansion = cfg.get("expansion")
        version = cfg["version"]

        case_name, def_lines, _, expected, debug = load_case(
            program,
            version,
            def_name,
            expansion=expansion,
        )

        if debug.get("payload_len") == 0 and debug.get("size_matches_payload") is True:
            Logger.success("Header only, done")
            return {
                "encoded": b"",
                "debug": "header-only packet; skipping encoding",
            }

        print("\n================ DSL ================\n")
        for line in def_lines:
            print(line.rstrip())

        print("\n=========== PARSING =============\n")

        session = get_session()
        session.reset()

        NodeTreeParser.parse((case_name, def_lines, b"", expected))
        nodes = copy.deepcopy(session.fields)

        print("RAW NODE TREE:\n")
        EncoderDebug._dump_nodes(nodes)

        flat = EncoderHandler._flatten_blocks(nodes)
        print("\n=========== FLATTENED =============\n")
        EncoderDebug._dump_nodes(flat)

        expanded = EncoderHandler._expand_loops(flat, fields)
        print("\n=========== LOOPS EXPANDED =============\n")
        EncoderDebug._dump_nodes(expanded)

        cleaned = EncoderHandler._cleanup(expanded, fields)
        print("\n=========== CLEANED =============\n")
        EncoderDebug._dump_cleaned(cleaned)

        print("\n=========== ENCODE STEPS =============\n")
        encoded = EncoderDebug._encode_with_debug(
            case_name,
            def_name,
            def_lines,
            cleaned,
            fields,
            reference_override=reference_override,
        )

        print("\n=========== FINAL BYTE STREAM =============\n")
        print(encoded.hex(" "))
        print("\n===========================================\n")
        return encoded

    @staticmethod
    def _dump_nodes(nodes: Iterable[Any]) -> None:
        """Print a compact summary of each node."""
        for node in nodes:
            print(
                f"{node.__class__.__name__}: "
                f"name={getattr(node, 'name', None)}, "
                f"fmt={getattr(node, 'format', None)}, "
                f"interp={getattr(node, 'interpreter', None)}"
            )
        return None

    @staticmethod
    def _dump_cleaned(cleaned: Iterable[tuple[Any, ...]]) -> None:
        """Print cleaned nodes with modifiers and values."""
        for entry in cleaned:
            if len(entry) == 3:
                node, name, fmt = entry
                server_mods = getattr(node, "modifiers", [])
                encode_mods = getattr(node, "encode_modifiers", [])
            elif len(entry) == 5:
                node, name, fmt, server_mods, encode_mods = entry
            else:
                raise RuntimeError(f"Unexpected cleaned entry structure: {entry}")

            print(
                "BaseNode: "
                f"name={name}, fmt={fmt}, server={server_mods}, "
                f"encode={encode_mods}, value={node.value}"
            )
        return None

    @staticmethod
    def _calc_field_size(
        node: Any,
        name: str | None,
        fmt: Any,
        fields: dict[str, Any],
        endian: str = "<",
    ) -> int:
        """Calculate field size in bytes for debug slicing.

        Args:
            node (Any): DSL node.
            name (str | None): Field name.
            fmt (Any): Node format or sentinel.
            fields (dict[str, Any]): Encoder field values.
            endian (str): Endianness for struct formats.

        Returns:
            int: Field size in bytes.
        """
        if fmt is None:
            return 0

        if fmt == "__dyn_str__":
            length_field = (
                getattr(node, "length_from", None)
                or getattr(node, "depends_on", None)
            )

            if isinstance(length_field, str) and length_field.startswith("€"):
                length_field = length_field[1:]

            if not length_field:
                match = re.search(r"€([A-Za-z0-9_]+)", getattr(node, "format", "") or "")
                if match:
                    length_field = match.group(1)

            if not length_field:
                candidates = [
                    field_name
                    for (_, field_name, _) in fields.get("_cleaned_name_fmt_list_", [])
                    if field_name
                    and (
                        field_name.lower().endswith("len")
                        or field_name.lower().startswith("len")
                        or field_name.lower().endswith("_len")
                    )
                ]
                if candidates:
                    length_field = candidates[0]

            strlen = fields.get(length_field)
            return int(strlen) if strlen is not None else 0

        if fmt == "__rest__":
            value = fields.get(name)

            if value is None:
                return 0

            if isinstance(value, str):
                if re.fullmatch(r"[0-9A-Fa-f]+", value) and len(value) % 2 == 0:
                    try:
                        value = bytes.fromhex(value)
                    except ValueError:
                        value = value.encode("utf-8")
                else:
                    value = value.encode("utf-8")

            try:
                return len(value)
            except Exception:
                return 0

        if isinstance(fmt, str) and fmt.startswith("__"):
            if fmt == "__buffer_io__":
                size_expr = getattr(node, "io_size_expr", None)
                size = EncoderHandler._resolve_length_expr(size_expr, fields, fields)
                if size is None:
                    start_idx = getattr(node, "index_start", 0) or 0
                    end_idx = getattr(node, "index_end", start_idx) or start_idx
                    size = max(1, end_idx - start_idx + 1)
                try:
                    return int(size)
                except Exception:
                    return 0
            return 0

        if isinstance(fmt, str) and fmt.endswith("s"):
            try:
                return int(fmt[:-1])
            except Exception:
                return 0

        try:
            return struct.calcsize(endian + str(fmt))
        except Exception:
            return 0

    @staticmethod
    def _load_original_reference(def_name: str) -> bytes | None:
        """Load a reference payload for comparisons, if available."""
        cfg = ConfigLoader.load_config()
        program = cfg["program"]
        expansion = cfg.get("expansion")
        version = cfg["version"]

        try:
            return FileHandler.load_payload(program, version, def_name, expansion=expansion)
        except FileNotFoundError:
            pass

        debug_file = Path(
            f"protocols/{program}/{expansion}/{version}/data/debug/{def_name}.json"
        )
        if not debug_file.exists():
            return None

        dbg = json.loads(debug_file.read_text("utf-8"))

        hex_payload = (dbg.get("hex_compact") or dbg.get("hex_spaced") or "").replace(" ", "")
        if hex_payload:
            try:
                return bytes.fromhex(hex_payload)
            except ValueError:
                pass

        header = (dbg.get("raw_header_hex") or "").replace(" ", "")
        data = (dbg.get("raw_data_hex") or "").replace(" ", "")
        try:
            return bytes.fromhex(header + data)
        except ValueError:
            return None

    @staticmethod
    def _align_reference(
        reference_full: bytes | None,
        pipeline: list[tuple[str, bytes, Any, Any]],
    ) -> bytes | None:
        """Align the reference payload by matching the first pipeline chunks."""
        if not reference_full or not pipeline:
            return reference_full

        signature = b"".join(
            chunk for (_, chunk, _, _) in pipeline[:SIGNATURE_CHUNK_COUNT]
        )
        idx = reference_full.find(signature)

        if idx != -1:
            print(f"[ALIGN] Found signature {signature.hex(' ')} at offset {idx}")
            return reference_full[idx:]

        print("[ALIGN] No signature match found - using full reference.")
        return reference_full

    @staticmethod
    def _decode_reference(
        case_name: str,
        def_lines: list[str],
        reference: bytes | None,
    ) -> Any | None:
        """Decode the reference payload with the decoder for comparison."""
        if not reference:
            return None

        try:
            session = get_session()
            cleaned_list = getattr(session, "fields", []) or []
        except Exception:
            cleaned_list = []

        override_map: dict[str, Any] = {}
        for node in cleaned_list:
            node_name = getattr(node, "name", None)
            node_value = getattr(node, "value", None)
            if node_name and node_value is not None:
                override_map[node_name] = node_value

        for node in cleaned_list:
            node_name = getattr(node, "name", None)
            if node_name in override_map:
                node.value = override_map[node_name]
                node.processed = True

        try:
            case = (case_name, def_lines, reference, None)
            result = DecoderHandler.decode(case, silent=True)
            print(f"[DECODE] Decoded original OK -> type={type(result).__name__}")
            return result
        except Exception as exc:
            print(f"[DECODE] Could not decode original with DecoderHandler: {exc}")
            return None

    @staticmethod
    def _build_pipeline(
        cleaned: Iterable[tuple[Any, ...]],
        raw_bytes: bytes,
        fields: dict[str, Any],
        endian: str = "<",
    ) -> list[tuple[str, bytes, Any, Any]]:
        """Build a byte-level pipeline from cleaned entries."""
        pipeline: list[tuple[str, bytes, Any, Any]] = []
        offset = 0

        for entry in cleaned:
            if len(entry) == 3:
                node, name, fmt = entry
            elif len(entry) == 5:
                node, name, fmt, _, _ = entry
            else:
                raise RuntimeError(f"Unexpected cleaned entry: {entry!r}")

            # --- PACKED GUID ---
            if fmt == "__packed_guid__":
                name = name or getattr(node, "name", "packed_guid")
                if offset < len(raw_bytes):
                    mask = raw_bytes[offset]
                    size = 1 + bin(mask).count("1")
                    chunk = raw_bytes[offset : offset + size]
                    offset += size
                else:
                    mask_val = fields.get(f"{name}_mask")
                    if mask_val is None and getattr(node, "raw_data", None):
                        try:
                            mask_val = node.raw_data[0]
                        except Exception:
                            mask_val = None
                    if mask_val is not None:
                        size = 1 + bin(int(mask_val) & 0xFF).count("1")
                    else:
                        guid = fields.get(name, getattr(node, "value", 0)) or 0
                        try:
                            guid_bytes = int(guid).to_bytes(8, "little", signed=False)
                        except Exception:
                            guid_bytes = b""
                        size = 1 + sum(1 for byte in guid_bytes[:8] if byte != 0)
                    chunk = raw_bytes[offset : offset + size]
                    offset += size
                pipeline.append((name, chunk, fmt, node))
                continue

            # --- BITFIELDS ---
            if fmt == "__bits__":
                pipeline.append((name or "<unnamed>", b"", fmt, node))
                continue

            size = EncoderDebug._calc_field_size(node, name, fmt, fields, endian)
            if size <= 0:
                continue

            chunk = raw_bytes[offset : offset + size]
            offset += size
            pipeline.append((name or "<unnamed>", chunk, fmt, node))

        return pipeline

    @staticmethod
    def _build_original_pipeline(
        reference: bytes | None,
        pipeline: list[tuple[str, bytes, Any, Any]],
    ) -> list[bytes]:
        """Slice the reference payload into pipeline-sized blocks."""
        if not reference:
            return []

        pos = 0
        blocks: list[bytes] = []

        for _, blk, _, _ in pipeline:
            size = len(blk)
            blocks.append(reference[pos : pos + size])
            pos += size

        return blocks

    @staticmethod
    def _print_pipeline(
        encoded: list[tuple[str, bytes, Any, Any]],
        original: list[bytes],
    ) -> None:
        """Print the encoded pipeline and the aligned reference."""
        print("\n--- ENCODED PIPELINE ---")
        print(" | ".join(chunk.hex(" ") for (_, chunk, _, _) in encoded))

        if original:
            print("\n--- ORIGINAL PIPELINE ---")
            print(" | ".join(chunk.hex(" ") for chunk in original))
        return None

    @staticmethod
    def _print_field_compare(
        pipeline: list[tuple[str, bytes, Any, Any]],
        orig_blocks: list[bytes],
        fields: dict[str, Any],
    ) -> None:
        """Print a per-field comparison table between encoded and reference."""
        if not orig_blocks:
            return None

        print("\n\nField compare:\n")

        print(
            "Field".ljust(FIELD_WIDTH_NAME)
            + "Format".ljust(FIELD_WIDTH_FORMAT)
            + "Value".ljust(FIELD_WIDTH_VALUE)
            + "Encoded".ljust(FIELD_WIDTH_ENCODED)
            + "Original".ljust(FIELD_WIDTH_ORIGINAL)
            + "Status"
        )
        print(
            "-" * (
                FIELD_WIDTH_NAME
                + FIELD_WIDTH_FORMAT
                + FIELD_WIDTH_VALUE
                + FIELD_WIDTH_ENCODED
                + FIELD_WIDTH_ORIGINAL
                + 6
            )
        )

        for idx, (name, enc, fmt, node) in enumerate(pipeline):
            orig = orig_blocks[idx]

            if fmt == "__bits__":
                enc_hex = "<bits>"
                orig_hex = "<bits>"
                status = "-"
            else:
                enc_hex = enc.hex(" ")
                orig_hex = orig.hex(" ")
                status = "OK" if enc == orig else "FAIL"

            value = getattr(node, "value", None)
            if value is None:
                value = fields.get(name)

            if isinstance(value, bytes):
                try:
                    value = int.from_bytes(value, "little")
                except Exception:
                    value = "-"

            print(
                f"{(name + ':').ljust(FIELD_WIDTH_NAME)}"
                f"{str(fmt).ljust(FIELD_WIDTH_FORMAT)}"
                f"{str(value).ljust(FIELD_WIDTH_VALUE)}"
                f"{enc_hex.ljust(FIELD_WIDTH_ENCODED)}"
                f"{orig_hex.ljust(FIELD_WIDTH_ORIGINAL)}"
                f"{status}"
            )

        return None

    @staticmethod
    def _print_compare_summary(raw: bytes, reference: bytes | None) -> None:
        """Print a high-level comparison summary."""
        if not reference:
            print("\n(No reference found, skipping comparison.)")
            return None

        print("\n--- REFERENCE COMPARISON ---")
        print("Original size:", len(reference))
        print("Encoded  size:", len(raw))

        if raw == reference:
            print("OK PERFECT MATCH")
            return None

        print("MISMATCH detected!")
        for idx in range(min(len(raw), len(reference))):
            if raw[idx] != reference[idx]:
                print("First difference at index", idx)
                print(" encoded =", f"{raw[idx]:02X}")
                print(" original =", f"{reference[idx]:02X}")
                break

        return None

    @staticmethod
    def _print_final_hex(raw_bytes: bytes, reference_full: bytes | None) -> None:
        """Print the encoded bytes and the full reference payload."""
        print("\n--- ENCODED PACKET ---")
        print(" ".join(f"{byte:02X}" for byte in raw_bytes))

        if reference_full:
            print("\n--- ORIGINAL PACKET ---")
            print(" ".join(f"{byte:02X}" for byte in reference_full))

        print("\n=========== FINAL BYTE STREAM =============\n")
        print(raw_bytes.hex(" "))
        print()
        return None

    @staticmethod
    def _encode_with_debug(
        case_name: str,
        def_name: str,
        def_lines: list[str],
        cleaned: Iterable[tuple[Any, ...]],
        fields: dict[str, Any],
        endian: str = "<",
        reference_override: bytes | None = None,
    ) -> bytes:
        """Encode a packet with verbose debug output."""
        reference_full = reference_override or EncoderDebug._load_original_reference(def_name)

        cleaned_list = list(cleaned)
        clean_short: list[tuple[Any, str | None, Any]] = []
        for entry in cleaned_list:
            node, name, fmt = entry[:3]
            clean_short.append((node, name, fmt))
        fields["_cleaned_name_fmt_list_"] = clean_short

        raw_bytes = EncoderHandler.encode_packet(case_name, fields)
        raw_bytes = bytes(raw_bytes)

        pipeline = EncoderDebug._build_pipeline(cleaned_list, raw_bytes, fields, endian)
        reference_aligned = EncoderDebug._align_reference(reference_full, pipeline)

        EncoderDebug._decode_reference(case_name, def_lines, reference_aligned)

        orig_blocks = EncoderDebug._build_original_pipeline(reference_aligned, pipeline)

        EncoderDebug._print_pipeline(pipeline, orig_blocks)
        EncoderDebug._print_field_compare(pipeline, orig_blocks, fields)
        EncoderDebug._print_compare_summary(raw_bytes, reference_aligned)
        EncoderDebug._print_final_hex(raw_bytes, reference_full)

        return raw_bytes
