#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import copy
import json
import re
import struct
from pathlib import Path

from utils.ConfigLoader import ConfigLoader
from utils.FileUtils import FileHandler
from utils.Logger import Logger
from modules.dsl.Processor import load_case
from modules.dsl.NodeTreeParser import NodeTreeParser
from modules.dsl.Session import get_session
from modules.dsl.EncoderHandler import EncoderHandler
from modules.dsl.DecoderHandler import DecoderHandler


class EncoderDebug:

    # =====================================================================
    # PUBLIC ENTRY
    # =====================================================================
    @staticmethod
    def dump_encoding(def_name: str, fields: dict, reference_override: bytes | None = None):
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
                "debug": "header-only packet; skipping encoding"
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
            case_name, def_name, def_lines, cleaned, fields, reference_override=reference_override
        )

        print("\n=========== FINAL BYTE STREAM =============\n")
        print(encoded.hex(" "))
        print("\n===========================================\n")
        return encoded

    # =====================================================================
    # NODE DUMP
    # =====================================================================
    @staticmethod
    def _dump_nodes(nodes):
        for n in nodes:
            print(
                f"{n.__class__.__name__}: "
                f"name={getattr(n, 'name', None)}, "
                f"fmt={getattr(n, 'format', None)}, "
                f"interp={getattr(n, 'interpreter', None)}"
            )

    @staticmethod
    def _dump_cleaned(cleaned):
        for entry in cleaned:
            # entry kan vara:
            # (node, name, fmt) eller (node, name, fmt, server_mods, encode_mods)

            if len(entry) == 3:
                node, name, fmt = entry
                server_mods = getattr(node, "modifiers", [])
                encode_mods = getattr(node, "encode_modifiers", [])

            elif len(entry) == 5:
                node, name, fmt, server_mods, encode_mods = entry

            else:
                raise RuntimeError(f"Unexpected cleaned entry structure: {entry}")

            print(f"BaseNode: name={name}, fmt={fmt}, server={server_mods}, encode={encode_mods}, value={node.value}")

    # =====================================================================
    # FIELD SIZE HELPER
    # =====================================================================
    @staticmethod
    def _calc_field_size(node, name, fmt, fields, endian="<"):
        """
        Beräknar antal bytes för ett fält, baserat på fmt och ev. dynamiska beroenden.
        Används ENDAST av debugpipelinen för att skiva upp encoded bytes korrekt.
        """

        if fmt is None:
            return 0

        # ------------------------------------------------------
        # 1) __dyn_str__  (t.ex. €I_len's)
        # ------------------------------------------------------
        if fmt == "__dyn_str__":
            # 1) Försök först med explicit längtkälla
            length_field = (
                getattr(node, "length_from", None)
                or getattr(node, "depends_on", None)
            )

            # Strip ev. ledande '€'
            if isinstance(length_field, str) and length_field.startswith("€"):
                length_field = length_field[1:]

            # 2) Försök hitta via interpreter-strängen (äldre noder)
            if not length_field:
                m = re.search(r"€([A-Za-z0-9_]+)", getattr(node, "format", "") or "")
                if m:
                    length_field = m.group(1)

            # 3) Fallback: gissa på fält som heter något med 'len'
            if not length_field:
                candidates = [
                    fname
                    for (_, fname, _) in fields.get("_cleaned_name_fmt_list_", [])
                    if fname and (
                        fname.lower().endswith("len")
                        or fname.lower().startswith("len")
                        or fname.lower().endswith("_len")
                    )
                ]
                if candidates:
                    length_field = candidates[0]

            strlen = fields.get(length_field)
            return int(strlen) if strlen is not None else 0



        # ------------------------------------------------------
        # 2) __rest__ (R / r)
        #    → returnera längden på fields[name]
        # ------------------------------------------------------
        if fmt == "__rest__":
            val = fields.get(name)

            if val is None:
                return 0

            # Om str kan det vara hex / vanlig text
            if isinstance(val, str):
                # Försök tolka som hex (jämnt antal tecken)
                if re.fullmatch(r"[0-9A-Fa-f]+", val) and len(val) % 2 == 0:
                    try:
                        val = bytes.fromhex(val)
                    except Exception:
                        val = val.encode("utf-8")
                else:
                    val = val.encode("utf-8")

            try:
                return len(val)
            except Exception:
                return 0

        # ------------------------------------------------------
        # 3) Specialformat (__padding__, __seek__ osv)
        # ------------------------------------------------------
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

        # ------------------------------------------------------
        # 4) N-s strängar (t.ex. 16s, 32s)
        # ------------------------------------------------------
        if isinstance(fmt, str) and fmt.endswith("s"):
            try:
                return int(fmt[:-1])
            except:
                return 0

        # ------------------------------------------------------
        # 5) Normala struct-format
        # ------------------------------------------------------
        try:
            return struct.calcsize(endian + str(fmt))
        except:
            return 0

    # =====================================================================
    # SUPPORT HELPERS
    # =====================================================================
    @staticmethod
    def _load_original_reference(def_name):
        cfg = ConfigLoader.load_config()
        program = cfg["program"]
        expansion = cfg.get("expansion")
        version = cfg["version"]

        # Försök först använda samma payload-källa som den vanliga pipelinen
        # (tar hänsyn till header_mode, auth1b osv).
        try:
            return FileHandler.load_payload(program, version, def_name, expansion=expansion)
        except FileNotFoundError:
            pass

        # Fallback: läs debug-json manuellt vid behov.
        debug_file = Path(f"protocols/{program}/{expansion}/{version}/data/debug/{def_name}.json")
        if not debug_file.exists():
            return None

        dbg = json.loads(debug_file.read_text("utf-8"))

        # I första hand: hex_compact / hex_spaced (ren payload)
        hex_payload = (dbg.get("hex_compact") or dbg.get("hex_spaced") or "").replace(" ", "")
        if hex_payload:
            try:
                return bytes.fromhex(hex_payload)
            except ValueError:
                pass

        # Sista utväg: raw_header_hex + raw_data_hex (äldre/konstiga fall)
        header = (dbg.get("raw_header_hex") or "").replace(" ", "")
        data = (dbg.get("raw_data_hex") or "").replace(" ", "")
        try:
            return bytes.fromhex(header + data)
        except ValueError:
            return None

    @staticmethod
    def _align_reference(reference_full, pipeline):
        if not reference_full or not pipeline:
            return reference_full

        signature = b"".join(chunk for (_, chunk, _, _) in pipeline[:3])
        idx = reference_full.find(signature)

        if idx != -1:
            print(f"[ALIGN] Found signature {signature.hex(' ')} at offset {idx}")
            return reference_full[idx:]

        print("[ALIGN] No signature match found – using full reference.")
        return reference_full

    @staticmethod
    def _decode_reference(case_name, def_lines, reference):
        if not reference:
            return None

        # =============================================================
        # PATCH: Override node values with CLEANED values before decode
        # =============================================================
        try:
            cleaned_list = session.fields  # raw node list BEFORE decode
        except Exception:
            cleaned_list = []

        # session.fields är full av nodobjekt som clean-steget modifierat
        # Bygg name->value karta
        override_map = {}
        for node in cleaned_list:
            if hasattr(node, "name") and hasattr(node, "value"):
                if node.name and node.value is not None:
                    override_map[node.name] = node.value

        # Tillämpa patchen: injicera värdena och markera processed=True
        for node in cleaned_list:
            if node.name in override_map:
                node.value = override_map[node.name]
                node.processed = True  # hindrar DecoderHandler från att försöka läsa från reference

        # =============================================================
        # KÖR DECODE, NU MED ÖVERSKRIVNA FÄLT
        # =============================================================
        try:
            case = (case_name, def_lines, reference, None)
            result = DecoderHandler.decode(case, silent=True)
            print(f"[DECODE] Decoded original OK → type={type(result).__name__}")
            return result
        except Exception as e:
            print(f"[DECODE] Could not decode original with DecoderHandler: {e}")
            return None

    @staticmethod
    def _build_pipeline(cleaned, raw_bytes, fields, endian="<"):
        pipeline = []
        offset = 0

        for entry in cleaned:
            if len(entry) == 3:
                node, name, fmt = entry
                server_mods = getattr(node, "modifiers", []) or []
                encode_mods = getattr(node, "encode_modifiers", []) or []
            elif len(entry) == 5:
                node, name, fmt, server_mods, encode_mods = entry
            else:
                raise RuntimeError(f"Unexpected cleaned entry: {entry!r}")

            # --- PACKED GUID ---
            if fmt == "__packed_guid__":
                name = name or getattr(node, "name", "packed_guid")
                if offset < len(raw_bytes):
                    mask = raw_bytes[offset]
                    size = 1 + bin(mask).count("1")
                    chunk = raw_bytes[offset:offset + size]
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
                        size = 1 + sum(1 for b in guid_bytes[:8] if b != 0)
                    chunk = raw_bytes[offset:offset + size]
                    offset += size
                pipeline.append((name, chunk, fmt, node))
                continue

            # --- BITFIELDS ---
            if fmt == "__bits__":
                # pipeline.append((name, b"<bits>", fmt, node))
                pipeline.append((name or "<unnamed>", b"", fmt, node))
                continue

            size = EncoderDebug._calc_field_size(node, name, fmt, fields, endian)
            if size <= 0:
                continue

            chunk = raw_bytes[offset:offset + size]
            offset += size
            pipeline.append((name or "<unnamed>", chunk, fmt, node))

        return pipeline

    @staticmethod
    def _build_original_pipeline(reference, pipeline):
        if not reference:
            return []

        pos = 0
        blocks = []

        for (_, blk, _, _) in pipeline:
            size = len(blk)
            blocks.append(reference[pos:pos + size])
            pos += size

        return blocks

    @staticmethod
    def _print_pipeline(encoded, original):
        print("\n--- ENCODED PIPELINE ---")
        print(" | ".join(b.hex(" ") for (_, b, _, _) in encoded))

        if original:
            print("\n--- ORIGINAL PIPELINE ---")
            print(" | ".join(b.hex(" ") for b in original))

    @staticmethod
    def _print_field_compare(pipeline, orig_blocks, fields):
        if not orig_blocks:
            return

        print("\n\nField compare:\n")
        w1, w2, w3, w4, w5 = 22, 14, 14, 18, 18

        print(
            "Field".ljust(w1)
            + "Format".ljust(w2)
            + "Value".ljust(w3)
            + "Encoded".ljust(w4)
            + "Original".ljust(w5)
            + "Status"
        )
        print("-" * (w1 + w2 + w3 + w4 + w5 + 6))

        for i, (name, enc, fmt, node) in enumerate(pipeline):
            orig = orig_blocks[i]

            if fmt == "__bits__":
                enc_hex = "<bits>"
                orig_hex = "<bits>"
                status = "-"
            else:
                enc_hex = enc.hex(" ")
                orig_hex = orig.hex(" ")
                status = "✓" if enc == orig else "✗"

            # använd nodens value i första hand (det encodern faktiskt använder)
            val = getattr(node, "value", None)
            if val is None:
                val = fields.get(name)

            if isinstance(val, bytes):
                try:
                    val = int.from_bytes(val, "little")
                except Exception:
                    val = "-"

            print(
                f"{(name+':').ljust(w1)}"
                f"{str(fmt).ljust(w2)}"
                f"{str(val).ljust(w3)}"
                f"{enc_hex.ljust(w4)}"
                f"{orig_hex.ljust(w5)}"
                f"{status}"
            )

    @staticmethod
    def _print_compare_summary(raw, reference):
        if not reference:
            print("\n(No reference found, skipping comparison.)")
            return

        print("\n--- REFERENCE COMPARISON ---")
        print("Original size:", len(reference))
        print("Encoded  size:", len(raw))

        if raw == reference:
            print("✓ PERFECT MATCH")
            return

        print("✗ MISMATCH detected!")
        for i in range(min(len(raw), len(reference))):
            if raw[i] != reference[i]:
                print("First difference at index", i)
                print(" encoded =", f"{raw[i]:02X}")
                print(" original =", f"{reference[i]:02X}")
                break

    @staticmethod
    def _print_final_hex(raw_bytes, reference_full):
        print("\n--- ENCODED PACKET ---")
        print(" ".join(f"{b:02X}" for b in raw_bytes))

        if reference_full:
            print("\n--- ORIGINAL PACKET ---")
            print(" ".join(f"{b:02X}" for b in reference_full))

        print("\n=========== FINAL BYTE STREAM =============\n")
        print(raw_bytes.hex(" "))
        print()

    # =====================================================================
    # ENCODE + DEBUG
    # =====================================================================
    @staticmethod
    def _encode_with_debug(case_name, def_name, def_lines, cleaned, fields, endian="<", reference_override=None):

        reference_full = reference_override or EncoderDebug._load_original_reference(def_name)
        reference_aligned = None

        # Only expose the first three items (node, name, fmt)
        _clean_short = []
        for entry in cleaned:
            n, name, fmt = entry[:3]
            _clean_short.append((n, name, fmt))
        fields["_cleaned_name_fmt_list_"] = _clean_short

        raw_bytes = EncoderHandler.encode_packet(case_name, fields)
        raw_bytes = bytes(raw_bytes)

        reference_aligned = EncoderDebug._align_reference(reference_full, EncoderDebug._build_pipeline(cleaned, raw_bytes, fields, endian))

        pipeline = EncoderDebug._build_pipeline(cleaned, raw_bytes, fields, endian)

        EncoderDebug._decode_reference(case_name, def_lines, reference_aligned)

        orig_blocks = EncoderDebug._build_original_pipeline(reference_aligned, pipeline)

        EncoderDebug._print_pipeline(pipeline, orig_blocks)
        EncoderDebug._print_field_compare(pipeline, orig_blocks, fields)
        EncoderDebug._print_compare_summary(raw_bytes, reference_aligned)
        EncoderDebug._print_final_hex(raw_bytes, reference_full)

        return raw_bytes
