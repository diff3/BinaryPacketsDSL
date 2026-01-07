#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Modifier parsing utilities for DSL fields."""

from __future__ import annotations

import re

_COMPOUND_BITS_RE = re.compile(r"^\s*(\d+)\s*([Bb])\s*(I?)\s*$")


class ModifierUtils:
    """Parse decode and encode modifiers for DSL fields."""

    @staticmethod
    def parse_modifiers(raw_line: str) -> tuple[str, list[str], list[str]]:
        """Parse "format, mods | enc_mods" into format and modifier lists.

        Args:
            raw_line (str): Full modifier string.

        Returns:
            tuple[str, list[str], list[str]]: (format, decode_mods, encode_mods).
        """
        if "," in raw_line:
            fmt_raw, mods_raw = [x.strip() for x in raw_line.split(",", 1)]
        else:
            fmt_raw, mods_raw = raw_line.strip(), ""

        if "|" in fmt_raw and not mods_raw:
            left, right = [x.strip() for x in fmt_raw.split("|", 1)]
            fmt_raw, mods_raw = left, ""
            mods_enc_inline = right
        else:
            mods_enc_inline = ""

        if "|" in mods_raw:
            mods_dec_raw, mods_enc_raw = [x.strip() for x in mods_raw.split("|", 1)]
        else:
            mods_dec_raw, mods_enc_raw = mods_raw, ""

        if mods_enc_inline:
            mods_enc_raw = mods_enc_inline

        is_bits_mode = fmt_raw.lower() == "bits"

        if is_bits_mode:
            fmt = ""
            modifiers = ModifierUtils._expand_modifiers(mods_dec_raw, bits_mode=True)
            modifiers.insert(0, "bits")
            encode_mods = ModifierUtils._expand_modifiers(mods_enc_raw, bits_mode=False)
        else:
            fmt = fmt_raw
            modifiers = ModifierUtils._expand_modifiers(mods_dec_raw, bits_mode=False)
            encode_mods = ModifierUtils._expand_modifiers(mods_enc_raw, bits_mode=False)

            bad = [m for m in modifiers if _COMPOUND_BITS_RE.fullmatch(m)]
            if bad:
                bad_joined = ", ".join(bad)
                raise ValueError(
                    f"Bit-operators {bad} used without 'bits' mode in '{raw_line}'. "
                    f"Write it as: 'bits, {bad_joined}' instead."
                )
        return fmt, modifiers, encode_mods

    @staticmethod
    def _expand_modifiers(raw_mods: str, *, bits_mode: bool) -> list[str]:
        """Tokenize the modifiers part into normalized tokens.

        Args:
            raw_mods (str): Raw modifiers string.
            bits_mode (bool): Whether the parser is in bits-only mode.

        Returns:
            list[str]: Parsed modifier tokens.
        """
        if not raw_mods:
            return []

        tokens: list[str] = []
        for seg in (p.strip() for p in raw_mods.split(",") if p.strip()):
            if bits_mode:
                if _COMPOUND_BITS_RE.fullmatch(seg):
                    tokens.append(seg.replace(" ", ""))
                else:
                    no_space = seg.replace(" ", "")
                    if _COMPOUND_BITS_RE.fullmatch(no_space):
                        tokens.append(no_space)
                    else:
                        raise ValueError(
                            f"Invalid token '{seg}' in bits-mode. "
                            "Use '<n>B', '<n>BI', '<n>b', or '<n>bI'."
                        )
            else:
                if ":" in seg or "=" in seg:
                    tokens.append(seg.replace(" ", ""))
                elif len(seg) == 1:
                    tokens.append(seg)
                else:
                    cleaned = seg.replace(" ", "")
                    if _COMPOUND_BITS_RE.fullmatch(cleaned):
                        tokens.append(cleaned)
                    else:
                        tokens.extend(list(seg))
        return tokens
