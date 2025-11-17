import re
from typing import Tuple, List
from modules.ModifierMapping import modifiers_operation_mapping

_COMPOUND_BITS_RE = re.compile(r"^\s*(\d+)\s*([Bb])\s*(I?)\s*$")

class ModifierUtils:
    @staticmethod
    def parse_modifiers(raw_line: str) -> Tuple[str, List[str]]:
        """
        Parse "format, modifiers..." into (fmt, modifiers_list).
        Rules:
          - If fmt == 'bits', we enter bit-mode and only allow compound bit tokens ('<n>B', '<n>BI', '<n>b', '<n>bI').
          - Otherwise, we allow normal one-letter modifiers (s, M, I, H, U, u, t, W, ...).
          - We do NOT allow bit-operators outside 'bits' mode to avoid mixing two systems.
        """
        if "," in raw_line:
            fmt_raw, mods_raw = [x.strip() for x in raw_line.split(",", 1)]
        else:
            fmt_raw, mods_raw = raw_line.strip(), ""

        # Decide mode
        is_bits_mode = fmt_raw.lower() == "bits"

        if is_bits_mode:
            # In bits mode we suppress fmt (no struct format) and inject a sentinel 'bits'
            fmt = ""  # or None, depending on your downstream
            modifiers = ModifierUtils._expand_modifiers(mods_raw, bits_mode=True)
            modifiers.insert(0, "bits")
        else:
            # Normal struct mode: keep fmt as-is
            fmt = fmt_raw
            modifiers = ModifierUtils._expand_modifiers(mods_raw, bits_mode=False)

            # Guard: forbid bit operators outside bits-mode
            bad = [m for m in modifiers if _COMPOUND_BITS_RE.fullmatch(m)]
            if bad:
                # Pick one: raise to be strict, or auto-upgrade to bits-mode.
                # Strict is safer so you notice mistakes early:
                raise ValueError(f"Bit-operators {bad} used without 'bits' mode in '{raw_line}'. "
                                 f"Write it as: 'bits, {', '.join(bad)}' instead.")
        return fmt, modifiers

    @staticmethod
    def _expand_modifiers(raw_mods: str, *, bits_mode: bool) -> List[str]:
        """
        Tokenize the modifiers part.
        - Split on commas, trim each piece.
        - Keep compound bit tokens intact (e.g., '8BI' stays one token).
        - Split glued normal tokens like 'sM' into ['s','M'] (but only in non-bits mode).
        - Ignore empty segments gracefully.
        """
        if not raw_mods:
            return []

        tokens: List[str] = []
        # First split on commas; users can write "8BI, sM" or just "8BI"
        for seg in (p.strip() for p in raw_mods.split(",") if p.strip()):
            if bits_mode:
                # In bits mode, accept only compound bit tokens; allow whitespace inside, but keep as one.
                if _COMPOUND_BITS_RE.fullmatch(seg):
                    tokens.append(seg.replace(" ", ""))  # normalize spaces
                else:
                    # If someone wrote e.g. "8B I" with a space instead of no space, normalize it:
                    no_space = seg.replace(" ", "")
                    if _COMPOUND_BITS_RE.fullmatch(no_space):
                        tokens.append(no_space)
                    else:
                        # Anything else (like 's','M','I',...) is not allowed in bits mode to prevent mixing.
                        raise ValueError(f"Invalid token '{seg}' in bits-mode. "
                                         f"Use '<n>B', '<n>BI', '<n>b', or '<n>bI'.")
            else:
                # Non-bits mode: allow one-letter ops (s,M,I,H,U,u,t,W,...) and also glued strings like 'sM'.
                # We do NOT allow plain 'B'/'b' as modifiers here; 'B' as a *format* is fine (fmt="B").
                if len(seg) == 1:
                    tokens.append(seg)
                else:
                    # If it's a bit token by mistake, let the caller error out in parse_modifiers.
                    if _COMPOUND_BITS_RE.fullmatch(seg.replace(" ", "")):
                        tokens.append(seg.replace(" ", ""))  # will be rejected by caller (not in bits mode)
                    else:
                        # Split glued normal ops like 'sM' into ['s','M']
                        tokens.extend(list(seg))
        return tokens
