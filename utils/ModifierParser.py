import re
from modules.ModifierMapping import modifiers_operation_mapping

class ModifierUtils:
    @staticmethod
    def parse_modifiers(raw_line: str) -> tuple[str, list]:
        """
        Parses a raw line (after ':') into (format, modifiers).
        """
        if "," in raw_line:
            parts = [x.strip() for x in raw_line.split(",", 1)]
            fmt = parts[0]
            raw_mods = parts[1]
            modifiers = ModifierUtils._expand_modifiers(raw_mods)
        else:
            fmt = raw_line.strip()
            modifiers = []
        
        return fmt, modifiers

    @staticmethod
    def _expand_modifiers(raw_mods: str) -> list:
        """
        Parses the modifiers part, e.g., '7BI, MU' → ['7B', 'I', 'M', 'U'].
        """
        modifiers = []
        raw_parts = raw_mods.split(',')

        for raw in raw_parts:
            raw = raw.strip()
            i = 0
            while i < len(raw):
                match = re.match(r'(\d*)(B)', raw[i:])
                if match:
                    num, letter = match.groups()
                    modifiers.append(f"{num}{letter}" if num else letter)
                    i += match.end()
                else:
                    if raw[i].isalpha() or raw[i] in "<>":
                        modifiers.append(raw[i])
                    i += 1
        return modifiers