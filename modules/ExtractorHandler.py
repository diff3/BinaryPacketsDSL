# modules/ExtractorHandler.py

import re
from utils.Logger import Logger
from modules.Session import session


class ExtractorHandler:
    """
    Extracts values from the global session store or inline expressions.
    Supports DSL syntax like:
        €field
        €loop[3].value
        €len'
        €field + 5
    """

    EXPR_RE = re.compile(r"€([A-Za-z0-9_.\[\]]+)(.*)")

    @staticmethod
    def get_value(name: str):
        """
        Resolve a DSL expression or direct session value.
        """
        # Not an expression → plain lookup
        if not name.startswith("€"):
            return session.get(name)

        return ExtractorHandler.eval_expr(name)

    @staticmethod
    def eval_expr(expr: str):
        """
        Parse expressions like:
            €x
            €field + 2
            €data[3]
            €loop[1].name
        """
        expr = expr.strip()

        m = ExtractorHandler.EXPR_RE.fullmatch(expr)
        if not m:
            Logger.error(f"Extractor: Invalid expression '{expr}'")
            return None

        base = m.group(1)
        tail = m.group(2).strip()

        value = ExtractorHandler.resolve_base(base)

        # No tail → direct value
        if not tail:
            return value

        # Very small arithmetic support: +n or -n
        if tail.startswith("+"):
            return value + int(tail[1:])
        if tail.startswith("-"):
            return value - int(tail[1:])

        Logger.warning(f"Extractor: Unsupported expression tail '{tail}'")
        return value

    @staticmethod
    def resolve_base(base: str):
        """
        Resolve things like:
            field
            header.size
            loop[3]
            loop[3].name
        """

        # Handle list-index syntax: field[3]
        if "[" in base and base.endswith("]"):
            name, idx = base.split("[", 1)
            idx = int(idx[:-1])  # remove ']'
            container = session.get(name)
            if isinstance(container, list):
                return container[idx]
            return None

        # Handle nested: a.b.c
        parts = base.split(".")
        value = session.get(parts[0])
        for p in parts[1:]:
            if isinstance(value, dict):
                value = value.get(p)
            elif hasattr(value, p):
                value = getattr(value, p)
            else:
                return None

        return value