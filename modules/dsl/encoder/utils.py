#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ast
import re

from utils.Logger import Logger


def preprocess_condition(expr: str) -> str:
    """
    Minimal normalisering av DSL-villkor:
    - tar bort '€'
    - gör foo[i].bar → foo[i]["bar"]
    """
    if not isinstance(expr, str):
        return expr

    e = expr.replace("€", "")
    e = re.sub(r"(\\w+\\[[^\\]]+\\])\\.(\\w+)", r'\\1[\"\\2\"]', e)
    return e


def split_print_args(expr: str) -> list[str]:
    if not isinstance(expr, str):
        return []
    s = expr.strip()
    if not s:
        return []
    parts = []
    buf = []
    depth = 0
    in_str = False
    quote = ""
    escape = False
    for ch in s:
        if in_str:
            buf.append(ch)
            if escape:
                escape = False
                continue
            if ch == "\\":
                escape = True
                continue
            if ch == quote:
                in_str = False
            continue
        if ch in ("'", '"'):
            in_str = True
            quote = ch
            buf.append(ch)
            continue
        if ch in "([{":
            depth += 1
            buf.append(ch)
            continue
        if ch in ")]}":
            depth = max(0, depth - 1)
            buf.append(ch)
            continue
        if ch == "," and depth == 0:
            part = "".join(buf).strip()
            if part:
                parts.append(part)
            buf = []
            continue
        buf.append(ch)
    if buf:
        part = "".join(buf).strip()
        if part:
            parts.append(part)
    return parts


def eval_print_expr(expr: str, context: dict):
    if not isinstance(expr, str) or not expr.strip():
        return ""
    expr_eval = preprocess_condition(expr.strip())
    ctx = dict(context or {})

    def eval_ast(node):
        if isinstance(node, ast.Expression):
            return eval_ast(node.body)
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Num):
            return node.n
        if hasattr(ast, "Str") and isinstance(node, ast.Str):
            return node.s
        if isinstance(node, ast.Name):
            val = ctx.get(node.id, 0)
            return 0 if val is None else val
        if isinstance(node, ast.BinOp):
            left = eval_ast(node.left)
            right = eval_ast(node.right)
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Mult):
                return left * right
            if isinstance(node.op, ast.Div):
                return left / right
            if isinstance(node.op, ast.Mod):
                return left % right
            raise ValueError(f"Unsupported operator: {type(node.op).__name__}")
        if isinstance(node, ast.UnaryOp):
            val = eval_ast(node.operand)
            if isinstance(node.op, ast.UAdd):
                return +val
            if isinstance(node.op, ast.USub):
                return -val
            raise ValueError(f"Unsupported unary operator: {type(node.op).__name__}")
        if isinstance(node, ast.Subscript):
            target = eval_ast(node.value)
            slc = eval_ast(node.slice)
            return target[slc]
        if isinstance(node, ast.Slice):
            lower = eval_ast(node.lower) if node.lower is not None else None
            upper = eval_ast(node.upper) if node.upper is not None else None
            step = eval_ast(node.step) if node.step is not None else None
            return slice(lower, upper, step)
        if hasattr(ast, "Index") and isinstance(node, ast.Index):
            return eval_ast(node.value)
        if isinstance(node, ast.List):
            return [eval_ast(elt) for elt in node.elts]
        if isinstance(node, ast.Tuple):
            return tuple(eval_ast(elt) for elt in node.elts)
        if isinstance(node, ast.Dict):
            return {eval_ast(k): eval_ast(v) for k, v in zip(node.keys, node.values)}
        raise ValueError(f"Unsupported expression node: {type(node).__name__}")

    tree = ast.parse(expr_eval, mode="eval")
    return eval_ast(tree)


def log_print_message(level: str, msg: str):
    lvl = (level or "debug").strip().lower()
    if lvl in ("info", "i"):
        Logger.info(msg)
    elif lvl in ("warn", "warning", "w"):
        Logger.warning(msg)
    elif lvl in ("error", "err", "e"):
        Logger.error(msg)
    elif lvl in ("success", "ok", "s"):
        Logger.success(msg)
    elif lvl in ("anticheat", "anti", "a"):
        Logger.anticheat(msg)
    elif lvl in ("script", "sc"):
        Logger.script(msg)
    else:
        Logger.debug(msg)
