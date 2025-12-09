#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from modules.GlobalScope import GlobalScope


# ============================================================
# Base node used by all AST elements
# ============================================================
class BaseNode:
    """Generic AST node container."""

    def __init__(
        self,
        name=None,
        format=None,
        interpreter=None,
        modifiers=None,
        encode_modifiers=None,
        depends_on=None,
        dynamic=False,
        ignore=False
    ):
        self.name = name
        self.format = format
        self.interpreter = interpreter
        self.modifiers = modifiers or []
        self.encode_modifiers = encode_modifiers or []
        self.depends_on = depends_on
        self.dynamic = dynamic
        self.ignore = ignore

        # decoder-populated
        self.value = None
        self.raw_data = None
        self.raw_offset = None
        self.raw_length = None
        self.processed = False

    def copy(self):
        """Shallow-safe copy for runtime decode operations."""
        new = self.__class__.__new__(self.__class__)
        new.__dict__ = dict(self.__dict__)

        if hasattr(self, "children"):
            new.children = [c.copy() for c in self.children]
        if hasattr(self, "nodes"):
            new.nodes = [c.copy() for c in self.nodes]

        return new
    
    def clone(self):
        """Backward compat alias for old code expecting .clone()."""
        return self.copy()
    
    def __repr__(self):
        name = getattr(self, "name", "_")
        fmt = getattr(self, "format", "?")
        interp = getattr(self, "interpreter", "")
        val = getattr(self, "value", None)
        return f"{name} : {fmt} ({interp}) value={val}"

    __str__ = __repr__


# ============================================================
# Variable node
# ============================================================
class VariableNode(BaseNode):
    def __init__(
        self,
        name,
        raw_value=None,
        value=None,
        format=None,
        interpreter="literal",
        modifiers=None,
        depends_on=None,
        dynamic=False,
        ignore=False
    ):
        super().__init__(
            name=name,
            format=format,
            interpreter=interpreter,
            modifiers=modifiers,
            depends_on=depends_on,
            dynamic=dynamic,
            ignore=ignore
        )
        self.raw_value = raw_value
        self.value = value


# ============================================================
# If node
# ============================================================
class IfNode(BaseNode):
    def __init__(
        self,
        name,
        format,
        interpreter,
        condition,
        true_branch,
        false_branch=None,
        elif_branches=None
    ):
        super().__init__(name=name, format=format, interpreter=interpreter)
        self.condition = condition
        self.true_branch = true_branch
        self.false_branch = false_branch
        self.elif_branches = elif_branches
        self.processed = False


# ============================================================
# Loop node
# ============================================================
class LoopNode(BaseNode):
    def __init__(
        self,
        name,
        format,
        interpreter,
        count_from,
        target,
        dynamic,
        children
    ):
        super().__init__(name=name, format=format, interpreter=interpreter, dynamic=dynamic)
        self.count_from = count_from
        self.target = target
        self.children = children
        self.processed = False


# ============================================================
# Block definition (include/import blocks)
# ============================================================
class BlockDefinition(BaseNode):
    def __init__(self, name, nodes):
        super().__init__(name=name, format=None, interpreter="block")
        self.nodes = nodes


# ============================================================
# Randseq nodes
# ============================================================
class RandSeqNode(BaseNode):
    def __init__(
        self,
        name,
        format,
        interpreter,
        count_from,
        children,
        modifiers=None
    ):
        super().__init__(name=name, format=format, interpreter=interpreter, modifiers=modifiers)
        self.count_from = count_from
        self.children = children
        self.processed = False


# ============================================================
# Bitmask node
# ============================================================
class BitmaskNode(BaseNode):
    def __init__(self, name, size, children):
        super().__init__(name=name, interpreter="bitmask")
        self.size = size
        self.children = children
        self.processed = False


# ============================================================
# Packed GUID node
# ============================================================
class PackedGuidNode(BaseNode):
    def __init__(self, name, format, interpreter, modifiers, encode_modifiers, ignore=False):
        super().__init__(
            name=name,
            format=format,
            interpreter=interpreter,
            modifiers=modifiers,
            encode_modifiers=encode_modifiers,
            ignore=ignore
        )
        self.processed = False


# ============================================================
# Uncompress block node
# ============================================================
class UncompressNode(BaseNode):
    def __init__(self, name, format, interpreter, algo, length_expr, children):
        super().__init__(name=name, format=format, interpreter=interpreter)
        self.algo = algo
        self.length_expr = length_expr
        self.children = children
        self.processed = False


# ============================================================
# Session object — includes unified GlobalScope
# ============================================================
class PacketSession:

    def __init__(self):
        self.fields = []
        self.blocks = {}
        self.variables = {}         # legacy compatibility
        self.scope = GlobalScope()  # new variable handling

    def reset(self):
        """Reset for next packet decode."""
        self.fields = []
        self.blocks = {}
        self.variables = {}
        self.scope = GlobalScope()

# ============================================================
# Slice node (e.g. x = slice[a:b])
# ============================================================
class SliceNode(BaseNode):
    def __init__(self, name, slice_expr):
        super().__init__(
            name=name,
            format="",
            interpreter="slice",
            modifiers=[],
            encode_modifiers=[],
            ignore=False,
        )
        self.slice_expr = slice_expr 
        self.processed = False


# ============================================================
# Singleton accessor
# ============================================================
_singleton_session = PacketSession()

def get_session():
    return _singleton_session

