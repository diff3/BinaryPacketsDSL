#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""AST node definitions and shared session state for DSL parsing."""

from __future__ import annotations

from typing import Any, Optional

from modules.dsl.GlobalScope import GlobalScope


class BaseNode:
    """Generic AST node container used by the DSL parser."""

    def __init__(
        self,
        name: Optional[str] = None,
        format: Optional[str] = None,
        interpreter: Optional[str] = None,
        modifiers: Optional[list[Any]] = None,
        encode_modifiers: Optional[list[Any]] = None,
        depends_on: Optional[str] = None,
        dynamic: bool = False,
        ignore: bool = False,
        visible: bool = True,
        payload: bool = True,
        has_io: bool = True,
        visibility_prefix: Optional[str] = None,
        optional: bool = False,
    ) -> None:
        """Initialize a base node."""
        self.name = name
        self.format = format
        self.interpreter = interpreter
        self.modifiers = modifiers or []
        self.encode_modifiers = encode_modifiers or []
        self.depends_on = depends_on
        self.dynamic = dynamic
        self.ignore = ignore
        self.visible = visible
        self.payload = payload
        self.has_io = has_io
        self.visibility_prefix = visibility_prefix
        self.optional = optional

        self.value: Any = None
        self.raw_data: Any = None
        self.raw_offset: Optional[int] = None
        self.raw_length: Optional[int] = None
        self.processed = False

    def copy(self) -> BaseNode:
        """Shallow-safe copy for runtime decode operations."""
        new = self.__class__.__new__(self.__class__)
        new.__dict__ = dict(self.__dict__)

        if hasattr(self, "children"):
            new.children = [c.copy() for c in self.children]
        if hasattr(self, "nodes"):
            new.nodes = [c.copy() for c in self.nodes]

        return new

    def clone(self) -> BaseNode:
        """Backward compatible alias for code expecting .clone()."""
        return self.copy()

    def __repr__(self) -> str:
        name = getattr(self, "name", "_")
        fmt = getattr(self, "format", "?")
        interp = getattr(self, "interpreter", "")
        val = getattr(self, "value", None)
        return f"{name} : {fmt} ({interp}) value={val}"

    __str__ = __repr__


class VariableNode(BaseNode):
    """AST node representing a variable assignment."""

    def __init__(
        self,
        name: str,
        raw_value: Optional[str] = None,
        value: Any = None,
        format: Optional[str] = None,
        interpreter: str = "literal",
        modifiers: Optional[list[Any]] = None,
        depends_on: Optional[str] = None,
        dynamic: bool = False,
        ignore: bool = False,
    ) -> None:
        super().__init__(
            name=name,
            format=format,
            interpreter=interpreter,
            modifiers=modifiers,
            depends_on=depends_on,
            dynamic=dynamic,
            ignore=ignore,
        )
        self.raw_value = raw_value
        self.value = value


class IfNode(BaseNode):
    """AST node representing an if/elif/else block."""

    def __init__(
        self,
        name: Optional[str],
        format: Optional[str],
        interpreter: str,
        condition: str,
        true_branch: list[BaseNode],
        false_branch: Optional[list[BaseNode]] = None,
        elif_branches: Optional[list[tuple[str, list[BaseNode]]]] = None,
    ) -> None:
        super().__init__(name=name, format=format, interpreter=interpreter)
        self.condition = condition
        self.true_branch = true_branch
        self.false_branch = false_branch
        self.elif_branches = elif_branches
        self.processed = False


class LoopNode(BaseNode):
    """AST node representing a loop block."""

    def __init__(
        self,
        name: Optional[str],
        format: Optional[str],
        interpreter: str,
        count_from: str,
        target: Optional[str],
        dynamic: bool,
        children: list[BaseNode],
    ) -> None:
        super().__init__(name=name, format=format, interpreter=interpreter, dynamic=dynamic)
        self.count_from = count_from
        self.target = target
        self.children = children
        self.processed = False


class BlockDefinition(BaseNode):
    """AST node for reusable block definitions."""

    def __init__(self, name: str, nodes: list[BaseNode]) -> None:
        super().__init__(name=name, format=None, interpreter="block")
        self.nodes = nodes


class BitmaskNode(BaseNode):
    """AST node for bitmask blocks."""

    def __init__(self, name: str, size: int, children: list[BaseNode]) -> None:
        super().__init__(name=name, interpreter="bitmask")
        self.size = size
        self.children = children
        self.processed = False


class PackedGuidNode(BaseNode):
    """AST node for packed GUID fields."""

    def __init__(
        self,
        name: str,
        format: str,
        interpreter: str,
        modifiers: Optional[list[Any]],
        encode_modifiers: Optional[list[Any]],
        ignore: bool = False,
    ) -> None:
        super().__init__(
            name=name,
            format=format,
            interpreter=interpreter,
            modifiers=modifiers,
            encode_modifiers=encode_modifiers,
            ignore=ignore,
        )
        self.processed = False


class UncompressNode(BaseNode):
    """AST node for compressed payload blocks."""

    def __init__(
        self,
        name: Optional[str],
        format: Optional[str],
        interpreter: str,
        algo: str,
        length_expr: Optional[str],
        children: list[BaseNode],
    ) -> None:
        super().__init__(name=name, format=format, interpreter=interpreter)
        self.algo = algo
        self.length_expr = length_expr
        self.children = children
        self.processed = False


class PacketSession:
    """Session state for a single decode or encode run."""

    def __init__(self) -> None:
        self.fields: list[BaseNode] = []
        self.blocks: dict[str, BlockDefinition] = {}
        self.variables: dict[str, Any] = {}
        self.scope = GlobalScope()

    def reset(self) -> None:
        """Reset the session state for the next decode pass."""
        self.fields = []
        self.blocks = {}
        self.variables = {}
        self.scope = GlobalScope()


class SliceNode(BaseNode):
    """AST node representing a payload slice assignment."""

    def __init__(self, name: str, slice_expr: str) -> None:
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


_singleton_session = PacketSession()


def get_session() -> PacketSession:
    """Return the shared PacketSession singleton."""
    return _singleton_session


__all__ = [
    "BaseNode",
    "VariableNode",
    "IfNode",
    "LoopNode",
    "BlockDefinition",
    "BitmaskNode",
    "PackedGuidNode",
    "UncompressNode",
    "PacketSession",
    "SliceNode",
    "get_session",
]
