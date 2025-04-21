#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from dataclasses import dataclass, field


@dataclass
class BaseNode:
    """
    Represents a single parsed field in the packet structure.
    """
    name: str
    format: str
    interpreter: str
    modifiers: list[str] = field(default_factory=list)
    depends_on: str | None = None
    dynamic: bool = False
    raw_offset: int | None = None
    raw_length: int | None = None 
    raw_data: bytes | None = None
    value: object | None = None
    ignore: bool = False


@dataclass
class BitmaskNode(BaseNode):
    size: int = 0
    children: list[BaseNode] = field(default_factory=list)
    format: str = field(init=False, default="")
    interpreter: str = field(init=False, default="bitmask")

    def __post_init__(self):
        self.format = ""
        self.interpreter = "bitmask"



@dataclass
class BlockDefinition:
    name: str
    nodes: list[BaseNode]


@dataclass
class IfNode(BaseNode):
    """
    Represents a conditional branch (if/elif/else).
    """
    condition: str = ""
    true_branch: list[BaseNode] = field(default_factory=list)
    false_branch: list[BaseNode] | None = None
    elif_branches: list[tuple[str, list[BaseNode]]] | None = None

    def __post_init__(self):
        self.format = ""
        self.interpreter = "if"


@dataclass
class LoopNode(BaseNode):
    """
    Represents a repeating structure (e.g., a list of nodes based on a count).
    """
    count_from: str = ""
    target: str = ""
    loop_line_count: int = 0
    children: list[BaseNode] = field(default_factory=list)


@dataclass
class PaddingNode:
    size: int
    name: str = field(init=False)
    format: str = field(init=False, default="")
    interpreter: str = field(init=False, default="padding")
    ignore: bool = field(init=False, default=True)
    raw_offset: int | None = None
    raw_length: int | None = None
    raw_data: bytes | None = None
    value: bytes | None = None

    def __post_init__(self):
        self.name = f"padding ({self.size} bytes)"


@dataclass
class RandSeqNode(BaseNode):
    count_from: str = ""
    target: str = ""
    children: list[BaseNode] = field(default_factory=list)

    def __post_init__(self):
        self.format = ""
        self.interpreter = "randseq"


@dataclass
class VariableNode:
    name: str
    raw_value: str
    value: object | None = None
    format: str | None = None
    interpreter: str | None = None
    modifiers: list[str] = field(default_factory=list)
    depends_on: str | None = None
    dynamic: bool = False
    ignore: bool = False
    

@dataclass
class PacketSession:
    """
    Holds state for a single packet analysis session.
    """
    endian: str = "little"
    variables: dict[str, VariableNode] = field(default_factory=dict)
    fields: list[BaseNode] = field(default_factory=list)
    raw_data: bytes | None = None
    version: str | None = None
    program: str | None = None
    offset: int = 0
    blocks: dict[str, BlockDefinition] = field(default_factory=dict)

    def reset(self) -> None:
        """
        Clear session-specific state while preserving config.
        """
        self.variables.clear()
        self.fields.clear()
        self.raw_data = None
        self.offset = 0



def get_session() -> PacketSession:
    """
    Return the singleton instance of PacketSession.

    Ensures that only one shared session object is used throughout
    the program execution. Useful for consistent state management
    across modules and function calls.

    Returns:
        PacketSession: The singleton session instance.
    """
    global _session_instance

    if _session_instance is None:
        _session_instance = PacketSession()
    
    return _session_instance


# Singleton holder
_session_instance: PacketSession | None = None
