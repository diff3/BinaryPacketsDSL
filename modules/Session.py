#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from dataclasses import dataclass, field
from typing import Any, List, Optional


@dataclass
class BaseNode:
    """
    Represents a single parsed field in the packet structure.
    """
    name: str
    format: str
    interpreter: str
    modifiers: List[str] = field(default_factory=list)
    depends_on: Optional[str] = None
    dynamic: bool = False
    raw_offset: Optional[int] = None
    raw_length: Optional[int] = None 
    raw_data: Optional[bytes] = None
    value: Optional[Any] = None


@dataclass
class LoopNode(BaseNode):
    """
    Represents a repeating structure (e.g., a list of nodes based on a count).
    """
    count_from: str = ""
    target: str = ""
    children: List[BaseNode] = field(default_factory=list)     


@dataclass
class PacketSession:
    """
    Holds state for a single packet analysis session.
    """
    endian: str = "little"
    variables: dict[str, Any] = field(default_factory=dict)
    fields: List[BaseNode] = field(default_factory=list)
    raw_data: Optional[bytes] = None
    version: Optional[str] = None
    program: Optional[str] = None
    offset: int = 0

    def reset(self) -> None:
        """
        Clear session-specific state while preserving config.
        """
        self.variables.clear()
        self.fields.clear()
        self.raw_data = None
        self.parse_offset = 0

# Singleton holder
_session_instance: Optional[PacketSession] = None

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