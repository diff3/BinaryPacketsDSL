#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Global variable scope management for the DSL runtime."""

from __future__ import annotations

from typing import Any, Optional


class GlobalScope:
    """Manage global and local scope variables for the DSL runtime."""

    def __init__(self) -> None:
        """Initialize empty global and local scope containers."""
        self.global_vars: dict[str, Any] = {}
        self.scope_stack: list[dict[str, Any]] = []
        self.loop_index: dict[str, int] = {}

    def get(self, name: str, default: Optional[Any] = None) -> Any:
        """Get a variable value, searching local scopes before globals."""
        for scope in reversed(self.scope_stack):
            if name in scope:
                return scope[name]

        return self.global_vars.get(name, default)

    def set(self, name: str, value: Any) -> None:
        """Set a variable value in the current local scope or globals."""
        if self.scope_stack:
            self.scope_stack[-1][name] = value
        else:
            self.global_vars[name] = value

    def delete(self, name: str) -> None:
        """Delete a variable from local scope or globals."""
        for scope in reversed(self.scope_stack):
            if name in scope:
                del scope[name]
                return

        if name in self.global_vars:
            del self.global_vars[name]

    def push(self) -> None:
        """Open a new local scope."""
        self.scope_stack.append({})

    def pop(self) -> None:
        """Close the most recent local scope."""
        if not self.scope_stack:
            raise RuntimeError("Scope stack underflow")
        self.scope_stack.pop()

    def reset(self) -> None:
        """Reset the global scope state before a new decode pass."""
        self.global_vars.clear()
        self.scope_stack.clear()
        self.loop_index.clear()

    def dump(self) -> None:
        """Print the current scope state for debugging."""
        print("GLOBAL:", self.global_vars)
        for idx, scope in enumerate(self.scope_stack):
            print(f"LOCAL[{idx}]:", scope)
        print("LOOP_INDEX:", self.loop_index)

    def get_all(self) -> dict[str, Any]:
        """Return a shallow copy of global variables."""
        return dict(self.global_vars)

    def set_all(self, mapping: dict[str, Any]) -> None:
        """Replace global variables with the provided mapping."""
        self.global_vars = dict(mapping)
