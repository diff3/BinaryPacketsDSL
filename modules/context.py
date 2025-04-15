from dataclasses import dataclass, field
import pprint
from copy import deepcopy

@dataclass
class ParserContext:
    assignment: list = field(default_factory=list)
    offset: int = 0
    i: int = 0
    bit_pos: int = 0
    byte_pos: int = 0
    parsed_data: dict = field(default_factory=dict)
    raw_data: bytes = b""
    fields: list = field(default_factory=list)
    modifiers: dict = field(default_factory=dict)
    block: dict = field(default_factory=dict)
    struct_definition_list: list = field(default_factory=list)
    debug: bool = False
    variables: dict = field(default_factory=dict)
    just: int = 0
    endianess: str = "<"

    def reset(self):
        self.assignment.clear()
        self.offset = 0
        self.i = 0
        self.bit_pos = 0
        self.byte_pos = 0
        self.parsed_data.clear()
        self.raw_data = b""
        self.fields.clear()
        self.modifiers.clear()
        self.block.clear()
        self.struct_definition_list.clear()
        self.debug = False
        self.just = 0
        self.endianess = "<"

    def get_values(self, *keys):
        values = []
        for key in keys:
            if not hasattr(self, key):
                raise KeyError(f"ParserContext has no attribute '{key}'")
            values.append(getattr(self, key))
        return tuple(values)
    
    def describe(self, show_empty=False):
        result = {}
        for field_name in self.__dataclass_fields__:
            value = getattr(self, field_name)
            if show_empty or value not in (None, {}, [], b"", 0, False):
                result[field_name] = value

        return pprint.pformat(result, indent=4, sort_dicts=True)

    def clone(self):
        return deepcopy(self)

    def set_values(self, **kwargs):
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
            else:
                raise AttributeError(f"Invalid field: {key}")

# Singleton-instans
_context = ParserContext()

def get_context() -> ParserContext:
    return _context