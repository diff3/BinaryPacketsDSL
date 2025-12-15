# DESIGN.md

## Project Overview
This project is a flexible and testable system for parsing and interpreting binary protocol data. It is inspired by earlier work with game network protocols (e.g. WoW), but is now generalized for arbitrary binary formats.

It uses a DSL to describe binary structures, and maps those descriptions into a typed node tree (AST-like) which can be traversed and interpreted. The goal is clarity, modularity, and robust analysis.

---

## Key Design Goals
- Clear separation of parser, interpreter, config, and logger
- AST-like node tree structure with typed dataclasses
- Global variable context with dependencies
- Reproducible, testable, file-based architecture
- NASA-inspired: prioritize **clarity**, **robustness**, **traceability**

---

## Core Concepts

### Node Tree
Each binary packet is parsed into a list/tree of nodes.
Each node contains:
- `name`: str
- `format`: str
- `interpreter`: str (e.g. "struct", "loop")
- `modifiers`: list[str]
- `offset`: int (filled by extractor)
- `length`: int (filled by extractor)
- `raw_data`: bytes
- `value`: any

Special interpreters like `loop` include:
- `fields`: list[BaseNode]
- Additional fields: `count_from`, `source_offset`, etc.

All nodes are instances of `BaseNode` or its subclasses.

---

## File Structure
```
packets/
  wow/
    18414/
      login.def
      login.bin
      login.json
```

Each packet includes:
- `.def`: structure definition
- `.bin`: binary input data
- `.json`: expected output result

---

## Configuration
- All project-wide settings are in `config.yaml`
- CLI arguments can override config values

Configuration includes:
- program name / version
- input folder path
- logger settings (colors, verbosity)

---

## Logging
- Logging is handled by `Loggger` module (custom or third-party)
- Colored log levels: info, debug, warning, error
- Initialized from `config.yaml`

---

## Extraction & Interpretation
The extractor processes the node tree step-by-step:
- Resolves variables
- Reads byte slices
- Applies interpreters (struct, S, etc.)
- Applies modifiers in order
- Fills offset, length, raw_data, value for each node

All variables are global. Dependencies (`depends_on`, `count_from`) are evaluated using a shared environment (`env`).

---

## Testing
- Each `.def`/`.bin`/`.json` trio is treated as a unit test
- `unittest` framework loops over all test files
- Fails are printed with details
- Option to auto-update `.json` output when expected changes

---

## Documentation & Quality
- All classes and methods must include docstrings
- Functions should mark input/output types clearly:
```python
    def parse_line(line: str) -> dict:
        ...
```
- Use `@dataclass` for all nodes
- All parsing/interpreting logic must be covered by unit tests

---

## Future-Proofing
- Allow alternative backends (e.g. hex viewer)
- Optionally support interpreter pipelines (if needed later)
- Keep DSL extensible but minimal
