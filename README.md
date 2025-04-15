# BinaryPacketsDSL

**BinaryPacketsDSL** is a modular tool and DSL for parsing and interpreting binary protocol packets. Originally inspired by World of Warcraft network protocol analysis, it is now fully generalized for any binary data format.



## Features

- DSL for describing binary packet layouts (`.def` files)
- Structured extraction to typed nodes
- YAML-based configuration with overridable CLI parameters
- Built-in test system using `.bin` and `.json` comparisons
- Colored logging (via `Loggger`)
- Modular architecture: parser, extractor, interpreter, CLI



## Project Structure

```
BinaryPacketsDSL/
├── etc/            # Configuration files (e.g., config.yaml)
├── logs/           # Output logs (debug, parse failures, etc.)
├── misc/           # Scratchpad, experiments
├── modules/        # Core logic (parser, nodes, extractor)
├── pakets/         # Packet definitions and examples (def/bin/json)
├── unittest/       # Unit tests, auto validation
├── utils/          # Common helpers (logger, config loader, etc.)
├── doc/            # Documentation and specs
└── main.py         # Entry point
```



## Getting Started

1. Set up your `config.yaml` in `etc/`
2. Place `.def`, `.bin`, and `.json` in `pakets/<program>/<version>/`
3. Run:

```bash
python3 main.py
```



## Testing

Run unit tests against all packet files using:

```bash
python3 -m unittest discover unittest/
```



## Author

Magnus Pettersson



---

This project follows a clear separation of concerns and aims for high transparency, traceability, and testability – inspired by NASA engineering practices. See doc/* for more information. 