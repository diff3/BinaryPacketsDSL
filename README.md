# BinaryPacketsDSL

**BinaryPacketsDSL** is a modular parser and DSL (Domain-Specific Language) for analyzing and interpreting binary protocol packets. While initially inspired by real-world game network formats, it is now fully generalized to support any binary data structure — making it suitable for reverse engineering, protocol research, and learning projects.

Each packet is defined through a .def file, describing its binary layout using a readable syntax. The parser reads accompanying .bin files (containing raw binary data) and .json files (containing the expected parsed output). These three files together define a **test case**.

When executed, the system parses the binary data according to the structure defined in the .def file and compares the result with the expected .json data. This allows for automated validation of protocol definitions and regression testing across protocol versions.


**Intended Use**

BinaryPacketsDSL is designed for protocol analysts, reverse engineers, and developers working with undocumented binary formats. Its DSL syntax prioritizes clarity, precision, and testability over abstraction – making it ideal for debugging live traffic or decoding archival packet captures.

**Personal Motivation**

This project began as a way to better understand network traffic analysis and deepen my Python skills. What started with curiosity around WoW protocols has evolved into a structured, testable system for binary decoding – built with learning and exploration in mind.


## Features

- DSL for describing binary packet layouts (`.def` files)
- Structured extraction to typed nodes
- YAML-based configuration with overridable CLI parameters
- Built-in test system using `.bin` and `.json` comparisons
- Colored logging (via `Loggger`)
- Modular architecture: parser, extractor, interpreter, CLI



## Getting Started

3. Install and configure a virtual environment:
- Install `virtualenvwrapper`:
  ```bash
  pip install virtualenvwrapper
  ```
- Add the following to your `.bashrc` or `.zshrc`:
  ```bash
  export WORKON_HOME=$HOME/.virtualenvs
  source $(which virtualenvwrapper.sh)
  ```
- Reload your shell:
  ```bash
  source ~/.bashrc  # or ~/.zshrc
  ```

- Create and activate the environment:
  ```bash
  mkvirtualenv bpdsl
  workon bpdsl
  ```

- Install dependencies:
  ```bash
  pip install -r requirements.txt
  ```

- (Optional) Add symlinks to scripts you want to use globally:
  ```bash
  ln -s <path-to-project>/<file>.py ~/.virtualenvs/bpdsl/bin/<file>.py
  ```

- (Optional) Enable autocomplete for CLI tools (like `main.py`):
  Add this line to your `postactivate` script:
  ```bash
  eval "$(register-python-argcomplete main.py)"
  ```

4. Run:
```bash
python3 main.py
python3 main.py -f AUTH_LOGON_CHALLENGE_C
main.py -f <CASE>
```



### args

| Argument      | Description                                                  |
| ------------- | :----------------------------------------------------------- |
| -f, --file    | Specify a single .def packet file (without extension) to parse |
| -p, --program | Set the program name (e.g., mop)                             |
| -V, --version | Set the program version (e.g., 18414)                        |
| -s, --silent  | Suppress all console output, still logs to file              |
| -a, --add     | Create a new, empty packet definition set (requires --program, --version, --file, --bin) |



### **.def File Format**

Each .def file consists of declarative sections:

- variables: – optional definitions like AUTH_OK = 12
- endian: – specifies byte order, e.g. little or big
- header: / data: – the actual packet structure
- Support for loop, block, if, and randseq control structures
- Optional modifiers like s, M, W, C, B to transform or interpret values



Example:
```dsl
endian: little
header:
  cmd: B
  size: H
data:
  username_len: B, BI
  username: €username_len's
```



This describes a packet where:

- cmd is a single byte,
- size is a 2-byte little-endian unsigned integer,
- username_len is read as bits, converted to int (modifier BI),
- username is a UTF-8 string of that length.

### **Resources**

- [Python struct format documentation](https://docs.python.org/3/library/struct.html)

- [YAML syntax guide](https://yaml.org/spec/)

  

### Examples

```Bash
python3 main.py -f AUTH_LOGON_PROOF_S
 {
    "cmd": 0,
    "error": 231,
    "M2": "30627B30E8577802107EB2C4C13551B454C238F0",
    "unk1": 3348831891,
    "unk2": 2030930855,
    "unk3": 62857
}
```



## Unit-tests

Run unit tests against all packet files using:

```bash
python3 -m unittest tests/<tests>.py
```



### Examples

```bash
python -m unittest tests/test_all_cases.py
[SUCCESS] AUTH_LOGON_PROOF_S

Run 1 tests
Success 1 tests
Failed 0 tests
```




## Project Structure

```
BinaryPacketsDSL/
├── etc/            # Configuration files (e.g., config.yaml)
├── logs/           # Output logs (debug, parse failures, etc.)
├── misc/           # Scratchpad, experiments
├── modules/        # Core logic (parser, nodes, extractor)
├── packets/        # Packet definitions and examples (def/bin/js
├── tests/       		# Unit tests, auto validation
├── utils/          # Common helpers (logger, config loader, etc.)
├── doc/            # Documentation and specs
└── main.py         # Entry point
```



## Author

Magnus Pettersson



---

This project follows a clear separation of concerns and aims for high transparency, traceability, and testability – inspired by NASA engineering practices. See doc/* for more information. 