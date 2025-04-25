# BinaryPacketsDSL

**BinaryPacketsDSL** is a modular parser and DSL (Domain-Specific Language) for analyzing and interpreting binary protocol packets. While initially inspired by real-world game network formats, it is now fully generalized to support any binary data structure — making it suitable for reverse engineering, protocol research, and learning projects.

This project follows a clear separation of concerns and aims for high transparency, traceability, and testability – inspired by NASA engineering practices. See doc/* for more information.

Each packet is defined through a .def file, describing its binary layout using a readable syntax. The parser reads accompanying .bin files (containing raw binary data) and .json files (containing the expected parsed output). These three files together define a **test case**.

When executed, the system parses the binary data according to the structure defined in the .def file and compares the result with the expected .json data. This allows for automated validation of protocol definitions and regression testing across protocol versions.


**Intended Use**

BinaryPacketsDSL is designed for protocol analysts, reverse engineers, and developers working with undocumented binary formats. Its DSL syntax prioritizes clarity, precision, and testability over abstraction – making it ideal for debugging live traffic or decoding archival packet captures. 

**Personal Motivation**

This project began as a way to better understand network traffic analysis and deepen my Python skills. What started with curiosity around real-world network protocols has evolved into a structured, testable system for binary decoding – built with learning and exploration in mind.


## Features

- DSL for describing binary packet layouts (`.def` files)
- Structured extraction to typed nodes
- YAML-based configuration with overridable CLI parameters
- Built-in test system using `.bin` and `.json` comparisons
- Colored logging (via `Loggger`)
- Modular architecture: parser, extractor, interpreter, CLI



## Getting Started

```bash
# Installation guide on a Debian system using system-wide virtualenvwrapper
sudo apt update
sudo apt install python3-venv python3-pip virtualenvwrapper -y

# Add virtualenvwrapper setup to .bashrc
echo 'export WORKON_HOME=$HOME/.virtualenvs' >> ~/.bashrc
echo 'export VIRTUALENVWRAPPER_PYTHON=$(which python3)' >> ~/.bashrc
echo 'source /usr/share/virtualenvwrapper/virtualenvwrapper.sh' >> ~/.bashrc

# Reload shell config to activate virtualenvwrapper
source ~/.bashrc

# OPTIONAL: Use a specific Python version (make sure it's installed first)
# mkvirtualenv -p /usr/bin/python3.11 bpdsl

# Create and activate the virtualenv
mkvirtualenv bpdsl

# If the virtualenv already exists, just activate it instead:
# workon bpdsl

# Create project directory and clone the repo
mkdir -p ~/projects
cd ~/projects
git clone https://github.com/diff3/BinaryPacketsDSL
cd BinaryPacketsDSL

# Install Python dependencies
pip install -r requirements.txt

# Make main.py executable
chmod +x main.py

# Symlink main.py into the virtualenv's bin directory
ln -s "$PWD/main.py" "$VIRTUAL_ENV/bin/main.py"

# Enable tab-completion for main.py
echo 'eval "$(register-python-argcomplete main.py 2>/dev/null)"' >> "$VIRTUAL_ENV/bin/postactivate"

# Ensure the postactivate script is executable
chmod +x "$VIRTUAL_ENV/bin/postactivate"

# Reload the environment to apply changes (re-runs postactivate)
workon bpdsl

# Now tab-completion should work for:
# main.py -f <tab>
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
├── tests/          # Unit tests, auto validation
├── utils/          # Common helpers (logger, config loader, etc.)
├── doc/            # Documentation and specs
└── main.py         # Entry point
```


## Generate test data

```bash
# Generate test data from file
python tools/generate_test_data.py
python main.py --add --file test1 --program custom -V 10000 -b test.bin
rm test.bin

# Or provide bytes directly
python main.py --add --file test2 --program custom -V 10000 -b "b'\x01\x02\x03\x04\x05'"
```

--
Created by Magnus Pettersson

This project contains no proprietary data or assets and is intended for educational and research use only.