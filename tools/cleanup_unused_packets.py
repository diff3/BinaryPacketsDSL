#!/usr/bin/env python3
import os
from pathlib import Path

ROOT = Path("protocols/mop/v18414")   # ändra vid behov
DEF_DIR = ROOT / "def"
BIN_DIR = ROOT / "bin"
JSON_DIR = ROOT / "json"
DBG_DIR = ROOT / "debug"

def load_def_names():
    """Return set of DEF-namn utan extension."""
    return {p.stem for p in DEF_DIR.glob("*.def")}

def clean_folder(folder: Path, valid: set):
    """Remove files whose basenames don't match a DEF."""
    for f in folder.glob("*"):
        name = f.stem  # exempel: "SMSG_AUTH_RESPONSE"
        if name not in valid:
            print(f"[REMOVE] {f}")
            f.unlink()

def main():
    valid = load_def_names()
    clean_folder(BIN_DIR, valid)
    clean_folder(JSON_DIR, valid)
    clean_folder(DBG_DIR, valid)

if __name__ == "__main__":
    main()