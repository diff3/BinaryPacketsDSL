#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
import sys

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

from packet_diff import main


if __name__ == "__main__":
    raise SystemExit(main())
