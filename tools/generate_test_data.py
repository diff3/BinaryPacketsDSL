#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random

def generate_bin_file(filename="test.bin", length=2000, min_byte=1, max_byte=10):
    data = bytes(random.randint(min_byte, max_byte) for _ in range(length))
    with open(filename, "wb") as f:
        f.write(data)
    print(f"Generated {filename} with {length} random bytes.")

if __name__ == "__main__":
    generate_bin_file()