#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
from typing import List


class FileHandler():
    """
    Utility class for loading and listing packet-related files.

    Supports reading .def, .bin, and .json files, as well as listing available cases.
    Intended for use in both CLI and automated processing.
    """
    
    @staticmethod
    def load_file(file_path:str) -> str:
        with open(file_path, "r") as file:
            return file.readlines()

    @staticmethod
    def load_bin_file(file_path:str) -> str:
        with open(file_path, "rb") as file:
            return file.read()

    @staticmethod
    def load_json_file(file_path:str) -> dict:
        with open(file_path, "r") as file:
            return json.load(file)

    @staticmethod
    def list_def_files(program: str, version: str) -> List[str]:
        folder = f"packets/{program}/{version}/def"
        if not os.path.exists(folder):
            return []
        
        return [
            f.replace(".def", "")
            for f in os.listdir(folder)
            if f.endswith(".def")
        ]