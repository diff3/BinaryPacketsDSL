#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json


class FileHandler():

    @staticmethod
    def load_file(file_path:str) -> str:
        with open(file_path, "r") as file:
            return file.read()

    @staticmethod
    def load_bin_file(file_path:str) -> str:
        with open(file_path, "rb") as file:
            return file.read()

    @staticmethod
    def load_json_file(file_path:str) -> dict:
        with open(file_path, "r") as file:
            return json.load(file)