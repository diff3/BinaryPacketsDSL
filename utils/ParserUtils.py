#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re 


class ParserUtils:

    @staticmethod   
    def remove_comments_and_reserved(struct_definition: list) -> list:
        """
        Removes comments (single and multi-line) and reserved sections ('header:', 'data:') 
        from the provided structure definition.
        """

        i = 0
        new_list = []

        while i < len(struct_definition):
            line = struct_definition[i].strip()

            if line.startswith('#-'):
                while not struct_definition[i].strip().endswith("-#"):
                    i += 1  
                i += 1  
                continue  
            elif line.startswith('#'):
                i += 1  
                continue 
            elif '#' in line:
                line = struct_definition.split('#')[0].strip()
                if line:  
                    new_list.append(line)
                i += 1
                continue  
            elif line.startswith("header:") or line.startswith("data:") or not line.strip():
                i += 1  
                continue  
            else:
                new_list.append(struct_definition[i])
                i += 1

        return new_list

    @staticmethod
    def count_size_of_block_structure(lines: list, i: int) -> list:
        """
        Given a list of lines and a starting index, this function returns the number of 
        indented lines and the list of those lines within the loop.
        """
        block_lines = []
        leading_spaces = len(re.match(r"^\s*", lines[i])[0])

        i += 1
        ant = 0

        while i < len(lines):
            line = lines[i]
            line_content = line.strip()

            if len(line_content) <= 0:
             
                break

            # Stoppa om vi backar ut på indraget
            if len(re.match(r"^\s*", line)[0]) <= leading_spaces:
   
                break

            block_lines.append(line_content)
            ant += 1
            i += 1

        return [ant, block_lines]
