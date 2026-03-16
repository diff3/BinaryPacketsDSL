from cli.commands import COMMANDS

def complete(line: str):
    ends_with_space = line.endswith(" ")
    tokens = line.split()

    # 🔑 SPECIAL: help är transparent
    if tokens and tokens[0] == "help":
        rest = line[len("help"):].lstrip()
        matches = complete(rest)
        return matches

    node = {"children": COMMANDS}

    # 1. traversal + prefix
    if not tokens:
        traverse = []
        prefix = ""
    elif ends_with_space:
        traverse = tokens
        prefix = ""
    else:
        traverse = tokens[:-1]
        prefix = tokens[-1]

    # 2. traversera
    for token in traverse:
        children = node.get("children")
        if not children or token not in children:
            return []
        node = children[token]

    children = node.get("children")
    if not children:
        return []

    # 3. inget prefix → lista alla
    if prefix == "":
        return sorted(children.keys())

    # 4. exakt match → descend
    if prefix in children:
        next_node = children[prefix]
        if next_node.get("children"):
            return sorted(next_node["children"].keys())
        return []

    # 5. prefix-match
    return sorted(
        name for name in children.keys()
        if name.startswith(prefix)
    )