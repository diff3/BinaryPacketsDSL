from cli.commands import COMMANDS


class HelpError(Exception):
    pass


def get_node(path_tokens):
    node = {"children": COMMANDS}
    for tok in path_tokens:
        children = node.get("children")
        if not children or tok not in children:
            raise HelpError(f"Unknown command: {' '.join(path_tokens)}")
        node = children[tok]
    return node


def render_help(args):
    """
    args: list[str] after 'help'
    returns: list[str] lines to print
    """
    node = get_node(args)

    # If node has children → list them
    children = node.get("children")
    if children:
        names = sorted(children.keys())
        width = max(len(name) for name in names)

        lines = []
        for name in names:
            desc = children[name].get("help", "")
            lines.append(f"{name.ljust(width)}  {desc}")
        return lines

    # Leaf node → show its help
    desc = node.get("help", "")
    return [desc] if desc else []