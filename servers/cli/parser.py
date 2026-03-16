from cli.commands import COMMANDS


class CommandError(Exception):
    pass


def parse_command(line: str):
    tokens = line.strip().split()
    if not tokens:
        return None, []

    node = {"children": COMMANDS}
    args = []

    for i, token in enumerate(tokens):
        children = node.get("children")
        if not children:
            # No more subcommands → rest are args
            args = tokens[i:]
            break

        if token not in children:
            raise CommandError(f"Unknown command: {token}")

        node = children[token]

    action = node.get("action")
    if not action:
        raise CommandError("Incomplete command")

    return action, args