from cli.editor import LineEditor
from cli.parser import parse_command, CommandError
from cli.help import render_help

ed = LineEditor(completer=None)

try:
    while True:
        line = ed.read_line()
        if line is None:
            break

        line = line.strip()
        if not line:
            continue

        try:
            action, args = parse_command(line)
        except CommandError as exc:
            print(exc)
            continue

        result = action(None, args)

        if isinstance(result, tuple):
            intent, payload = result
            if intent == "__help__":
                for row in render_help(payload):
                    print(row)
                continue
            if intent == "__exit__":
                break

        if isinstance(result, str):
            print(result)
        elif isinstance(result, list):
            for row in result:
                print(row)

except KeyboardInterrupt:
    print("\n^C")

print("Bye.")