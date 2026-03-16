# cli/commands.py
from utils.config_loader import ConfigLoader

def cmd_exit(state, args):
    return "__exit__", None


def cmd_clear(state, args):
    return "\x1b[2J\x1b[H", None

def cmd_help(state, args):
    return "__help__", args

def cmd_routes_show(state, args):
    lines = []
    for name, route in state.routes.items():
        lines.append(
            f"{name}: "
            f"{route['listen']} -> "
            f"{route['forward']['host']}:{route['forward']['port']}"
        )
    return lines

def cmd_state_list(state, args):
    cfg = ConfigLoader.load_active_config("default")
    states = cfg.get("states", {})

    if not states:
        return ["No states defined"]

    return ["states:"] + [f" - {name}" for name in sorted(states)]

def cmd_state_use(state, args):
    if not args:
        return ["usage: state use <name>"]

    name = args[0]

    try:
        cfg = ConfigLoader.load_active_config(name)
    except Exception as exc:
        return [f"unknown state: {name}"]

    # PATCH: uppdatera state in-place
    state.routes.clear()
    state.routes.update(cfg["routes"])

    # uppdatera flaggor om de finns
    for key in ("enable_log", "enable_view", "enable_decode"):
        if key in cfg:
            setattr(state, key, cfg[key])

    return [f"state switched to '{name}'"]

def cmd_state_show(state, args):
    lines = [
        f"shutdown     = {state.shutdown}",
    ]

    # Visa flaggor om de finns
    for name in ("enable_log", "enable_view"):
        if hasattr(state, name):
            lines.append(f"{name:12} = {getattr(state, name)}")

    return lines

COMMANDS = {
    "help": {
        "help": "Show help for commands",
        "action": cmd_help,
    },
    "exit": {
        "help": "Shut down the CLI",
        "action": cmd_exit,
    },
    "clear": {
        "help": "Clear the screen",
        "action": cmd_clear,
    },
    "state": {
        "help": "Inspect or modify state",
        "children": {
            "show": {
                "help": "Show current state",
                "action": cmd_state_show,
            },
            "use": {
                "help": "Switch active state",
                "action": cmd_state_use,
            },
            "list": {
                "help": "List available states",
                "action": cmd_state_list,
            },
        },
    },
    "routes": {
        "help": "Inspect proxy routes",
        "children": {
            "show": {
                "help": "Show active routes",
                "action": cmd_routes_show,
            },
        },
    },

}