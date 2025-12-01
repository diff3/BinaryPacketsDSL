# utils/AutoRewrite.py

import importlib
from utils.ConfigLoader import ConfigLoader

def resolve_import(request: str):
    cfg = ConfigLoader.load_config()
    program = cfg["program"]
    version = cfg["version"]

    # ------------------------------------------------------
    # Old import: "from packets.AuthOpcodes import ..."
    # Return dynamic opcodes (client, server, lookup)
    # ------------------------------------------------------
    if "protocols.AuthOpcodes" in request:
        from utils.OpcodeLoader import load_auth_opcodes
        client, server, lookup = load_auth_opcodes()
        return {
            "AUTH_CLIENT_OPCODES": client,
            "AUTH_SERVER_OPCODES": server,
            "lookup": lookup
        }

    # ------------------------------------------------------
    # Old import: "from handlers.AuthHandler import ..."
    # Return dynamic handlers
    # ------------------------------------------------------
    if "handlers.AuthHandler" in request:
        module_path = f"protocols.{program}.{version}.handlers.AuthHandlers"
        handlers_module = importlib.import_module(module_path)
        return handlers_module.opcode_handlers

    # ------------------------------------------------------
    # Fallback
    # ------------------------------------------------------
    raise ImportError(f"AutoRewrite cannot resolve import: {request}")