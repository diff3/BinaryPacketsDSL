#!/usr/bin/env python3
import os
import sys
import importlib

from utils.Logger import Logger
from utils.ConfigLoader import ConfigLoader
from protocols.wow.shared.modules.crypto.SRP6Crypto import SRP6Crypto
from protocols.wow.shared.modules.crypto.ShaPassHash import ShaPassHash


def get_db():
    cfg = ConfigLoader.load_config()
    program = cfg["program"]
    version = cfg["version"]

    mod = importlib.import_module(
        f"protocols.{program}.{cfg.get('expansion')}.{version}.modules.database.DatabaseConnection"
    )
    DB = getattr(mod, "DatabaseConnection")
    DB.initialize()
    return DB


def main():
    if len(sys.argv) < 3 or len(sys.argv) > 4:
        print("Usage: create_user_pandaria548 <username> <password> [gmlevel]")
        return

    username = sys.argv[1]
    password = sys.argv[2]
    gmlevel = int(sys.argv[3]) if len(sys.argv) == 4 else 0

    sha_hash = ShaPassHash.generate(username, password)
    salt = os.urandom(32)
    verifier = SRP6Crypto().calculate_verifier_from_hash(sha_hash, salt)

    DB = get_db()
    acc_id = DB.create_or_update_account(username.upper(), salt, verifier, sha_pass_hash=sha_hash)
    DB.set_gmlevel(acc_id, gmlevel)

    Logger.success(f"User '{username}' created/updated (id={acc_id}).")
    Logger.success(f"GM level {gmlevel}")
    Logger.success(f"sha_pass_hash: {sha_hash}")
    Logger.success(f"Salt: {salt.hex()}")
    Logger.success(f"Verifier: {verifier.hex()}")


if __name__ == "__main__":
    main()
