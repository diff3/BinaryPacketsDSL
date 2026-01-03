#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import hashlib
from sqlalchemy import text

from utils.Logger import Logger
from protocols.vanilla.v1121.modules.database.DatabaseConnection import DatabaseConnection
from protocols.vanilla.v1121.modules.crypto.SRP6CryptoVanilla import SRP6CryptoVanilla


def main():
    if len(sys.argv) != 4:
        print("Usage: create_user_vanilla <username> <password> <gmlevel>")
        return

    username = sys.argv[1]
    password = sys.argv[2]
    try:
        gmlevel = int(sys.argv[3])
    except ValueError:
        print("gmlevel must be an integer")
        return

    DatabaseConnection.initialize()
    session = DatabaseConnection.auth()

    if DatabaseConnection._salt_col is None or DatabaseConnection._verifier_col is None:
        raise RuntimeError("account table lacks salt/verifier columns (SRP6 required)")

    username_u = username.upper()
    password_u = password.upper()
    crypto = SRP6CryptoVanilla(mode="vmangos")

    # vMangos: v = g^x mod N, x = SHA1(s_le || SHA1(UPPER(user:pass))) as little-endian int.
    salt_bytes = os.urandom(32)
    salt_le = salt_bytes[::-1]
    up_hash = hashlib.sha1(f"{username_u}:{password_u}".encode("utf-8")).digest()
    x_int = int.from_bytes(hashlib.sha1(salt_le + up_hash).digest(), "little")
    n_int = int.from_bytes(crypto._modulus_bytes_be, "big")
    v_int = pow(crypto.G, x_int, n_int)
    verifier_bytes = v_int.to_bytes(32, "big")

    if DatabaseConnection._srp_binary:
        salt_out = salt_bytes
        verifier_out = verifier_bytes
    else:
        salt_out = salt_bytes.hex()
        verifier_out = verifier_bytes.hex()

    existing = DatabaseConnection.get_user_by_username(username_u)

    if existing is None:
        session.execute(
            text(
                f"INSERT INTO account (username, {DatabaseConnection._salt_col}, {DatabaseConnection._verifier_col}) "
                "VALUES (:username, :salt, :verifier)"
            ),
            {
                "username": username_u,
                "salt": salt_out,
                "verifier": verifier_out,
            },
        )
        Logger.success(f"[DB] Created account {username_u}")
    else:
        session.execute(
            text(
                f"UPDATE account SET {DatabaseConnection._salt_col} = :salt, "
                f"{DatabaseConnection._verifier_col} = :verifier "
                "WHERE username = :username"
            ),
            {
                "username": username_u,
                "salt": salt_out,
                "verifier": verifier_out,
            },
        )
        Logger.success(f"[DB] Updated account {username_u}")

    session.commit()

    acc = DatabaseConnection.get_user_by_username(username_u)
    acc_id = getattr(acc, "id", None)
    if acc_id is not None:
        DatabaseConnection.set_gmlevel(acc_id, gmlevel)
    else:
        Logger.warning(f"[DB] Could not resolve account id for {username_u}")

    Logger.success(f"User '{username_u}' created/updated (id={acc_id}).")
    Logger.success(f"GM level {gmlevel}")
    Logger.success(f"Salt: {salt_bytes.hex()}")
    Logger.success(f"Verifier: {verifier_bytes.hex()}")


if __name__ == "__main__":
    main()
