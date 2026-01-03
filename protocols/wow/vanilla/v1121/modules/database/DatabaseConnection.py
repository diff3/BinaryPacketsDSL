#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from types import SimpleNamespace
from datetime import datetime

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import scoped_session, sessionmaker

from utils.ConfigLoader import ConfigLoader
from utils.Logger import Logger
from protocols.wow.shared.modules.crypto.SRP6Crypto import SRP6Crypto

from protocols.wow.vanilla.v1121.modules.database.AuthModel import Account, AccountAccess, RealmList
from protocols.wow.vanilla.v1121.modules.database.CharactersModel import Characters


class DatabaseConnection:
    """Handles separate DB connections for auth-db and characters-db."""

    _auth_engine = None
    _auth_session = None

    _char_engine = None
    _char_session = None

    # Detected auth.account column names (runtime introspection)
    _account_columns: set[str] = set()
    _sessionkey_col: str | None = None
    _sessionkey_binary: bool = False
    _salt_col: str | None = None
    _verifier_col: str | None = None
    _srp_binary: bool = False

    @staticmethod
    def initialize():
        """Initialize BOTH auth and characters DB connections."""
        config = ConfigLoader.load_config()
        db = config["database"]

        # AUTH DATABASE
        auth_db_name = db.get("auth_db") or db.get("realmd")
        if not auth_db_name:
            raise RuntimeError("Database name for auth DB is missing (auth_db/realmd).")
        auth_url = (
            f"mysql+pymysql://{db['username']}:{db['password']}@"
            f"{db['host']}:{db['port']}/{auth_db_name}?charset=utf8"
        )
        DatabaseConnection._auth_engine = create_engine(auth_url, pool_pre_ping=True)
        DatabaseConnection._auth_session = scoped_session(
            sessionmaker(bind=DatabaseConnection._auth_engine, autoflush=False)
        )

        DatabaseConnection._detect_account_columns()

        # CHARACTERS DATABASE
        characters_db_name = db.get("characters_db") or db.get("characters")
        if not characters_db_name:
            raise RuntimeError("Database name for characters DB is missing (characters_db/characters).")
        char_url = (
            f"mysql+pymysql://{db['username']}:{db['password']}@"
            f"{db['host']}:{db['port']}/{characters_db_name}?charset=utf8"
        )
        DatabaseConnection._char_engine = create_engine(char_url, pool_pre_ping=True)
        DatabaseConnection._char_session = scoped_session(
            sessionmaker(bind=DatabaseConnection._char_engine, autoflush=False)
        )

        Logger.info("Database initialized (auth + characters)")

    @staticmethod
    def _pick_first(columns: set[str], candidates: list[str]) -> str | None:
        """Return the first candidate name that exists in `columns`."""
        for name in candidates:
            if name in columns:
                return name
        return None

    @staticmethod
    def _detect_account_columns():
        """
        Inspect the account table to adapt to different schemas (vanilla vs mop).
        Stores resolved column names for later queries.
        """
        try:
            insp = inspect(DatabaseConnection._auth_engine)
            cols = {c["name"] for c in insp.get_columns("account")}
            DatabaseConnection._account_columns = cols

            DatabaseConnection._sessionkey_col = DatabaseConnection._pick_first(
                cols, ["sessionkey", "session_key", "sessionKey"]
            )
            DatabaseConnection._sessionkey_binary = (
                DatabaseConnection._sessionkey_col in {"session_key", "sessionKey"}
            )

            DatabaseConnection._salt_col = DatabaseConnection._pick_first(
                cols, ["s", "salt"]
            )
            DatabaseConnection._verifier_col = DatabaseConnection._pick_first(
                cols, ["v", "verifier"]
            )
            DatabaseConnection._srp_binary = (
                DatabaseConnection._salt_col == "salt"
                or DatabaseConnection._verifier_col == "verifier"
            )

            if DatabaseConnection._salt_col is None or DatabaseConnection._verifier_col is None:
                Logger.warning(
                    "[DB] account table missing: salt/verifier (SRP6 required)"
                )
        except Exception as exc:
            Logger.error(f"[DB] Failed to inspect account table: {exc}")
            DatabaseConnection._account_columns = set()
            DatabaseConnection._sessionkey_col = None
            DatabaseConnection._salt_col = None
            DatabaseConnection._verifier_col = None

    # AUTH DB SESSION
    @staticmethod
    def auth():
        if DatabaseConnection._auth_session is None:
            raise RuntimeError("DatabaseConnection.initialize() not called.")
        return DatabaseConnection._auth_session

    # CHARACTERS DB SESSION
    @staticmethod
    def chars():
        if DatabaseConnection._char_session is None:
            raise RuntimeError("DatabaseConnection.initialize() not called.")
        return DatabaseConnection._char_session

    # AUTH QUERIES
    @staticmethod
    def get_user_by_username(username: str):
        """Fetch account row by username using runtime-detected schema."""
        session = DatabaseConnection.auth()

        cols = ["id", "username"]
        for opt in [
            DatabaseConnection._salt_col,
            DatabaseConnection._verifier_col,
            DatabaseConnection._sessionkey_col,
            "last_ip" if "last_ip" in DatabaseConnection._account_columns else None,
            "last_login" if "last_login" in DatabaseConnection._account_columns else None,
        ]:
            if opt:
                cols.append(opt)

        cols_sql = ", ".join(cols)
        row = session.execute(
            text(f"SELECT {cols_sql} FROM account WHERE username = :username LIMIT 1"),
            {"username": username},
        ).mappings().first()

        if not row:
            return None

        ns = SimpleNamespace(**row)

        # Canonical aliases
        if DatabaseConnection._salt_col and DatabaseConnection._salt_col in row:
            setattr(ns, "s", row[DatabaseConnection._salt_col])
            setattr(ns, "salt", row[DatabaseConnection._salt_col])
        if DatabaseConnection._verifier_col and DatabaseConnection._verifier_col in row:
            setattr(ns, "v", row[DatabaseConnection._verifier_col])
            setattr(ns, "verifier", row[DatabaseConnection._verifier_col])
        if DatabaseConnection._sessionkey_col and DatabaseConnection._sessionkey_col in row:
            setattr(ns, "sessionkey", row[DatabaseConnection._sessionkey_col])

        return ns

    @staticmethod
    def get_realmlist():
        return DatabaseConnection.auth().query(RealmList).first()

    @staticmethod
    def get_all_realms():
        return DatabaseConnection.auth().query(RealmList).all()

    # CHARACTER QUERIES
    @staticmethod
    def get_characters_for_account(account_id, realm_id=None):
        session = DatabaseConnection.chars()
        rows = session.execute(
            text(
                "SELECT guid, account, name "
                "FROM characters WHERE account = :account"
            ),
            {"account": account_id},
        ).mappings().all()
        return [SimpleNamespace(**row) for row in rows]

    @staticmethod
    def count_characters_for_account(account_id, realm_id=None):
        session = DatabaseConnection.chars()
        try:
            row = session.execute(
                text(
                    "SELECT COUNT(*) AS count "
                    "FROM characters WHERE account = :account"
                ),
                {"account": account_id},
            ).mappings().first()
            return int(row["count"]) if row else 0
        except Exception as exc:
            Logger.error(f"[DB] Failed to count characters: {exc}")
            return 0

    # SRP helpers
    @staticmethod
    def update_sessionkey(account, key_bytes):
        if DatabaseConnection._sessionkey_col is None:
            return

        session = DatabaseConnection.auth()
        if DatabaseConnection._sessionkey_binary and isinstance(key_bytes, (bytes, bytearray)):
            val = bytes(key_bytes)
        elif isinstance(key_bytes, (bytes, bytearray)):
            # vMangos stores sessionkey as big-endian hex string; reverse K bytes.
            val = bytes(key_bytes)[::-1].hex().upper()
        else:
            val = key_bytes

        params = {
            "sessionkey": val,
            "id": getattr(account, "id", None),
            "username": getattr(account, "username", None),
        }
        where = "id = :id" if params["id"] is not None else "username = :username"

        session.execute(
            text(
                f"UPDATE account SET {DatabaseConnection._sessionkey_col} = :sessionkey "
                f"WHERE {where}"
            ),
            params,
        )
        session.commit()

    @staticmethod
    def update_verifier_and_salt(account, verifier, salt):
        if DatabaseConnection._salt_col is None or DatabaseConnection._verifier_col is None:
            return

        session = DatabaseConnection.auth()

        if DatabaseConnection._srp_binary:
            ver_out = verifier if isinstance(verifier, (bytes, bytearray)) else DatabaseConnection._as_bytes(verifier)
            salt_out = salt if isinstance(salt, (bytes, bytearray)) else DatabaseConnection._as_bytes(salt)
        else:
            ver_out = verifier.hex() if isinstance(verifier, (bytes, bytearray)) else verifier
            salt_out = salt.hex() if isinstance(salt, (bytes, bytearray)) else salt

        params = {
            "verifier": ver_out,
            "salt": salt_out,
            "id": getattr(account, "id", None),
            "username": getattr(account, "username", None),
        }
        where = "id = :id" if params["id"] is not None else "username = :username"

        session.execute(
            text(
                f"UPDATE account SET {DatabaseConnection._verifier_col} = :verifier, "
                f"{DatabaseConnection._salt_col} = :salt "
                f"WHERE {where}"
            ),
            params,
        )
        session.commit()
    
    # ACCOUNT ORM HELPERS

    @staticmethod
    def create_or_update_account(username: str, password: str):
        """
        Create or update an account in the vanilla auth DB.

        vMangos uses SRP6 (salt/verifier) only.
        """
        session = DatabaseConnection.auth()

        has_srp = (
            DatabaseConnection._salt_col is not None
            and DatabaseConnection._verifier_col is not None
        )

        if not has_srp:
            raise RuntimeError("account table lacks salt/verifier columns (SRP6 required)")

        existing = DatabaseConnection.get_user_by_username(username)

        cfg = ConfigLoader.load_config()
        srp_mode = cfg.get("crypto", {}).get("srp6_mode", "vmangos")
        crypto = SRP6Crypto(mode=srp_mode)
        salt_bytes, verifier_bytes = crypto.make_registration(username, password)

        if DatabaseConnection._srp_binary:
            salt_out = salt_bytes
            verifier_out = verifier_bytes
        else:
            salt_out = salt_bytes.hex()
            verifier_out = verifier_bytes.hex()

        if existing is None:
            session.execute(
                text(
                    f"INSERT INTO account (username, {DatabaseConnection._salt_col}, {DatabaseConnection._verifier_col}) "
                    "VALUES (:username, :salt, :verifier)"
                ),
                {
                    "username": username,
                    "salt": salt_out,
                    "verifier": verifier_out,
                },
            )
            Logger.success(f"[DB] Created account {username}")
        else:
            session.execute(
                text(
                    f"UPDATE account SET {DatabaseConnection._salt_col} = :salt, "
                    f"{DatabaseConnection._verifier_col} = :verifier "
                    "WHERE username = :username"
                ),
                {
                    "username": username,
                    "salt": salt_out,
                    "verifier": verifier_out,
                },
            )
            Logger.success(f"[DB] Updated account {username}")

        session.commit()

        acc = DatabaseConnection.get_user_by_username(username)
        return getattr(acc, "id", None)

    @staticmethod
    def _as_bytes(value):
        if value is None:
            return None
        if isinstance(value, (bytes, bytearray)):
            return bytes(value)
        try:
            raw = str(value).strip()
            return bytes.fromhex(raw)
        except Exception:
            return None

    @staticmethod
    def get_or_generate_srp(account: Account):
        """
        Return (salt_bytes, verifier_bytes) for the account.
        """
        salt_attr = getattr(account, "s", None) or getattr(account, "salt", None)
        verifier_attr = getattr(account, "v", None) or getattr(account, "verifier", None)

        salt_bytes = DatabaseConnection._as_bytes(salt_attr)
        verifier_bytes = DatabaseConnection._as_bytes(verifier_attr)

        if salt_bytes and verifier_bytes and len(salt_bytes) == 32 and len(verifier_bytes) == 32:
            return salt_bytes, verifier_bytes

        return None, None

    @staticmethod
    def set_gmlevel(account_id, gmlevel):
        """
        Uses ORM model for account_access just like SkyFire expects.
        """
        session = DatabaseConnection.auth()

        row = (
            session.query(AccountAccess)
            .filter(AccountAccess.id == account_id)
            .first()
        )

        if row is None:
            row = AccountAccess(id=account_id, gmlevel=gmlevel, RealmID=-1)
            session.add(row)
        else:
            row.gmlevel = gmlevel

        session.commit()
        Logger.success(f"[DB] GM level set to {gmlevel} for account {account_id}")

    @staticmethod
    def update_login_metadata(account, session_key_bytes, last_ip: str):
        """
        Update session key + last login/ip in the most compatible way.
        """
        session = DatabaseConnection.auth()

        set_parts = []
        params = {
            "id": getattr(account, "id", None),
            "username": getattr(account, "username", None),
        }

        if DatabaseConnection._sessionkey_col:
            if DatabaseConnection._sessionkey_binary and isinstance(session_key_bytes, (bytes, bytearray)):
                params["sessionkey"] = bytes(session_key_bytes)
            elif isinstance(session_key_bytes, (bytes, bytearray)):
                # vMangos stores sessionkey as big-endian hex string; reverse K bytes.
                params["sessionkey"] = session_key_bytes[::-1].hex().upper()
            else:
                params["sessionkey"] = session_key_bytes
            set_parts.append(f"{DatabaseConnection._sessionkey_col} = :sessionkey")

        if "last_login" in DatabaseConnection._account_columns:
            params["last_login"] = datetime.utcnow()
            set_parts.append("last_login = :last_login")

        if "last_ip" in DatabaseConnection._account_columns and last_ip:
            params["last_ip"] = last_ip
            set_parts.append("last_ip = :last_ip")

        if not set_parts:
            return

        where = "id = :id" if params["id"] is not None else "username = :username"

        session.execute(
            text(f"UPDATE account SET {', '.join(set_parts)} WHERE {where}"),
            params,
        )
        session.commit()
