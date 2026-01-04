#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

from utils.ConfigLoader import ConfigLoader
from utils.Logger import Logger

from protocols.wow.pandaria548.v18414.modules.database.AuthModel import (
    Account,
    AccountAccess,
)


class DatabaseConnection:
    """Auth-db connection helpers (minimal for account creation)."""

    _auth_engine = None
    _auth_session = None

    @staticmethod
    def initialize():
        """Initialize auth DB connection."""
        config = ConfigLoader.load_config()
        db = config["database"]

        # AUTH DATABASE
        auth_url = (
            f"mysql+pymysql://{db['username']}:{db['password']}@"
            f"{db['host']}:{db['port']}/{db['auth_db']}?charset=utf8"
        )
        DatabaseConnection._auth_engine = create_engine(auth_url, pool_pre_ping=True)
        DatabaseConnection._auth_session = scoped_session(
            sessionmaker(bind=DatabaseConnection._auth_engine, autoflush=False)
        )

        Logger.info("Database initialized (auth)")

    # AUTH DB SESSION
    @staticmethod
    def auth():
        if DatabaseConnection._auth_session is None:
            raise RuntimeError("DatabaseConnection.initialize() not called.")
        return DatabaseConnection._auth_session

    # SRP helpers
    @staticmethod
    def update_verifier_and_salt(account, verifier, salt):
        s = DatabaseConnection.auth()
        if hasattr(account, "v") and hasattr(account, "s"):
            if isinstance(verifier, (bytes, bytearray)):
                account.v = bytes(verifier)[::-1].hex().upper()
            else:
                account.v = str(verifier)
            if isinstance(salt, (bytes, bytearray)):
                account.s = bytes(salt)[::-1].hex().upper()
            else:
                account.s = str(salt)
        else:
            account.verifier = verifier
            account.salt = salt
        s.commit()
    
    # ACCOUNT ORM HELPERS
    @staticmethod
    def get_user_by_username(username: str):
        """Fetch Account row by username."""
        return (
            DatabaseConnection.auth()
            .query(Account)
            .filter(Account.username == username)
            .first()
        )

    @staticmethod
    def create_or_update_account(username, salt, verifier, sha_pass_hash=None):
        """
        Create or update account using the ORM Account model.
        Matches the style used by proxies.
        """
        session = DatabaseConnection.auth()

        acc = (
            session.query(Account)
            .filter(Account.username == username)
            .first()
        )

        if acc is None:
            acc = Account(username=username)
            session.add(acc)
            Logger.success(f"[DB] Created account {username}")
        else:
            Logger.success(f"[DB] Updated account {username}")

        if sha_pass_hash and hasattr(acc, "sha_pass_hash"):
            acc.sha_pass_hash = str(sha_pass_hash).upper()

        # Ensure NOT NULL columns get sane defaults for new accounts.
        defaults = {
            "project_member_id": 0,
            "rank": 0,
            "staff_id": 0,
            "activation": "",
            "invited_by": "",
            "inv_friend_acc": "",
            "project_hwid": "",
        }
        for key, value in defaults.items():
            if hasattr(acc, key) and getattr(acc, key) is None:
                setattr(acc, key, value)

        DatabaseConnection.update_verifier_and_salt(acc, verifier, salt)

        return acc.id

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
