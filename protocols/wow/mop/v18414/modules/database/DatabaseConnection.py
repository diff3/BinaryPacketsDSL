#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

from utils.ConfigLoader import ConfigLoader
from utils.Logger import Logger

from protocols.wow.mop.v18414.modules.database.AuthModel import Account, AccountAccess, RealmList
from protocols.wow.mop.v18414.modules.database.CharactersModel import Characters


class DatabaseConnection:
    """Handles separate DB connections for auth-db and characters-db."""

    _auth_engine = None
    _auth_session = None

    _char_engine = None
    _char_session = None

    @staticmethod
    def initialize():
        """Initialize BOTH auth and characters DB connections."""
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

        # CHARACTERS DATABASE
        char_url = (
            f"mysql+pymysql://{db['username']}:{db['password']}@"
            f"{db['host']}:{db['port']}/{db['characters_db']}?charset=utf8"
        )
        DatabaseConnection._char_engine = create_engine(char_url, pool_pre_ping=True)
        DatabaseConnection._char_session = scoped_session(
            sessionmaker(bind=DatabaseConnection._char_engine, autoflush=False)
        )

        Logger.info("Database initialized (auth + characters)")

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
    def get_user_by_username(username):
        return DatabaseConnection.auth().query(Account).filter(
            Account.username == username
        ).first()

    @staticmethod
    def get_realmlist():
        return DatabaseConnection.auth().query(RealmList).first()

    @staticmethod
    def get_all_realms():
        return DatabaseConnection.auth().query(RealmList).all()

    # CHARACTER QUERIES
    @staticmethod
    def get_characters_for_account(account_id, realm_id):
        session = DatabaseConnection.chars()
        return session.query(Characters).filter(
            Characters.account == account_id,
            Characters.realm == realm_id
        ).all()

    @staticmethod
    def count_characters_for_account(account_id, realm_id):
        session = DatabaseConnection.chars()
        return session.query(Characters).filter(
            Characters.account == account_id,
            Characters.realm == realm_id
        ).count()

    # SRP helpers
    @staticmethod
    def update_sessionkey(account, key_bytes):
        s = DatabaseConnection.auth()
        account.session_key = key_bytes
        s.commit()

    @staticmethod
    def update_verifier_and_salt(account, verifier, salt):
        s = DatabaseConnection.auth()
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
    def create_or_update_account(username, salt, verifier):
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
            acc = Account(username=username, salt=salt, verifier=verifier)
            session.add(acc)
            Logger.success(f"[DB] Created account {username}")
        else:
            acc.salt = salt
            acc.verifier = verifier
            Logger.success(f"[DB] Updated account {username}")

        session.commit()
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
