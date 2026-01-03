#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime

from sqlalchemy import Column, Integer, String, DateTime, Float
from sqlalchemy.dialects.mysql import TINYINT, INTEGER, BIGINT

from .Base import Base


# -------------------------------------------------------
# ACCOUNT TABLE (Vanilla realmd.account)
# -------------------------------------------------------
class Account(Base):
    __tablename__ = "account"

    id = Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True)

    username = Column(String(32), unique=True, nullable=False)

    # Legacy hash column; vMangos SRP6 flow uses salt/verifier instead.
    # sha_pass_hash = Column(String(40), nullable=False, default="")

    # Session + SRP material (hex strings in most schemas)
    sessionkey = Column(String(80), nullable=False, default="")
    v = Column(String(64), nullable=True, default="")
    s = Column(String(64), nullable=True, default="")

    token_key = Column(String(100), nullable=False, default="")
    email = Column(String(255), nullable=True, default="")

    joindate = Column(DateTime, nullable=False, default=datetime.utcnow)

    last_ip = Column(String(30), nullable=False, default="0.0.0.0")
    failed_logins = Column(INTEGER(unsigned=True), nullable=False, default=0)

    locked = Column(TINYINT(unsigned=True), nullable=False, default=0)
    lock_country = Column(String(2), nullable=False, default="00")

    last_login = Column(DateTime, nullable=False, default=datetime.fromtimestamp(0))
    online = Column(TINYINT, nullable=False, default=0)

    expansion = Column(TINYINT(unsigned=True), nullable=False, default=0)

    mutetime = Column(BIGINT, nullable=False, default=0)

    locale = Column(TINYINT(unsigned=True), nullable=False, default=0)

    os = Column(String(4), nullable=False, default="")

# -------------------------------------------------------
# ACCOUNT ACCESS TABLE (GM level)
# -------------------------------------------------------
class AccountAccess(Base):
    __tablename__ = "account_access"

    id = Column(INTEGER(unsigned=True), primary_key=True, nullable=False)
    RealmID = Column(Integer, primary_key=True, nullable=False, default=-1)
    gmlevel = Column(TINYINT(unsigned=True), nullable=False)


# -------------------------------------------------------
# ACCOUNT BANNED TABLE
# -------------------------------------------------------
class AccountBanned(Base):
    __tablename__ = "account_banned"

    banid = Column(BIGINT(unsigned=True), primary_key=True, autoincrement=True)

    id = Column(BIGINT(unsigned=True), nullable=False)
    bandate = Column(BIGINT, nullable=False)
    unbandate = Column(BIGINT, nullable=False)

    bannedby = Column(String(50), nullable=False)
    banreason = Column(String(255), nullable=False)

    active = Column(TINYINT, nullable=False, default=1)

    realm = Column(TINYINT, nullable=False, default=1)
    gmlevel = Column(TINYINT(unsigned=True), nullable=False, default=0)


# -------------------------------------------------------
# REALMLIST TABLE (Vanilla)
# -------------------------------------------------------
class RealmList(Base):
    __tablename__ = "realmlist"

    id = Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True)

    name = Column(String(32), unique=True, nullable=False)

    address = Column(String(32), nullable=False, default="127.0.0.1")
    localAddress = Column(String(255), nullable=False, default="127.0.0.1")
    localSubnetMask = Column(String(255), nullable=False, default="255.255.255.0")

    port = Column(INTEGER, nullable=False, default=8085)

    icon = Column(TINYINT(unsigned=True), nullable=False, default=0)
    realmflags = Column(TINYINT(unsigned=True), nullable=False, default=2)
    timezone = Column(TINYINT(unsigned=True), nullable=False, default=0)

    allowedSecurityLevel = Column(TINYINT(unsigned=True), nullable=False, default=0)

    population = Column(Float(asdecimal=False), nullable=False, default=0.0)

    gamebuild_min = Column(INTEGER(unsigned=True), nullable=False, default=0)
    gamebuild_max = Column(INTEGER(unsigned=True), nullable=False, default=0)

    flag = Column(TINYINT(unsigned=True), nullable=False, default=2)

    realmbuilds = Column(String(64), nullable=False, default="")
