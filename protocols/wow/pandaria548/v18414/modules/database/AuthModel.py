#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime

from sqlalchemy import Column, Integer, String, DateTime, Float
from sqlalchemy.dialects.mysql import SMALLINT, TINYINT

from .Base import Base


# -------------------------------------------------------
# ACCOUNT TABLE (pandaria548 auth.account)
# -------------------------------------------------------
class Account(Base):
    __tablename__ = "account"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(32), unique=True, nullable=False)
    battlenet_account = Column(String(32), nullable=False, default="")

    # Simplified SRP6: SHA1(USER:PASS)
    sha_pass_hash = Column(String(40), nullable=False, default="")

    # SRP6 material as hex strings
    sessionkey = Column(String(80), nullable=False, default="")
    v = Column(String(64), nullable=False, default="")
    s = Column(String(64), nullable=False, default="")

    token_key = Column(String(100), nullable=False, default="")
    email = Column(String(255), nullable=False, default="")
    reg_mail = Column(String(255), nullable=False, default="")

    joindate = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_ip = Column(String(30), nullable=False, default="0.0.0.0")
    failed_logins = Column(Integer, nullable=False, default=0)
    locked = Column(TINYINT, nullable=False, default=0)
    last_login = Column(DateTime, nullable=False, default=datetime.utcnow)
    online = Column(TINYINT, nullable=False, default=0)
    expansion = Column(TINYINT, nullable=False, default=4)
    hasBoost = Column(TINYINT, nullable=False, default=0)
    mutetime = Column(Integer, nullable=False, default=0)
    mutereason = Column(String(255), nullable=False, default="")
    muteby = Column(String(255), nullable=False, default="")
    locale = Column(TINYINT, nullable=False, default=0)
    os = Column(String(10), nullable=False, default="Win")
    recruiter = Column(Integer, nullable=False, default=0)
    project_member_id = Column(Integer, nullable=True)
    rank = Column(Integer, nullable=True)
    staff_id = Column(Integer, nullable=True)
    vp = Column(Integer, nullable=False, default=0)
    dp = Column(Integer, nullable=False, default=0)
    isactive = Column(TINYINT, nullable=False, default=0)
    activation = Column(String(255), nullable=True)
    invited_by = Column(String(255), nullable=True)
    inv_friend_acc = Column(String(255), nullable=True)
    rewarded = Column(TINYINT, nullable=False, default=0)
    flags = Column(Integer, nullable=False, default=0)
    gmlevel = Column(Integer, nullable=False, default=0)
    active_realm_id = Column(Integer, nullable=False, default=0)
    online_mute_timer = Column(Integer, nullable=False, default=0)
    active_mute_id = Column(Integer, nullable=False, default=0)
    project_verified = Column(Integer, nullable=False, default=0)
    cash = Column(Integer, nullable=False, default=0)
    project_is_free = Column(TINYINT, nullable=False, default=0)
    project_is_temp = Column(TINYINT, nullable=False, default=0)
    project_unban_count = Column(Integer, nullable=False, default=0)
    project_antierror = Column(Integer, nullable=False, default=0)
    project_attached = Column(Integer, nullable=False, default=0)
    project_passchange = Column(Integer, nullable=False, default=0)
    project_vote_time = Column(Integer, nullable=False, default=0)
    project_hwid = Column(String(255), nullable=True)
    lock_country = Column(String(2), nullable=False, default="00")


# -------------------------------------------------------
# ACCOUNT ACCESS TABLE (gm level)
# -------------------------------------------------------
class AccountAccess(Base):
    __tablename__ = "account_access"

    id = Column(Integer, primary_key=True)
    gmlevel = Column(SMALLINT, nullable=False)
    RealmID = Column(Integer, nullable=False, default=-1, primary_key=True)


# -------------------------------------------------------
# ACCOUNT BANNED TABLE
# -------------------------------------------------------
class AccountBanned(Base):
    __tablename__ = "account_banned"
    __table_args__ = {"comment": "Ban list"}

    id = Column(Integer, primary_key=True)
    bandate = Column(Integer, primary_key=True)
    unbandate = Column(Integer)
    bannedby = Column(String(50))
    banreason = Column(String(255))
    active = Column(SMALLINT)


# -------------------------------------------------------
# REALMLIST TABLE
# -------------------------------------------------------
class RealmList(Base):
    __tablename__ = "realmlist"

    id = Column(Integer, primary_key=True)
    name = Column(String(32))
    address = Column(String(255))
    localAddress = Column(String(255))
    localSubnetMask = Column(String(255))
    port = Column(SMALLINT)

    icon = Column(Integer)
    flag = Column(Integer)
    timezone = Column(Integer)
    allowedSecurityLevel = Column(Integer)

    population = Column(Float)
    gamebuild = Column(Integer)
