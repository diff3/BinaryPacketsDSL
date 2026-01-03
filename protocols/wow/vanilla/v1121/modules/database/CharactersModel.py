# -*- coding: utf-8 -*-

from sqlalchemy import (
    Column, Integer, BigInteger, SmallInteger,
    String, Text, Float
)
from sqlalchemy.dialects.mysql import TINYINT, SMALLINT
from datetime import datetime

from .Base import Base


class Characters(Base):
    __tablename__ = "characters"

    guid = Column(Integer, primary_key=True, autoincrement=False)
    account = Column(Integer, nullable=False)
    name = Column(String(12), nullable=False)

    race = Column(TINYINT, nullable=False, default=0)
    class_ = Column("class", TINYINT, nullable=False, default=0)
    gender = Column(TINYINT, nullable=False, default=0)

    level = Column(TINYINT, nullable=False, default=1)
    xp = Column(Integer, nullable=False, default=0)
    money = Column(BigInteger, nullable=False, default=0)

    playerBytes = Column(Integer, nullable=False, default=0)
    playerBytes2 = Column(Integer, nullable=False, default=0)
    playerFlags = Column(Integer, nullable=False, default=0)

    map = Column(SMALLINT, nullable=False, default=0)
    zone = Column(SMALLINT, nullable=False, default=0)
    position_x = Column(Float, nullable=False, default=0.0)
    position_y = Column(Float, nullable=False, default=0.0)
    position_z = Column(Float, nullable=False, default=0.0)
    orientation = Column(Float, nullable=False, default=0.0)

    health = Column(Integer, nullable=False, default=0)
    power1 = Column(Integer, nullable=False, default=0)
    power2 = Column(Integer, nullable=False, default=0)
    power3 = Column(Integer, nullable=False, default=0)
    power4 = Column(Integer, nullable=False, default=0)
    power5 = Column(Integer, nullable=False, default=0)

    online = Column(TINYINT, nullable=False, default=0)
    cinematic = Column(TINYINT, nullable=False, default=0)

    totaltime = Column(Integer, nullable=False, default=0)
    leveltime = Column(Integer, nullable=False, default=0)
    logout_time = Column(Integer, nullable=False, default=0)
    is_logout_resting = Column(TINYINT, nullable=False, default=0)
    rest_bonus = Column(Float, nullable=False, default=0.0)

    exploredZones = Column(Text)
    equipmentCache = Column(Text)
    knownTitles = Column(Text)

    actionBars = Column(TINYINT, nullable=False, default=0)
    drunk = Column(SMALLINT, nullable=False, default=0)

    latency = Column(Integer, nullable=False, default=0)