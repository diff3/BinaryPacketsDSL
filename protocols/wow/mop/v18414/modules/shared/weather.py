# weather.py
# Weather enums used by SMSG_WEATHER

from enum import IntEnum


class WeatherType(IntEnum):
    FINE = 0
    RAIN = 1
    SNOW = 2
    STORM = 3
    THUNDERSTORM = 4
    BLACKRAIN = 90


def weather_name(weather_id: int) -> str:
    try:
        return WeatherType(weather_id).name
    except ValueError:
        return f"UNKNOWN_WEATHER_{weather_id}"