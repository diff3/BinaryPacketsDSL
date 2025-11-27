#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from colorama import init, Fore, Style
from datetime import datetime
from enum import Enum, IntEnum

from utils.ConfigLoader import ConfigLoader

config = ConfigLoader.get_config()
init()

class DebugColorLevel(Enum):
    SUCCESS = Fore.GREEN + Style.BRIGHT
    INFO = Fore.BLUE + Style.BRIGHT
    ANTICHEAT = Fore.LIGHTBLUE_EX + Style.BRIGHT
    WARNING = Fore.YELLOW + Style.BRIGHT
    ERROR = Fore.RED + Style.BRIGHT
    DEBUG = Fore.CYAN + Style.BRIGHT
    SCRIPT = Fore.MAGENTA + Style.BRIGHT


class DebugLevel(IntEnum):
    NONE = 0x00
    SUCCESS = 0x01
    INFO = 0x02
    ANTICHEAT = 0x04
    WARNING = 0x08
    ERROR = 0x10
    DEBUG = 0x20
    SCRIPT = 0x40
    ALL = 0xff


class Logger:
    """Unified colored console logger + file logger."""

    @staticmethod
    def _get_logging_mask(levels):
        level_map = {
            'None': DebugLevel.NONE,
            'Success': DebugLevel.SUCCESS,
            'Information': DebugLevel.INFO,
            'Anticheat': DebugLevel.ANTICHEAT,
            'Warning': DebugLevel.WARNING,
            'Error': DebugLevel.ERROR,
            'Debug': DebugLevel.DEBUG,
            'Script': DebugLevel.SCRIPT,
            'All': DebugLevel.ALL
        }

        mask = DebugLevel.NONE
        for level in levels:
            if level in level_map:
                mask |= level_map[level]

        return mask

    @staticmethod
    def _should_log(level: DebugLevel):
        levels = config.get('Logging', {}).get('logging_levels', 'All').split(', ')
        mask = Logger._get_logging_mask(levels)
        return (mask & level) != 0

    @staticmethod
    def _should_log_file(level: DebugLevel):
        levels = config.get('Logging', {}).get('logging_file_leves', 'All').split(', ')
        mask = Logger._get_logging_mask(levels)
        return (mask & level) != 0

    @staticmethod
    def _colorize(label, color, msg):
        date = datetime.now().strftime(config['Logging']['date_format'])
        if label:
            return f"{color.value}{label}{Style.RESET_ALL}{date} {msg}"
        return msg

    @staticmethod
    def add_to_log(msg, level_tag):
        file = config['Logging']['log_file']
        date = datetime.now().strftime(config['Logging']['date_format'])

        if level_tag:
            line = f"[{level_tag}] {date} {msg}"
        else:
            line = msg

        with open(f"logs/{file}", "a", encoding='utf-8', errors='replace') as log:
            log.write(line + "\n")

    @staticmethod
    def reset_log(file=None):
        file = file or config['Logging']['log_file']
        open(f"logs/{file}", "w").close()

    # ===================================================================
    # Console + File logging methods
    # ===================================================================

    @staticmethod
    def debug(msg):
        if Logger._should_log(DebugLevel.DEBUG):
            print(Logger._colorize("[DEBUG]", DebugColorLevel.DEBUG, msg))
        if Logger._should_log_file(DebugLevel.DEBUG):
            Logger.add_to_log(msg, "DEBUG")

    @staticmethod
    def info(msg):
        if Logger._should_log(DebugLevel.INFO):
            print(Logger._colorize("[INFO]", DebugColorLevel.INFO, msg))
        if Logger._should_log_file(DebugLevel.INFO):
            Logger.add_to_log(msg, "INFO")

    @staticmethod
    def warning(msg):
        if Logger._should_log(DebugLevel.WARNING):
            print(Logger._colorize("[WARNING]", DebugColorLevel.WARNING, msg))
        if Logger._should_log_file(DebugLevel.WARNING):
            Logger.add_to_log(msg, "WARNING")

    @staticmethod
    def error(msg):
        if Logger._should_log(DebugLevel.ERROR):
            print(Logger._colorize("[ERROR]", DebugColorLevel.ERROR, msg))
        if Logger._should_log_file(DebugLevel.ERROR):
            Logger.add_to_log(msg, "ERROR")

    @staticmethod
    def success(msg):
        if Logger._should_log(DebugLevel.SUCCESS):
            print(Logger._colorize("[SUCCESS]", DebugColorLevel.SUCCESS, msg))
        if Logger._should_log_file(DebugLevel.SUCCESS):
            Logger.add_to_log(msg, "SUCCESS")

    @staticmethod
    def anticheat(msg):
        if Logger._should_log(DebugLevel.ANTICHEAT):
            print(Logger._colorize("[ANTICHEAT]", DebugColorLevel.ANTICHEAT, msg))
        if Logger._should_log_file(DebugLevel.ANTICHEAT):
            Logger.add_to_log(msg, "ANTICHEAT")

    @staticmethod
    def script(msg):
        if Logger._should_log(DebugLevel.SCRIPT):
            print(Logger._colorize("[SCRIPT]", DebugColorLevel.SCRIPT, msg))
        if Logger._should_log_file(DebugLevel.SCRIPT):
            Logger.add_to_log(msg, "SCRIPT")

    # ===================================================================
    # to_log = FILE ONLY
    # ===================================================================

    @staticmethod
    def to_log(msg):
        """Write ONLY to log file, never print to console."""
        if Logger._should_log_file(DebugLevel.INFO):
            Logger.add_to_log(msg, "")

    # ===================================================================
    # Progress bar
    # ===================================================================

    @staticmethod
    def progress(msg, current, total, divisions=20):
        pct = int(current * 100 / total)
        text = f"{msg} [{current}/{total}] ({pct}%)"

        if current != total and divisions > 0:
            if int(current % (total / divisions)) == 0:
                Logger.info(text)
        else:
            Logger.success(text)