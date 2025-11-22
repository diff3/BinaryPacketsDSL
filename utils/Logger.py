#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from colorama import init, Fore, Style
from datetime import datetime
from enum import Enum, IntEnum

from utils.ConfigLoader import ConfigLoader

config = ConfigLoader.get_config()
   
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
    """
    Simple colored logging utility for standardized terminal output.

    Provides static methods for different log levels (info, debug, warning, error),
    with optional color formatting. Used throughout the system for consistent messaging.
    """
    init()

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
    def _should_log(log_type: DebugLevel):
        levels = config.get('Logging', {}).get('logging_levels', 'All').split(', ')
        logging_mask = Logger._get_logging_mask(levels)
        return logging_mask & log_type

    @staticmethod
    def _should_log_file(log_type: DebugLevel):
        levels = config.get('Logging', {}).get('logging_file_leves', 'All').split(', ')
        logging_mask = Logger._get_logging_mask(levels)
        return logging_mask & log_type

    @staticmethod
    def _colorize_message(label, color, msg):
        date_format = config['Logging']['date_format']
        date = datetime.now().strftime(date_format)
        
        if label:
            return f'{color.value}{label}{Style.RESET_ALL}{date} {msg}'
        
        return f'{msg}'

    @staticmethod
    def add_to_log(msg, debugLevel):
        file = config['Logging']['log_file']
        date_format = config['Logging']['date_format']
        date = datetime.now().strftime(date_format)

        if debugLevel:
            formatted_msg = f'[{debugLevel}] {date} {msg}'
        else:
            formatted_msg = f'{msg}'

        with open(f'logs/{file}', 'a', encoding='utf-8', errors='replace') as log_file:
            log_file.write(formatted_msg + '\n')

    @staticmethod
    def reset_log(file=None):
        if not file:
            file = config['Logging']['log_file']
        open(f'logs/{file}', 'w').close()

    @staticmethod
    def debug(msg):
        if Logger._should_log(DebugLevel.DEBUG):
            print(Logger._colorize_message('[DEBUG]', DebugColorLevel.DEBUG, msg))
        
        if Logger._should_log_file(DebugLevel.DEBUG):
            Logger.add_to_log(msg, 'DEBUG')

    @staticmethod
    def warning(msg):
        if Logger._should_log(DebugLevel.WARNING):
            print(Logger._colorize_message('[WARNING]', DebugColorLevel.WARNING, msg))

        if Logger._should_log_file(DebugLevel.WARNING):
            Logger.add_to_log(msg, 'WARNING')

    @staticmethod
    def error(msg):
        if Logger._should_log(DebugLevel.ERROR):
            print(Logger._colorize_message('[ERROR]', DebugColorLevel.ERROR, msg))

        if Logger._should_log_file(DebugLevel.ERROR):
            Logger.add_to_log(msg, 'ERROR')

    @staticmethod
    def info(msg, end='\n'):
        if Logger._should_log(DebugLevel.INFO):
            print(Logger._colorize_message('[INFO]', DebugColorLevel.INFO, msg), end=end)
            
        if Logger._should_log_file(DebugLevel.INFO):
            Logger.add_to_log(msg, 'INFO')

    @staticmethod
    def to_log(msg):
        if Logger._should_log(DebugLevel.INFO):
            print(Logger._colorize_message('', DebugColorLevel.INFO, msg))
        
        if Logger._should_log_file(DebugLevel.INFO):
            Logger.add_to_log(msg, '')

    def success(msg):
        if Logger._should_log(DebugLevel.SUCCESS):
            print(Logger._colorize_message('[SUCCESS]', DebugColorLevel.SUCCESS, msg))

        if Logger._should_log_file(DebugLevel.SUCCESS):
            Logger.add_to_log(msg, 'SUCCESS')

    @staticmethod
    def anticheat(msg):
        if Logger._should_log(DebugLevel.ANTICHEAT):
            print(Logger._colorize_message('[ANTICHEAT]', DebugColorLevel.ANTICHEAT, msg))

        if Logger._should_log_file(DebugLevel.ANTICHEAT):
            Logger.add_to_log(msg, 'ANTICHEAT')

    @staticmethod
    def script(msg):
        if Logger._should_log(DebugLevel.SCRIPT):
            print(Logger._colorize_message('[SCRIPT]', DebugColorLevel.SCRIPT, msg))
    
        if Logger._should_log_file(DebugLevel.SCRIPT):
            Logger.add_to_log(msg, 'SCRIPT')


    @staticmethod
    def progress(msg, current, total, divisions=20):
        msg = f'{msg} [{current}/{total}] ({int(current * 100 / total)}%)'
        if current != total and divisions > 0:
            if int(current % (total / divisions)) == 0:
                Logger.info(msg, end='\r')
        else:
            Logger.success(msg)
