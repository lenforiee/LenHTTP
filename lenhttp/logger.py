from time import localtime, strftime
from colorama import Fore, Back
import sys
import os

CLEAR_FORE = Fore.RESET
CLEAR_BACK = Back.RESET

__name__ = "LoggerModule"
__author__ = "Lenforiee"

DEBUG = "debug" in sys.argv

# Windows support
# activated only when os name is nt (windows)
if os.name == "nt":
    from ctypes import windll
    windll.kernel32.SetConsoleMode(
        windll.kernel32.GetStdHandle(-11),
        7
    )

def formatted_date():
    """Returns the current fromatted date in the format."""

    # D/MM/YYYY HH:MM:SS, 04/05/2021 04:20:01
    
    return strftime("%d-%m-%Y %H:%M:%S", localtime())

def log_message(content: str, l_type: str, bg_col: Fore):
    """Creates the final string and writes it to console.
    
    Args:
        content (str): The main text to be logged to
            console.
        l_type (str): The type of the log that will be
            displayed to the user.
        bl_col (Fore): The background colour for the
            `l_type`.
    """
        
    # Print to console. Use this as faster ig.
    sys.stdout.write(
        f"{Fore.WHITE}{bg_col}[{l_type}]{CLEAR_BACK} - "
        f"[{formatted_date()}] {content}{CLEAR_FORE}\n"
    )

def debug(message: str):
    if DEBUG:
        return log_message(message, "DEBUG", Back.YELLOW)

def info(message: str):
    return log_message(message, "INFO", Back.GREEN)
 
def error(message: str):
    return log_message(message, "ERROR", Back.RED)

def warning(message: str):
    return log_message(message, "WARNING", Back.BLUE)
