from time import localtime, strftime
import sys
import os

__name__ = "LoggerModule"
__author__ = "Lenforiee"
__desc__ = "My module but nerfed from colorama to be bare python."

class Ansi:
    BLACK = 40
    RED = 41
    GREEN = 42
    YELLOW = 43
    BLUE = 44
    MAGENTA = 45
    CYAN = 46
    WHITE = 47

def formatted_date():
    """Returns the current fromatted date in the format."""

    # D/MM/YYYY HH:MM:SS, 04/05/2021 04:20:01
    
    return strftime("%d-%m-%Y %H:%M:%S", localtime())

def log_message(content: str, l_type: str, bg_col: str):
    """Creates the final string and writes it to console.
    
    Args:
        content (str): The main text to be logged to
            console.
        l_type (str): The type of the log that will be
            displayed to the user.
        bl_col (str): The background colour for the
            `l_type`.
    """
        
    # Print to console. Use this as faster ig.
    sys.stdout.write(
        f"\033[37m{bg_col}[{l_type}]\033[49m - "
        f"[{formatted_date()}] {content}\033[39m\n"
    )

def custom_log(message: str, header: str, colour: Ansi):
    """Prints custom log with custom header and colour"""
    return log_message(message, header, f"\033[{colour}m")

def info(message: str):
    return log_message(message, "INFO", "\033[42m")
 
def error(message: str):
    return log_message(message, "ERROR", "\033[41m")

def warning(message: str):
    return log_message(message, "WARNING", "\033[44m")
