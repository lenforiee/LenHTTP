from datetime import datetime
import time

__author__ = "RealistikDash"

## CLASSES ##

class Timer:
    """A simple timer class for timing things."""

    def __init__(self):
        """Initialises timer for use."""

        self.start_time = 0
        self.end_time = 0

    def start(self) -> None:
        """Begins the timer."""

        self.start_time = time.time()

    def end(self) -> float:
        """Ends the timer and returns final time."""

        self.end_time = time.time()
        return self.end_time - self.start_time

    def get_difference(self) -> float:
        """Returns the difference between start and end."""

        return self.end_time - self.start_time

    def reset(self) -> None:
        """Resets the timer."""

        self.end_time = 0
        self.start_time = 0

    def ms_return(self) -> float:
        """Returns difference in 2dp ms."""

        return round((self.end_time - self.start_time) * 1000, 2)
    
    def time_str(self) -> str:

        return time_str(self)

def time_str(timer: Timer) -> str:
    """If time is in ms, returns ms value. Else returns rounded seconds value.
    Params:
        - timer: Timer = Timer class
    Returns:
        String of calculated time, eg 15ms, 2s.
    """

    time = timer.end()
    if time < 1:
        time_str = f"{timer.ms_return()}ms"
    else:
        time_str = f"{round(time,2)}s"
    return time_str
