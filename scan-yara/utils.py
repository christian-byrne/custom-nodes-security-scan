import time
from rich import print

def report_time_taken(func):
    def wrapper(*args, **kwargs):
        time_start = time.time()
        print(f"Starting {func.__name__}...")
        result = func(*args, **kwargs)
        time_end = time.time()
        print(f"Finished {func.__name__} in {time_end - time_start:.2f} seconds.")
        return result

    return wrapper
