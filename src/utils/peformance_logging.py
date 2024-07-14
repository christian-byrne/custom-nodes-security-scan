import time
from utils.log import Logger
from utils.config import Config

logger = Logger(__name__, Config()["log_level"])()

def report_time_taken(func):
    def wrapper(*args, **kwargs):
        time_start = time.time()
        logger.debug(f"Starting {func.__name__}...")
        result = func(*args, **kwargs)
        time_end = time.time()
        logger.info(f"Finished {func.__name__} in {time_end - time_start:.2f} seconds.")
        return result

    return wrapper
