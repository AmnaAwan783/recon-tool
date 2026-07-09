"""
logger_setup.py
Centralized logging configuration with verbosity levels for the recon tool.
Used by main.py so every module logs through the same configured handler.
"""
import logging
import sys


def setup_logger(verbosity: int = 1) -> logging.Logger:
    """
    Configure and return the root 'recon' logger used across all modules.

    Verbosity levels:
        0 -> WARNING and above only (quiet mode)
        1 -> INFO and above (default)
        2 -> DEBUG and above (verbose / troubleshooting)
    """
    level_map = {
        0: logging.WARNING,
        1: logging.INFO,
        2: logging.DEBUG,
    }
    level = level_map.get(verbosity, logging.INFO)

    logger = logging.getLogger("recon")
    logger.setLevel(level)
    logger.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.propagate = False

    return logger
