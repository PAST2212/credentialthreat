import logging

from aiohttp import ClientResponseError


def log_discovery_error(stage: str, error: Exception) -> None:
    """Log a fixed stage name and error type. HTTP error text can contain a full URL."""
    name = type(error).__name__
    if isinstance(error, ClientResponseError) and error.status:
        logging.warning("%s failed (%s, HTTP %d)", stage, name, error.status)
    else:
        logging.warning("%s failed (%s)", stage, name)
