from rich.logging import RichHandler
import logging

def setup_logger(name: str) -> logging.Logger:
    logging.basicConfig(
        level="INFO",
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler()]
    )
    return logging.getLogger(name)