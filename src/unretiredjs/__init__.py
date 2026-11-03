import logging
from logging import NullHandler
from .retirejs import (
    check,
    is_vulnerable,
    scan,
    scan_endpoint,
    scan_file_content,
    scan_filename,
    scan_uri,
    unique,
)

__version__ = "1.4.15"

__all__ = [
    "check",
    "is_vulnerable",
    "scan",
    "scan_endpoint",
    "scan_file_content",
    "scan_filename",
    "scan_uri",
    "unique",
    "__version__",
]

logging.getLogger(__name__).addHandler(NullHandler())
