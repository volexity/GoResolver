"""Logging stream redirecting output to the SRE's native print function."""

import logging
from typing import Final, override

from .sre_interface import SREInterface


class SREStreamHandler(logging.Handler):
    """Logging stream redirecting output to the SRE's native print function."""

    def __init__(self, sre: SREInterface, level: int = 0) -> None:
        """Initialize a new SREStreamHandler instance.

        Args:
            sre: The SREInterface the stream should use.
            level: The stream's log level.
        """
        super().__init__(level)

        self._sre = sre

    @override
    def emit(self, record: logging.LogRecord) -> None:
        """Write a log record to the stream.

        Args:
            record: LogRecord to be written.
        """
        msg: Final[str] = record.getMessage()
        self._sre.print(msg)
