"""Custom exception types."""

from typing import Final


class UserCancellationError(Exception):
    """Exception generated whenever the user cancel a task or diaglog."""

    def __init__(self, message: str = "") -> None:
        """Initialize a new UserCancellationError instance.

        Args:
            message: The exception's error message.
        """
        super().__init__()
        self.message: Final[str] = message

    def __str__(self) -> str:
        """Returns the exception's error message.

        Returns: The exception's error message.
        """
        return self.message


class ReportDecodeError(Exception):
    """Exception gerated whenever the plugin isn't able to parse a GoResolver report."""

    def __init__(self, message: str = "") -> None:
        """Initialize a new ReportDecodeError instance.

        Args:
            message: The exception's error message.
        """
        super().__init__()
        self.message: Final[str] = message

    def __str__(self) -> str:
        """Returns the exception's error message.

        Returns: The exception's error message.
        """
        return self.message
