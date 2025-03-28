"""Allow the parsing of C-like Null terminated strings."""

from typing import Final


class Cstr:
    """Allow the parsing of C-like Null terminated strings."""

    def __init__(self, bin_data: bytes) -> None:
        """Parses a new C string."""
        str_data: list[str] = []
        for c in bin_data:
            if c == 0:
                break
            str_data.append(chr(c))

        self._string: Final[str] = "".join(str_data)

    def __str__(self) -> str:
        """String representation."""
        return self._string

    def __repr__(self) -> str:
        """Cstr representation."""
        return f'"{self._string}"'
