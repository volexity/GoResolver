"""Go Function symbol parsing."""

from dataclasses import dataclass
from typing import Final

from .binary_reader import BinaryReader


@dataclass
class Func:
    """Go Function symbol."""

    entry: Final[int] = 0
    name: Final[str] = "unknown"


class FuncData:
    """Go Function data parser."""

    def __init__(self, func_reader: BinaryReader, field_size: int) -> None:
        """Parses new function data from a binary reader.

        Args:
            func_reader: The binary reader to fetch the function data from.
            field_size: The size of variable length fields.
        """
        self.entry: int = func_reader.read_int(field_size)
        self.name_offset: int = func_reader.read_int(4)
        # More fields not useful for this tool...
