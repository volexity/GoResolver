"""Go-Like slice."""

from dataclasses import dataclass
from typing import Final


@dataclass
class Slice:
    """Go-Like slice."""

    data_address: Final[int] = 0
    length: Final[int] = 0
    capacity: Final[int] = 0
