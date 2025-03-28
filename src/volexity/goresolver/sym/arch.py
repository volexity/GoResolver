"""Represents the details of a particular CPU architecture."""

from enum import Enum
from typing import Final

from .endian import Endian


# Could possibly become an Enum of different architectures if needs be.
class Arch(Enum):
    """Represents the details of a particular CPU architecture."""

    X86 = Endian.LITTLE, 1, 4
    AMD64 = Endian.LITTLE, 1, 8
    ARM = Endian.LITTLE, 4, 4
    ARM64 = Endian.LITTLE, 4, 8

    def __init__(self, endian: Endian, quantum: int, pointer_size: int) -> None:
        """Initialize a new architecture.

        Args:
            endian: The endianess of the architecture.
            quantum: The byte allignement of the architecture.
            pointer_size: The word size on the architecture.
        """
        self.endian: Final[Endian] = endian
        self.quantum: Final[int] = quantum
        self.pointer_size: Final[int] = pointer_size
