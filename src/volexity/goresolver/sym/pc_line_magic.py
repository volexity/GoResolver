"""Defines the magic numbers relating to each PcLineTable versions."""

from enum import IntEnum
from typing import Final

from ..models.go_version import GOVersion
from .endian import Endian


class PcLineMagic(IntEnum):
    """Defines the magic numbers relating to each PcLineTable versions."""

    # TODO: Find better way around moduledata version issue
    GO_1_20 = 0xFFFFFFF1
    GO_1_18 = 0xFFFFFFF0
    GO_1_16 = 0xFFFFFFFA
    GO_1_2 = 0xFFFFFFFB

    @staticmethod
    def check_table_type(bin_data: bytes, offset: int = 0) -> tuple["PcLineMagic", Endian] | None:
        """Returns the PcLineTable type and endianess.

        Args:
            bin_data: The data of the binary.
            offset: The offset at which to check the table type

        Returns:
            The table type and endianess.
        """
        magic_le: Final[tuple[int, Endian]] = (int.from_bytes(bin_data[offset : offset + 6], "little"), Endian.LITTLE)
        magic_be: Final[tuple[int, Endian]] = (int.from_bytes(bin_data[offset : offset + 6], "big"), Endian.BIG)

        for magic, endian in (magic_le, magic_be):
            if magic in PcLineMagic._value2member_map_:
                return (PcLineMagic(magic), endian)
        return None

    @staticmethod
    def from_version(version: GOVersion) -> "PcLineMagic":
        """."""
        if version >= GOVersion("go1.20"):
            return PcLineMagic.GO_1_20
        if version >= GOVersion("go1.18"):
            return PcLineMagic.GO_1_18
        if version >= GOVersion("go1.16"):
            return PcLineMagic.GO_1_16
        if version >= GOVersion("go1.2"):
            return PcLineMagic.GO_1_2
        msg = f"Unsupported Go version {version}"
        raise ValueError(msg)
