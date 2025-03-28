"""Integer parsing of different length and endianess."""

from enum import StrEnum, auto


class Endian(StrEnum):
    """Integer parsing of different length and endianess."""

    BIG = auto()
    LITTLE = auto()

    def parse_int(self, data: bytes, size: int, offset: int = 0) -> int:
        """Parse an integer of the current endianess.

        Args:
            data: The data to parse the integer from.
            size: The size of the integer to parse.
            offset: The offset in the data from which to parse the integer.

        Returns:
            The parsed integer.
        """
        match self:
            case Endian.LITTLE:
                return int.from_bytes(data[offset : offset + size], "little")
            case Endian.BIG:
                return int.from_bytes(data[offset : offset + size], "big")

    def as_bytes(self, value: int, size: int = 0) -> bytes:
        """Return the byte reperesentation of the supplied value in the current endianess.

        Args:
            value: The value to convert.
            size: Optionaly the number of bytes to use.

        Returns:
            The byte reperesentation of the supplied value.
        """
        value_size: int = (value.bit_length() + 7) // 8
        value_size = max(value_size, size)

        match self:
            case Endian.LITTLE:
                return value.to_bytes(value_size, "little")
            case Endian.BIG:
                return value.to_bytes(value_size, "big")
