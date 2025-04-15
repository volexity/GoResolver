"""The BinaryReader allows the parsing of binary data in a stream-like fashion."""

from typing import Final

from .arch import Arch
from .binary import Binary
from .cstr import Cstr
from .slice import Slice


class BinaryReader:
    """The BinaryReader allows the parsing of binary data in a stream-like fashion."""

    def __init__(self, binary: Binary, arch: Arch, offset: int | None = None) -> None:
        """Initialize a new BinaryReader.

        Args:
            binary: The data to parse from.
            arch: The current CPU architecture.
            offset: The offset in the data to start from.
        """
        self._binary: Final[Binary] = binary
        self._arch: Final[Arch] = arch
        self.offset: int = offset if offset is not None else 0

    @property
    def data(self) -> bytes:
        """Returns the data of the current BinaryReader.

        Returns:
            Byte data of the BinaryReader.
        """
        return self._binary.data

    def skip(self, offset: int) -> None:
        """Skip in the data of the specified offset.

        Args:
            offset: The offset to skip in the data by.
        """
        self.offset += offset

    def read_int(self, size: int, offset: int | None = None) -> int:
        """Parse an integer of the specified size.

        Args:
            size: The size of the integer to parse.
            offset: The absolute offset to parse the integer from.

        Returns:
            The parsed integer.
        """
        if offset is not None:
            self.offset = offset
        word: Final[int] = self._arch.endian.parse_int(self._binary.data, size, self.offset)
        self.offset += size
        return word

    def read_word(self, offset: int | None = None) -> int:
        """Parse an integer of the current architecture word's size.

        Args:
            offset: The absolute offset to parse the integer from.

        Returns:
            The parsed integer.
        """
        return self.read_int(self._arch.pointer_size, offset=offset)

    def read_cstr(self, offset: int | None = None) -> str:
        """Parse a null terminated string.

        Args:
            offset: The absolute offset to parse the string from.

        Returns:
            The parsed string.
        """
        if offset is not None:
            self.offset = offset
        read_str: Final[str] = str(Cstr(self._binary.data[self.offset :]))
        self.offset += len(read_str) + 1
        return read_str

    def read_str_data(self, offset: int | None = None) -> bytes:
        """Parse a Go string's byte data.

        Args:
            offset: The absolute offset to parse the string from.

        Returns:
            The parsed string.
        """
        if offset is not None:
            self.offset = offset
        data_address: Final[int] = self.read_word()
        length: Final[int] = self.read_word()

        return self.read_bytes(length, offset=self._binary.get_offset_from_address(data_address))

    def read_str(self, offset: int | None = None) -> str:
        """Parse a Go string.

        Args:
            offset: The absolute offset to parse the string from.

        Returns:
            The parsed string.
        """
        return self.read_str_data(offset=offset).decode()

    def read_slice(self, offset: int | None = None) -> Slice:
        """Reads a Go-Like slice from the stream.

        Args:
            offset: The absolute offset to parse the slice from.

        Returns:
            The parsed Slice.
        """
        if offset is not None:
            self.offset = offset
        data_address: Final[int] = self.read_word()
        length: Final[int] = self.read_word()
        capacity: Final[int] = self.read_word()

        return Slice(data_address, length, capacity)

    def read_uvarint(self, offset: int | None = None) -> int:
        """Read a unsigned varint encoded integer.

        Args:
            offset: The absolute offset to parse the varint from.

        Returns:
            The parsed integer.
        """
        if offset is not None:
            self.offset = offset

        length = 0x0
        uint_value: int = 0x0
        while True:
            current_byte = self.read_int(0x1)
            uint_value |= (current_byte & 0x7F) << length
            length += 0x7
            if not current_byte >> 0x7:
                break
        return uint_value

    def read_varint(self, offset: int | None = None) -> int:
        """Read a signed varint encoded integer.

        Args:
            offset: The absolute offset to parse the varint from.

        Returns:
            The parsed integer.
        """
        value = self.read_uvarint(offset=offset)
        signed_value = value >> 1
        if value & 0x1:
            return ~signed_value
        return signed_value

    def read_bytes(self, size: int, offset: int | None = None) -> bytes:
        """Read a byte sequence of the specified size.

        Args:
            size: The size of the byte sequence to read.
            offset: The absolute offset to read from.

        Returns:
            The read byte sequence.
        """
        if offset is not None:
            self.offset = offset
        sequence: Final[bytes] = self._binary.data[self.offset : self.offset + size]
        self.offset += size
        return sequence

    def walk(self, value: int, size: int = 0, offset: int | None = None, walk_size: int | None = None) -> int | None:
        """Walk the binary searching for the specified value.

        Args:
            value: The value to look for.
            size: The window size to search with
            offset: The absolute offset to start walking from.
            walk_size: The max amount of data to walk.

        Returns:
            The offset of the found value (if any).
        """
        if offset is not None:
            self.offset = offset
        end_offset: Final[int] = self.offset + walk_size if walk_size is not None else len(self._binary.data)

        window_size: int = (value.bit_length() + 7) // 8
        window_size = max(window_size, size)

        for address in range(self.offset, end_offset - window_size, self._arch.quantum):
            if value == self._arch.endian.parse_int(self._binary.data, window_size, address):
                self.offset = address + window_size
                return address
        self.offset = len(self.data)

        return None
