"""The BinaryReader allows the parsing of binary data in a stream-like fashion."""

from typing import Final

from .arch import Arch
from .binary import Binary
from .cstr import Cstr
from .slice import Slice


class BinaryReader:
    """The BinaryReader allows the parsing of binary data in a stream-like fashion."""

    def __init__(self, binary: Binary | bytes, arch: Arch, offset: int = 0) -> None:
        """Initialize a new BinaryReader.

        Args:
            binary: The data to parse from.
            arch: The current CPU architecture.
            offset: The offset in the data to start from.
        """
        self._data: Final[bytes] = binary if isinstance(binary, bytes) else binary.data
        self._arch: Final[Arch] = arch
        self.offset: int = offset

    @property
    def data(self) -> bytes:
        """Returns the data of the current BinaryReader.

        Returns:
            Byte data of the BinaryReader.
        """
        return self._data

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
        word: Final[int] = self._arch.endian.parse_int(self._data, size, self.offset)
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

    def read_str(self, offset: int | None = None) -> str:
        """Parse a null terminated string.

        Args:
            offset: The absolute offset to parse the string from.

        Returns:
            The parsed string.
        """
        if offset is not None:
            self.offset = offset
        read_str: Final[str] = str(Cstr(self._data[self.offset :]))
        self.offset += len(read_str) + 1
        return read_str

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

    def walk(self, value: int, size: int = 0, offset: int | None = None) -> int | None:
        """Walk the binary searching for the specified value.

        Args:
            value: The value to look for.
            size: The window size to search with
            offset: The absolute offset to start walking from.

        Returns:
            The offset of the found value (if any).
        """
        if offset is not None:
            self.offset = offset
        window_size: int = (value.bit_length() + 7) // 8
        window_size = max(window_size, size)

        for address in range(self.offset, len(self._data) - window_size, self._arch.quantum):
            if value == self._arch.endian.parse_int(self._data, window_size, address):
                self.offset = address
                return address
        self.offset = len(self.data)

        return None
