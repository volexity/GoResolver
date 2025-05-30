"""Go v1.2+ ModuleData."""

from typing import TYPE_CHECKING, Final, override

from ..binary import Binary
from ..binary_reader import BinaryReader
from ..pc_line_magic import PcLineMagic
from .module_data import ModuleData

if TYPE_CHECKING:
    from ..slice import Slice


class ModuleData1_02(ModuleData):  # noqa: N801
    """ModuleData class for Go v1.2 and UP."""

    def __init__(self, binary: Binary, offset: int) -> None:
        """Initialise the ModuleData for Go v1.2 and UP.

        Args:
            binary: The binary to initalize the ModuleData from.
            offset: The file offset of the ModuleData.
            magic: The Go version of the binary.
        """
        super().__init__(binary, offset, PcLineMagic.GO_1_2)

    @override
    def _parse(self, reader: BinaryReader) -> None:
        """Parse the ModuleData of the corresponding version.

        Args:
            reader: Byte stream a the start of the ModuleData.
        """
        pclinetable_slice: Final[Slice] = reader.read_slice()
        self.pclinetable_address: int = pclinetable_slice.data_address

        _ftab: Final[Slice] = reader.read_slice()
        _filetab: Final[Slice] = reader.read_slice()

        _findfunctab: Final[int] = reader.read_word()

        self.minpc: int = reader.read_word()
        self.maxpc: int = reader.read_word()

        self.text: int = reader.read_word()
        self.etext: int = reader.read_word()

        _noptrdata: Final[int] = reader.read_word()
        _enoptrdata: Final[int] = reader.read_word()

        _data: Final[int] = reader.read_word()
        _edata: Final[int] = reader.read_word()

        _bss: Final[int] = reader.read_word()
        _ebss: Final[int] = reader.read_word()

        _noptrbss: Final[int] = reader.read_word()
        _enoptrbss: Final[int] = reader.read_word()

        _end: Final[int] = reader.read_word()
        _gcdata: Final[int] = reader.read_word()
        _gcbss: Final[int] = reader.read_word()

        _types: Final[int] = reader.read_word()
        _etypes: Final[int] = reader.read_word()

        _textsectmap: Final[Slice] = reader.read_slice()
        self.typelinks: Slice = reader.read_slice()
        _itablinks: Final[Slice] = reader.read_slice()
        _ptab: Final[Slice] = reader.read_slice()
        _pluginpath: Final[Slice] = reader.read_slice()  # String
        _pkghashes: Final[Slice] = reader.read_slice()
        self.modulename: Slice = reader.read_slice()  # String
        self.modulehashes: Slice = reader.read_slice()

        self.hasmain: bool = reader.read_int(1) != 0

        _gcdatamask: None = None  # bitvector
        _gcbssmask: None = None  # bitvector
        _typemap: None = None  # map

        self.bad: bool = reader.read_int(1) != 0
