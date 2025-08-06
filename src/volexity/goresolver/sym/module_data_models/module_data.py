"""Module data base class."""

import logging
from abc import ABC, abstractmethod
from collections.abc import Generator
from typing import Final

from ..arch import Arch
from ..binary import Binary
from ..binary_reader import BinaryReader
from ..pc_line_table import PcLineMagic, PcLineTable
from ..signature import Signature
from ..slice import Slice

logger: Final[logging.Logger] = logging.getLogger(__name__)


# TODO: Issues with older go samples -> Rewrite at a later date
MANDIANT_AMD64_SIG: Final[Signature] = Signature("{ 48 8D 0? ?? ?? ?? ?? E? ?? 48 8? 8? ?? 02 00 00 }")
MANDIANT_X86_SIG: Final[Signature] = Signature(
    "{ 8D ?? ?? ?? ?? ?? EB ?? [0-50] 8B ?? ?? 01 00 00 8B ?? ?? ?? 85 ?? 75 ?? }"
)
MANDIANT_ARM64_SIG: Final[Signature] = Signature(
    "{ ?? ?? ?? (90 | b0 | f0 | d0) ?? ?? ?? 91 ?? ?? ?? (14 | 17) ?? ?? 41 F9 ?? ?? ?? B4 }"
)
MANDIANT_ARM_SIG: Final[Signature] = Signature("{ ?? ?? 9F E5 ?? ?? ?? EA ?? ?? ?? E5 ?? ?? ?? E3 ?? ?? ?? 0A }")

SIGNATURES: Final[dict[Arch, Signature]] = {
    Arch.AMD64: MANDIANT_AMD64_SIG,
    Arch.X86: MANDIANT_X86_SIG,
    Arch.ARM64: MANDIANT_ARM64_SIG,
    Arch.ARM: MANDIANT_ARM_SIG,
}


class ModuleData(ABC):
    """Module data base class."""

    def __init__(self, binary: Binary, offset: int, magic: PcLineMagic) -> None:
        """Initialize the ModuleData from the offset in the binary.

        Args:
            binary: The binary to initalize the ModuleData from.
            offset: The file offset of the ModuleData.
            magic: The Go version of the binary.
        """
        reader: Final[BinaryReader] = BinaryReader(binary, binary.arch, offset)
        self._offset: Final[int] = offset
        self._magic: Final[PcLineMagic] = magic

        # Common properties
        self.pclinetable_address: int = 0
        self.minpc: int = 0
        self.maxpc: int = 0
        self.text: int = 0
        self.etext: int = 0
        self.types: int = 0
        self.typelinks: Slice = Slice()
        self.modulename: Slice = Slice()  # String
        self.modulehashes: Slice = Slice()
        self.hasmain: bool = False
        self.bad: bool = False

        # Parse table data
        self._parse(reader)
        self.next: Final[int] = reader.read_word()

        pclinetable_offset: Final[int] = binary.get_offset_from_address(self.pclinetable_address)
        self.pclinetable: PcLineTable

        try:
            self.pclinetable = PcLineTable(binary, pclinetable_offset)
        except ValueError:
            self.pclinetable = PcLineTable(binary, pclinetable_offset, self._magic)
        self._verify()

    @property
    def offset(self) -> int:
        """Returns the file offset of the ModuleData.

        Returns:
            File offset of the ModuleData.
        """
        return self._offset

    @abstractmethod
    def _parse(self, reader: BinaryReader) -> None:
        """Parse the ModuleData of the corresponding version.

        Args:
            reader: Byte stream a the start of the ModuleData.
        """

    def _verify(self) -> None:
        """Verify that the parsed PcLineTable is coherent with this ModuleData."""
        if self.pclinetable.start_pc != self.minpc:
            msg = "ModuleData: Minimum program counter invalid."
            raise ValueError(msg)
        if self.pclinetable.end_pc != self.maxpc:
            msg = "ModuleData: Maximum program counter invalid."
            raise ValueError(msg)

    @staticmethod
    def localize_walk(
        binary: Binary, pclinetable_address: int, arch: Arch, offset: int | None = None
    ) -> Generator[int]:
        """Localize ModuleData by walking the binary (if successful).

        Args:
            binary: The binary to localize the ModuleData in.
            pclinetable_address: The virtual address of the PcLineTable.
            arch: The architecture of the binary.
            offset: The starting file offset for the walk.

        Returns:
            The ModuleData file offset (if any).
        """
        reader: Final[BinaryReader] = BinaryReader(binary, arch, offset)

        while True:
            if moduledata_offset := reader.walk(pclinetable_address, arch.pointer_size):
                logger.debug(f"ModuleData found at offset: {moduledata_offset:#0x}")
                yield moduledata_offset
            else:
                return

    @staticmethod
    def localize_signature(binary: Binary) -> list[int]:
        """Localize ModuleData by checking its signature.

        Args:
            binary: The binary to localize the ModuleData in.

        Returns:
            The list of probable file offsets.
        """
        matches: list[tuple[int, bytes]] = SIGNATURES[binary.arch].match(binary.data)
        probable_offsets: list[int] = []
        for file_offset, match in matches:
            extracted_offset: int = int.from_bytes(match[3:6], "little")  # TODO: Should match the architecture
            instruction_length: int = 0x7
            instruction_virtual_address: int = binary.get_address_from_offset(file_offset)

            localized_address: int = instruction_virtual_address + extracted_offset + instruction_length
            localized_offset: int = binary.get_offset_from_address(localized_address)
            logger.debug(f"match: {file_offset:#0x}, {match.hex()} -> {localized_address:#0x}:{localized_offset:#0x}")
            probable_offsets.append(localized_offset)

        return probable_offsets
