"""Load and provide abstract access to the binary across PE, ELF and Mach-O exectuable formats."""

import logging
from collections.abc import Iterable
from enum import Enum, IntFlag, auto
from pathlib import Path
from typing import Final, cast

import lief

from .arch import Arch

logger: Final[logging.Logger] = logging.getLogger(__name__)


class BinaryFormat(Enum):
    """Enumeration of the supported binary formats."""

    PE = auto()
    ELF = auto()
    MACH_O = auto()


class BinarySection:
    """Abstraction of a section withing a Binary."""

    class Flags(IntFlag):
        """Section's access flags."""

        Initialized = auto()
        Read = auto()
        Write = auto()
        Execute = auto()

    def __init__(self, section: lief.Section, bin_format: BinaryFormat) -> None:
        """Initialize a new BinarySection.

        Args:
            section: The underlying section data.
            bin_format: The binary type to parse the section of.
        """
        self._name: Final[str] = str(section.name)
        self._offset: Final[int] = section.offset
        self._size: Final[int] = section.size

        self._flags: BinarySection.Flags = BinarySection.Flags(0)
        match bin_format:
            case BinaryFormat.PE:
                self._parse_pe_section(section)
            case BinaryFormat.ELF:
                self._parse_elf_section(section)
            case BinaryFormat.MACH_O:
                self._parse_macho_section(section)

    def _parse_pe_section(self, section: lief.Section) -> None:
        """Parse a BinarySection from a PE file.

        Args:
            section: The underlying section data.
        """
        pe_section: lief.PE.Section = cast("lief.PE.Section", section)

        for characteristic in pe_section.characteristics_lists:
            match characteristic:
                case lief.PE.Section.CHARACTERISTICS.CNT_INITIALIZED_DATA:
                    self._flags |= BinarySection.Flags.Initialized
                case lief.PE.Section.CHARACTERISTICS.MEM_READ:
                    self._flags |= BinarySection.Flags.Read
                case lief.PE.Section.CHARACTERISTICS.MEM_WRITE:
                    self._flags |= BinarySection.Flags.Write
                case lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE:
                    self._flags |= BinarySection.Flags.Execute
                case _:
                    pass

    def _parse_elf_section(self, section: lief.Section) -> None:
        """Parse a BinarySection from an ELF file.

        Args:
            section: The underlying section data.
        """
        elf_section: lief.ELF.Section = cast("lief.ELF.Section", section)

        for elf_segment in elf_section.segments:
            for flag in elf_segment.flags:
                match flag:
                    case lief.ELF.Segment.FLAGS.R:
                        self._flags |= BinarySection.Flags.Read
                    case lief.ELF.Segment.FLAGS.W:
                        self._flags |= BinarySection.Flags.Write
                    case lief.ELF.Segment.FLAGS.X:
                        self._flags |= BinarySection.Flags.Execute
                    case _:
                        pass

    def _parse_macho_section(self, section: lief.Section) -> None:
        """Parse a BinarySection from a Mach-O file.

        Args:
            section: The underlying section data.
        """
        macho_section: Final[lief.MachO.Section] = cast("lief.MachO.Section", section)
        protection: Final[int] = macho_section.segment.init_protection & macho_section.segment.max_protection

        if protection & int(lief.MachO.SegmentCommand.VM_PROTECTIONS.R):
            self._flags |= BinarySection.Flags.Read
        if protection & int(lief.MachO.SegmentCommand.VM_PROTECTIONS.W):
            self._flags |= BinarySection.Flags.Write
        if protection & int(lief.MachO.SegmentCommand.VM_PROTECTIONS.X):
            self._flags |= BinarySection.Flags.Execute

    @property
    def name(self) -> str:
        """Return the name of the binary section.

        Returns:
            The name of the binary section.
        """
        return self._name

    @property
    def offset(self) -> int:
        """Return the offset of the binary section.

        Returns:
            The offset of the binary section.
        """
        return self._offset

    @property
    def size(self) -> int:
        """Reeturn the size of the binary section.

        Returns:
            The size of the binary section.
        """
        return self._size

    @property
    def flags(self) -> "BinarySection.Flags":
        """Returns the flags of the binary section.

        Returns:
            The flags of the binary section.
        """
        return self._flags


class Binary:
    """Load and provide abstract access to the binary across PE, ELF and Mach-O exectuable formats."""

    def __init__(self, path: Path) -> None:
        """Loads and initialize a new Binary.

        Args:
            path: Path to the binary to initialize.
        """
        try:
            self._path: Final[Path] = path
            with path.open("rb") as file:
                self._bin_data: Final[bytes] = file.read()
                if binary := lief.parse(self._bin_data):
                    self._parsed_binary: Final[lief.Binary] = binary

                    self._format: BinaryFormat
                    match self._parsed_binary.format:
                        case lief.Binary.FORMATS.PE:
                            self._format = BinaryFormat.PE
                        case lief.Binary.FORMATS.ELF:
                            self._format = BinaryFormat.ELF
                        case lief.Binary.FORMATS.MACHO:
                            self._format = BinaryFormat.MACH_O
                        case _:
                            msg = "Unsupported binary format"
                            raise ValueError(msg)  # noqa: TRY301

                    self._arch: Arch
                    match self._parsed_binary.abstract.header.architecture:
                        case lief.Header.ARCHITECTURES.X86_64:
                            self._arch = Arch.AMD64
                        case lief.Header.ARCHITECTURES.X86:
                            self._arch = Arch.X86
                        case lief.Header.ARCHITECTURES.ARM64:
                            self._arch = Arch.ARM64
                        case lief.Header.ARCHITECTURES.ARM:
                            self._arch = Arch.ARM
                        case _:
                            msg = "Unsupported architecture"
                            raise ValueError(msg)  # noqa: TRY301

                    self._sections: list[BinarySection] = [
                        BinarySection(section, self._format) for section in self._parsed_binary.sections
                    ]
                else:
                    msg = "Couln't parse input binary"
                    raise Exception(msg)  # noqa: TRY002,TRY301
        except Exception:
            logger.exception("Uncaught exception")

    @property
    def name(self) -> str:
        """Return the name of the binary.

        Returns:
            The name of the binary.
        """
        return self._path.name

    @property
    def path(self) -> Path:
        """Returns the path to the binary.

        Returns:
            Path to the binary.
        """
        return self._path

    @property
    def data(self) -> bytes:
        """Return the raw byte data of the binary.

        Returns:
            Raw data of the binary.
        """
        return self._bin_data

    @property
    def format(self) -> BinaryFormat:
        """Returns the binary executable format.

        Returns:
            Executable format of the binary.
        """
        return self._format

    @property
    def arch(self) -> Arch:
        """Returns the CPU architecture of the binary.

        Returns:
            The CPU architecture of the binary.
        """
        return self._arch

    @property
    def sections(self) -> Iterable[BinarySection]:
        """Returns the list of BinarySection of the binary.

        Returns:
            The list of BinarySections of the binary.
        """
        return self._sections

    @property
    def base_address(self) -> int:
        """Return the base address of the binary.

        Returns:
            Base address of the binary.
        """
        return self._parsed_binary.imagebase

    def get_address_from_offset(self, offset: int) -> int:
        """Returns the virtual address corresponding to a file offset.

        Args:
            offset: The file offset to translate.

        Returns:
            The translated virtual address.
        """
        virtual_address: Final[int | lief.lief_errors] = self._parsed_binary.offset_to_virtual_address(offset)
        if isinstance(virtual_address, lief.lief_errors):
            msg = "Invalid offset!"
            raise TypeError(msg)

        if self.format == BinaryFormat.PE:  # Resolve RVA for PEs
            return virtual_address + self._parsed_binary.imagebase
        return virtual_address

    def get_offset_from_address(self, address: int) -> int:
        """Get the file offset corresponding to a virtual address.

        Args:
            address: The virtual address to translate.

        Returns:
            The translated file offset
        """
        for section in sorted(self._parsed_binary.sections, key=lambda x: x.virtual_address, reverse=True):
            section_address: int = section.virtual_address
            if self.format == BinaryFormat.PE:  # Resolve RVA for PEs
                section_address += self.base_address

            if address >= section_address:
                return address - section_address + section.offset
        msg = "Invalid address"
        raise ValueError(msg)

    def get_section(self, name: str) -> BinarySection | None:
        """Get the section with the specified name (if any).

        Args:
            name: The name of the section to retrieve.

        Returns:
            The retrieved section (if any).
        """
        return next((section for section in self._sections if section.name == name), None)

    def get_symbol_offset(self, name: str) -> int | None:
        """Get the value of the symbol with the supplied name (if any).

        Args:
            name: The name of the symbol to retrieve.

        Returns:
            The value of the symbol (if any).
        """
        if symbol := self._parsed_binary.get_symbol(name):
            return symbol.value
        return None

    def __len__(self) -> int:
        """Returns the length of the Binary.

        Returns:
            Length of the binary.
        """
        return len(self._bin_data)
