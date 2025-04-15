"""Parses the BuildInfo of a Go binary."""

# Ref: https://go.dev/src/debug/buildinfo/buildinfo.go
# Ref: https://github.com/golang/go/blob/master/src/cmd/go/internal/modload/build.go

import logging
from collections.abc import Generator, Iterable
from pathlib import Path
from typing import Final

from ..sym.binary import Binary, BinaryFormat, BinarySection
from ..sym.binary_reader import BinaryReader

BUILDINFO_MAGIC: Final[bytes] = b"\xff\x20\x47\x6f\x20\x62\x75\x69\x6c\x64\x69\x6e\x66\x3a"

logger: Final[logging.Logger] = logging.getLogger(__name__)


class BuildInfo:
    """Parses the BuildInfo of a Go binary."""

    def __init__(self, binary: Binary | Path) -> None:
        """Parses a new Go binary.

        Args:
            binary: The binary to parse or its path.

        Returns:
            The BuildInfo of the supplied binary.
        """
        msg: Final[str] = "Unable to parse the binary's BuildInfo !"
        self._version: str
        self._mod: str

        go_binary: Final[Binary] = binary if isinstance(binary, Binary) else Binary(binary)

        data_section_candidates: Generator[BinarySection]
        match go_binary.format:
            case BinaryFormat.PE:
                data_section_candidates = BuildInfo._get_pe_data(go_binary)
            case BinaryFormat.ELF:
                data_section_candidates = BuildInfo._get_elf_data(go_binary)
            case BinaryFormat.MACH_O:
                data_section_candidates = BuildInfo._get_macho_data(go_binary)

        if build_info_reader := BuildInfo._get_build_info_reader(go_binary, data_section_candidates):
            _ptr_size: int = build_info_reader.read_int(1)
            endian_int: int = build_info_reader.read_int(1)
            buildversion_address: int = build_info_reader.read_word()
            modinfo_address: int = build_info_reader.read_word()

            mod_data: bytes
            if endian_int & 0x2:  # >= go1.18
                self._version = build_info_reader.read_bytes(build_info_reader.read_uvarint()).decode()
                mod_data = build_info_reader.read_bytes(build_info_reader.read_uvarint())
            else:  # < go1.18
                self._version = build_info_reader.read_str(go_binary.get_offset_from_address(buildversion_address))
                mod_data = build_info_reader.read_str_data(go_binary.get_offset_from_address(modinfo_address))
            self._mod = BuildInfo._strip_sentinel_strguard(mod_data).decode()
        else:
            raise ValueError(msg)

    @property
    def version(self) -> str:
        """Returns the Go version of the binary."""
        return self._version

    @staticmethod
    def _strip_sentinel_strguard(data: bytes) -> bytes:
        """Remove the sentinel guards on a bytesequence (if any).

        Args:
            data: The data to strip the sentinel guards off

        Returns:
            The stripped byte sequence.
        """
        lf: Final[int] = 0xA
        guard_size: Final[int] = 0x20

        if len(data) > guard_size and data[-0x11] == lf:
            return data[0x10:-0x10]
        return data

    @staticmethod
    def _get_build_info_reader(
        go_binary: Binary, data_section_candidates: Iterable[BinarySection]
    ) -> BinaryReader | None:
        """Localize the BuildInfo of a Go Binary.

        Args:
            go_binary: The Go Binary to localize the BuildInfo for.
            data_section_candidates: The list of possible BuildInfo locations.

        Returns:
            A BinaryReader on the BuildInfo data.
        """
        expected_magic: Final[int] = go_binary.arch.endian.parse_int(BUILDINFO_MAGIC, len(BUILDINFO_MAGIC))
        for candidate in data_section_candidates:
            logger.info(f'Identified data section "{candidate.name}"')

            reader: BinaryReader = BinaryReader(go_binary, go_binary.arch)
            if reader.walk(expected_magic, offset=candidate.offset, walk_size=candidate.size) is not None:
                return reader

            logger.warning(f'No BuildInfo data in section "{candidate.name}" !')
        logger.error("BuildInfo unavailable !")
        return None

    @staticmethod
    def _get_pe_data(binary: Binary) -> Generator[BinarySection]:
        """Get data section candidates for PE binaries.

        Args:
            binary: The binary to get the candidates for.

        Returns:
            The data section candidates.
        """
        if section := binary.get_section(".data"):
            yield section
        data_flags: Final[BinarySection.Flags] = (
            BinarySection.Flags.Initialized | BinarySection.Flags.Read | BinarySection.Flags.Write
        )
        for section in binary.sections:
            if (section.flags & data_flags) == data_flags:
                yield section

    @staticmethod
    def _get_elf_data(binary: Binary) -> Generator[BinarySection]:
        """Get data section candidates for ELF binaries.

        Args:
            binary: The binary to get the candidates for.

        Returns:
            The data section candidates.
        """
        if section := binary.get_section(".go.buildinfo"):
            yield section
        for section in binary.sections:
            if section.flags & BinarySection.Flags.Write:
                yield section

    @staticmethod
    def _get_macho_data(binary: Binary) -> Generator[BinarySection]:
        """Get data section candidates for Mach-O binaries.

        Args:
            binary: The binary to get the candidates for.

        Returns:
            The data section candidates.
        """
        if section := binary.get_section("__go_buildinfo"):
            yield section
        data_flags: Final[BinarySection.Flags] = BinarySection.Flags.Read | BinarySection.Flags.Write
        for section in binary.sections:
            if section.offset and (section.flags & data_flags) == data_flags:
                yield section
