"""Go Symbol Parser."""

# Ref: https://cloud.google.com/blog/topics/threat-intelligence/golang-internals-symbol-recovery/?hl=en
# Ref: https://docs.google.com/document/d/1lyPIbmsYbXnpNj57a261hgOYVpNRcgydurVQIyZOz_o/pub
# Ref: https://www.pnfsoftware.com/blog/analyzing-golang-executables/
# Ref: https://github.com/golang/go/tree/2cb9042dc2d5fdf6013305a077d013dbbfbaac06/src/debug/gosym
# Ref: https://github.com/golang/go/blob/master/src/cmd/link/internal/ld/pcln.go

import logging
from collections.abc import Generator
from pathlib import Path
from typing import Final

from ..buildinfo.go_buildinfo_parser import BuildInfo
from ..models.go_version import GOVersion
from .binary import Binary, BinaryFormat
from .module_data_models.module_data import ModuleData
from .module_data_models.module_data_1_02 import ModuleData1_02
from .module_data_models.module_data_1_16 import ModuleData1_16
from .module_data_models.module_data_1_18 import ModuleData1_18
from .module_data_models.module_data_1_20 import ModuleData1_20
from .pc_line_magic import PcLineMagic
from .pc_line_table import PcLineTable

logger: Final[logging.Logger] = logging.getLogger(__name__)


class GoSymParser:
    """Go Symbol Parser."""

    @staticmethod
    def extract(sample_bin: Path | Binary) -> dict[int, str]:
        """Extract the symbols from a Go binary.

        Args:
            sample_bin: The Go binary to extract the samples from.

        Returns:
            Dictionary of extracted symbols in a (entry -> name) configuration.
        """
        binary: Final[Binary] = sample_bin if isinstance(sample_bin, Binary) else Binary(sample_bin)
        symbols: Final[dict[int, str]] = {}

        if moduledata_table := GoSymParser.extract_moduledata(binary):
            logger.info(
                f"Found valid PcLineTable <-> ModuleData couple at "
                f"{moduledata_table.pclinetable.offset:#0x} <-> {moduledata_table.offset:#0x}."
            )

            pcline_table: PcLineTable = moduledata_table.pclinetable
            for pc, symbol in pcline_table.fct_table.items():
                symbols[pc] = symbol.name

        return symbols

    @staticmethod
    def extract_moduledata(binary: Binary) -> ModuleData | None:
        """Attempts to extract the ModuleData from a binary by rearching for a valid ModuleData <-> PcLineTable couple.

        Args:
            binary: The binary to extract the ModuleData from

        Returns:
            The extracted moduledata (if any).
        """
        # Step1 - Try straightforward aproach.
        logger.info("Searching for a valid PcLineTable <-> ModuleData couple ...")
        potential_pclinetable_offsets: Final[Generator[int]] = GoSymParser._get_pclinetable_offset(binary)
        for pcline_table_offset in potential_pclinetable_offsets:
            logger.info(f"Localized PcLineTable candidate at {pcline_table_offset:#0x} !")
            pclinetable_address: int = binary.get_address_from_offset(pcline_table_offset)

            potential_moduledata_offsets: Generator[int] = ModuleData.localize_walk(
                binary, pclinetable_address, binary.arch
            )
            for moduledata_offset in potential_moduledata_offsets:
                if moduledata := GoSymParser._get_moduledata_table(binary, [moduledata_offset]):
                    return moduledata

            logger.error(f"PcLineTable candidate at {pcline_table_offset:#0x} is invalid !")

        # Step2 - Try the backup approach
        logger.warning("Conventional extraction failed, attempting backup ...")
        if moduledata := GoSymParser._get_moduledata_table(binary, ModuleData.localize_signature(binary)):
            return moduledata

        logger.critical("Unable to find a valid PcLineTable <-> ModuleData couple !")
        return None

    @staticmethod
    def _get_magic_from_buildinfo(binary: Binary) -> PcLineMagic | None:
        """Attempts to extract the Go version from the binary's build info (if available).

        Args:
            binary: The binary from which to extract the Go version.

        Returns:
            The extracted Go version magic.
        """
        try:
            build_info: Final[BuildInfo] = BuildInfo(binary)
            version: Final[GOVersion] = GOVersion(build_info.version)
            return PcLineMagic.from_version(version)
        except ValueError:
            return None

    @staticmethod
    def _get_magic_from_fragments() -> PcLineMagic | None:
        """Attempts to extract the Go version from version fragments in the binary (if available).

        Args:
            binary: The binary from which to extract the Go version.

        Returns:
            The extracted Go version magic.
        """
        raise NotImplementedError  # TODO: Implement me!

    @staticmethod
    def _get_moduledata_table(binary: Binary, probable_moduledata_offsets: list[int]) -> ModuleData | None:
        """Attempts to parse the ModuleData form the supplied binary.

        Args:
            binary: The binary to parse the ModuleData from.
            probable_moduledata_offsets: The list of probable locations of the ModuleData in the binary.

        Returns:
            The parsed ModuleData (if successful).
        """
        magic: Final[PcLineMagic | None] = GoSymParser._get_magic_from_buildinfo(binary)

        offsets_attempts: Final[list[int]] = []
        # TODO: We should really UNIQ the offsets to prevent useless processing of the multiple same invalid moduledata
        for moduledata_offset in probable_moduledata_offsets:
            if moduledata_offset not in offsets_attempts:
                offsets_attempts.append(moduledata_offset)
                logger.info(f"Localized ModuleData candidate at {moduledata_offset:#0x} !")

                if magic is not None:
                    try:
                        return GoSymParser._init_moduledata_table(binary, moduledata_offset, magic)
                    except ValueError:
                        pass
                logger.warning("Invalid moduledata version ! Attempting recovery ...")
                for magic in PcLineMagic:
                    logger.debug(f"Attempt to parse ModuleData with magic {magic.name} !")
                    try:
                        return GoSymParser._init_moduledata_table(binary, moduledata_offset, magic)
                    except ValueError:
                        continue
                logger.error(f"ModuleData candidate at {moduledata_offset:#0x} is invalid !")
        return None

    @staticmethod
    def _init_moduledata_table(binary: Binary, offset: int, magic: PcLineMagic) -> ModuleData:
        """Initialize the ModuleData corresponding to the supplied Go version.

        Args:
            binary: Binary to initialize the ModuleData from.
            offset: The offset of the ModuleData.
            magic: The Go version of the binary.

        Raise:
            ValueError: In cases of invalid magic or ModuleData.

        Returns:
            The parsed ModuleData.
        """
        match magic:
            case PcLineMagic.GO_1_2:
                return ModuleData1_02(binary, offset)
            case PcLineMagic.GO_1_16:
                return ModuleData1_16(binary, offset)
            case PcLineMagic.GO_1_18:
                return ModuleData1_18(binary, offset)
            case PcLineMagic.GO_1_20:
                return ModuleData1_20(binary, offset)
            case _:
                msg = "Invalid magic!"
                raise ValueError(msg)

    @staticmethod
    def _get_pclinetable_offset(binary: Binary) -> Generator[int]:
        """Attempts to localize the PcLineTable offset.

        Args:
            binary: The binary to get the PcLineTable offset from.

        Returns:
            The localized PcLineTable offset (if successful).
        """
        potential_table_offsets: Generator[int] | None = None
        match binary.format:
            case BinaryFormat.PE:
                logger.debug("Parsing PE file ...")
                potential_table_offsets = GoSymParser._loc_pe_table(binary)
            case BinaryFormat.ELF:
                logger.debug("Parsing ELF file ...")
                potential_table_offsets = GoSymParser._loc_elf_table(binary)
            case BinaryFormat.MACH_O:
                logger.debug("Parsing MACH-O file ...")
                potential_table_offsets = GoSymParser._loc_macho_table(binary)
            case _:
                msg = "Unsupported binary type!"
                raise ValueError(msg)

        if potential_table_offsets is not None:
            yield from potential_table_offsets

    @staticmethod
    def _loc_pe_table(binary: Binary) -> Generator[int]:
        """Localize the PcLineTable in a PE file.

        Args:
            binary: The binary being analyzed.

        Returns:
            The offset to the PcLineTable.
        """
        logger.debug("Attempt _locTableSym")
        if table_offset := PcLineTable.localize_symbol(binary, "runtime.pclntab", "runtime.epclntab"):
            yield table_offset
        if rdata := binary.get_section(".rdata"):
            logger.debug("Attempt _locTableWalk .rdata")
            yield from PcLineTable.localize_walk(binary, rdata.offset)
        if data := binary.get_section(".data"):
            logger.debug("Attempt _locTableWalk .data")
            yield from PcLineTable.localize_walk(binary, data.offset)
        logger.debug("Attempt _locTableWalk large")
        yield from PcLineTable.localize_walk(binary)

    @staticmethod
    def _loc_elf_table(binary: Binary) -> Generator[int]:
        """Localize the PcLineTable in a ELF file.

        Args:
            binary: The the binary being analyzed.

        Returns:
            The offset to the PcLineTable.
        """
        if pclntab_sec := binary.get_section(".gopclntab"):
            yield pclntab_sec.offset
        yield from PcLineTable.localize_walk(binary)

    @staticmethod
    def _loc_macho_table(binary: Binary) -> Generator[int]:
        """Localize the PcLineTable in a Mach-O file.

        Args:
            binary: The the binary being analyzed.

        Returns:
            The offset to the PcLineTable.
        """
        if pclntab_sec := binary.get_section("__gopclntab"):
            yield pclntab_sec.offset
        yield from PcLineTable.localize_walk(binary)
