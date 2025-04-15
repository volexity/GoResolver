"""Parses and represent the PcLineTable cross all majors Go version."""

import logging
from collections.abc import Generator
from typing import Final

from .arch import Arch
from .binary import Binary
from .binary_reader import BinaryReader
from .cstr import Cstr
from .endian import Endian
from .func import Func, FuncData
from .pc_line_magic import PcLineMagic

logger: Final[logging.Logger] = logging.getLogger(__name__)


# Absolutes offsets
QUANTUM_OFFSET: Final[int] = 6
POINTER_SIZE_OFFSET: Final[int] = 7
DATA_BASE_OFFSET: Final[int] = 8


class PcLineTable:
    """Parses and represent the PcLineTable cross all majors Go version."""

    def __init__(self, binary: Binary, table_offset: int, magic: PcLineMagic | None = None) -> None:
        """Parses a new PcLineTable.

        Args:
            binary: The binary data to parse the PcLineTable from.
            table_offset: The offset at which to parse the PcLineTable at.
            magic: Overide the table's magic detection in favor of the supplied value.
        """
        self._offset: Final[int] = table_offset

        tmp_magic: PcLineMagic
        endian: Endian

        if magic is None:
            tmp_magic, endian = self._parse_magic(binary, table_offset)
        else:
            tmp_magic = magic
            endian = binary.arch.endian

        self._arch: Final[Arch] = self._parse_arch(binary, table_offset, endian)

        self.fct_table: Final[dict[int, Func]] = {}
        self.end_pc: int
        match tmp_magic:
            case PcLineMagic.GO_1_2:
                logger.debug("Parsing PcLineTable as ver 1.2!")
                self._parse_v1_2_tables(binary, table_offset)
            case PcLineMagic.GO_1_16:
                logger.debug("Parsing PcLineTable as ver 1.16!")
                self._parse_v1_16_tables(binary, table_offset)
            case PcLineMagic.GO_1_18:
                logger.debug("Parsing PcLineTable as ver 1.18!")
                self._parse_v1_18_tables(binary, table_offset)
            case PcLineMagic.GO_1_20:
                logger.debug("Parsing PcLineTable as ver 1.20!")
                self._parse_v1_18_tables(binary, table_offset)
        self.start_pc: int = min(self.fct_table)
        if self.start_pc >= self.end_pc:
            msg = "Invalid function table ! Invalid start/end pc."
            raise ValueError(msg)

    @property
    def offset(self) -> int:
        """Returns the file offset of the table.

        Returns:
            File offset of the PcLineTable.
        """
        return self._offset

    def _insert_func(self, pc: int, func: Func) -> None:
        """Insert a new symbol into the function table, asserting that they are inserted in ascending order.

        Args:
            pc: The entry point of the function.
            func: The function data.
        """
        try:
            if next(reversed(self.fct_table.keys())) >= pc:
                msg = "Invalid function table ! Not sorted"
                raise ValueError(msg)
        except StopIteration:
            pass
        self.fct_table[pc] = func

    @staticmethod
    def _parse_magic(binary: Binary, offset: int) -> tuple[PcLineMagic, Endian]:
        """Parses the magic of the PcLineTable header and returns the Magic and Endianess.

        Args:
            binary: Binary in which to parse the PcLineTable.
            offset: File offset of the PcLineTable.

        Returns:
            Parsed Magic and Endianess of the PcLineTable header.
        """
        table_type: Final[tuple[PcLineMagic, Endian] | None] = PcLineMagic.check_table_type(binary.data, offset)

        if table_type is None:
            msg = "Invalid Magic!"
            raise ValueError(msg)

        return table_type

    @staticmethod
    def _parse_arch(binary: Binary, offset: int, endian: Endian) -> Arch:
        """Parse the architecture of the PcLineTable.

        Args:
            binary: Binary in which to parse the PcLineTable's architecture.
            offset: File offset of the PcLineTable.
            endian: Endianness of the PcLineTable.

        Returns:
            Parsed architecture from the PcLineTable.
        """
        msg: Final[str] = "Invalid Architecture!"

        try:
            quantum: Final[int] = binary.data[offset + QUANTUM_OFFSET]  # x86: 1, ARM: 4
            pointer_size: Final[int] = binary.data[offset + POINTER_SIZE_OFFSET]  # x86: 4, x86_64: 8
        except IndexError as e:
            logger.debug(f"PCLineTable offset out of range ! {offset:#x}")
            raise ValueError(msg) from e

        if quantum != binary.arch.quantum or pointer_size != binary.arch.pointer_size:
            raise ValueError(msg)

        return Arch(endian, quantum, pointer_size)

    def _parse_v1_2_tables(self, binary: Binary, table_offset: int) -> None:
        """Parses the Go symbol table for Go binaries following the v1.2 format.

        Args:
            binary: PcLineTab binary data to parse.
            table_offset: Offset of the PcLineTable.
        """
        bin_reader: Final[BinaryReader] = BinaryReader(binary, self._arch, table_offset + DATA_BASE_OFFSET)
        fct_table_size: Final[int] = bin_reader.read_word()

        for _ in range(fct_table_size):
            pc: int = bin_reader.read_word()
            func_data_offset: int = bin_reader.read_word()
            func_data: FuncData = FuncData(
                BinaryReader(binary, self._arch, table_offset + func_data_offset), self._arch.pointer_size
            )

            # NOTE: Obfuscators such as Garbe may randomize the Func entry.
            #       This check ensures each func entry stays coherent.
            if func_data.entry != pc:
                func_data.entry = pc

            entry: int = func_data.entry
            name_offset: int = table_offset + func_data.name_offset

            self._insert_func(pc, Func(entry, str(Cstr(binary.data[name_offset:]))))
        self.end_pc = bin_reader.read_word()

    def _parse_v1_16_tables(self, binary: Binary, table_offset: int) -> None:
        """Parses the Go symbol table for Go binaries following the v1.2 format.

        Args:
            binary: PcLineTab binary data to parse.
            table_offset: Offset of the PcLineTable.
        """
        bin_reader: BinaryReader = BinaryReader(binary, self._arch, table_offset + DATA_BASE_OFFSET)
        fct_table_size: Final[int] = bin_reader.read_word()

        _file_table_size: Final[int] = bin_reader.read_word()
        func_name_tab: Final[int] = bin_reader.read_word()  # String blobs of function names
        _cu_tab: Final[int] = bin_reader.read_word()
        _file_tab: Final[int] = bin_reader.read_word()
        _pc_tab: Final[int] = bin_reader.read_word()
        func_tab: Final[int] = bin_reader.read_word()  # List of function pc entrypoints

        bin_reader = BinaryReader(binary, self._arch, table_offset + func_tab)
        for _ in range(fct_table_size):
            pc: int = bin_reader.read_word()
            func_data_offset: int = bin_reader.read_word()
            func_data: FuncData = FuncData(
                BinaryReader(binary, self._arch, table_offset + func_tab + func_data_offset), self._arch.pointer_size
            )

            # NOTE: Obfuscators such as Garbe may randomize the Func entry.
            #       This check ensures each func entry stays coherent.
            if func_data.entry != pc:
                func_data.entry = pc

            entry: int = func_data.entry
            name_offset: int = (table_offset + func_name_tab) + func_data.name_offset

            self._insert_func(pc, Func(entry, str(Cstr(binary.data[name_offset:]))))
        self.end_pc = bin_reader.read_word()

    def _parse_v1_18_tables(self, binary: Binary, table_offset: int) -> None:
        """Parses the Go symbol table for Go binaries following the v1.18 format.

        Args:
            binary: PcLineTab binary data to parse.
            table_offset: Offset of the PcLineTable.
        """
        bin_reader: BinaryReader = BinaryReader(binary, self._arch, table_offset + DATA_BASE_OFFSET)
        fct_table_size: Final[int] = bin_reader.read_word()

        _file_table_size: Final[int] = bin_reader.read_word()
        entry_pc: Final[int] = bin_reader.read_word()
        func_name_tab: Final[int] = bin_reader.read_word()  # String blobs of function names
        _cu_tab: Final[int] = bin_reader.read_word()
        _file_tab: Final[int] = bin_reader.read_word()
        _pc_tab: Final[int] = bin_reader.read_word()
        func_tab: Final[int] = bin_reader.read_word()  # List of function pc entrypoints

        func_tab_field_size: Final[int] = 4
        bin_reader = BinaryReader(binary, self._arch, table_offset + func_tab)
        for _ in range(fct_table_size):
            pc_off: int = bin_reader.read_int(func_tab_field_size)
            pc: int = pc_off + entry_pc

            func_data_offset: int = bin_reader.read_int(func_tab_field_size)

            func_data_reader: BinaryReader = BinaryReader(
                binary, self._arch, table_offset + func_tab + func_data_offset
            )
            func_data: FuncData = FuncData(func_data_reader, func_tab_field_size)

            # NOTE: Obfuscators such as Garbe may randomize the Func entry.
            #       This check ensures each func entry stays coherent.
            if func_data.entry != pc_off:
                func_data.entry = pc_off

            entry: int = func_data.entry + entry_pc
            name_offset: int = (table_offset + func_name_tab) + func_data.name_offset

            self._insert_func(pc, Func(entry, str(Cstr(binary.data[name_offset:]))))
        self.end_pc = bin_reader.read_int(func_tab_field_size) + entry_pc

    @staticmethod
    def localize_walk(binary: Binary, offset: int = 0) -> Generator[int]:
        """Localize the PcLineTable by walking the binary, and returns its offset.

        Args:
            binary: The the binary being analyzed.
            offset: Offset at which to start walking.

        Returns:
            The offset to the PcLineTable.
        """
        window_size: Final[int] = 6
        for pclntab_address in range(offset, len(binary) - window_size):
            if _ := PcLineMagic.check_table_type(binary.data, pclntab_address):
                logger.debug(f"Localized symbol table by walking at address: {pclntab_address:#0x}:unknown")
                yield pclntab_address

    @staticmethod
    def localize_symbol(binary: Binary, start_symbol: str, end_symbol: str) -> int | None:
        """Localize the PcLineTable through the symbols, and returns its contents.

        Args:
            binary: The the binary being analyzed.
            start_symbol: The symbol name marking the start of the pclntab.
            end_symbol: The symbol name marking the end of the pclntab.

        Returns:
            The offset to the PcLineTable.
        """
        if sec_rdata := binary.get_section(".rdata"):  # .rdata in pe only
            # Get symbols
            sym_pclntab: Final[int | None] = binary.get_symbol_offset(start_symbol)
            sym_epclntab: Final[int | None] = binary.get_symbol_offset(end_symbol)

            if sym_pclntab is not None and sym_epclntab is not None:
                # Compute value and size
                pclntab_size: Final[int] = sym_epclntab - sym_pclntab
                pclntab_address: Final[int] = sec_rdata.offset + sym_pclntab

                logger.debug(
                    f"Localized symbol table conventionally at address: {pclntab_address:#0x}:{pclntab_size:#0x}"
                )
                return pclntab_address
        return None
