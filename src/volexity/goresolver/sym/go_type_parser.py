"""Logic to extract RTTI from Go binaries."""

import logging
from typing import TYPE_CHECKING, Final

from .arch import Arch
from .binary import Binary
from .binary_reader import BinaryReader
from .module_data_models.module_data import ModuleData
from .type_flags import TFlag
from .type_kinds import Kind

if TYPE_CHECKING:
    from .slice import Slice

logger: Final[logging.Logger] = logging.getLogger(__name__)


class GoTypeParser:
    """Type parsing class."""

    def __init__(self, binary: Binary, moduledata: ModuleData) -> None:
        """Initialize constants needed to walk the type information.

        Args:
            binary (Binary): The binary we are extracting types from
            moduledata (ModuleData): The moduledata structure guessed from the
                                     binary
        """
        self._binary: Final[Binary] = binary

        # Type offsets
        self._types: Final[int] = moduledata.types
        self._typelinks: Final[Slice] = moduledata.typelinks

        # Store strings and types that have already been visited
        self._names: dict[int, str] = {}
        self._parsed: set[int] = set()

        # Type information dictionary to be imported into IDA Pro/Ghidra
        self._output: dict = {}

        # Separate readers to walk each typelink offset and any associated
        # data or types (helps prevent overwriting global state of readers)
        self._typelink_reader: Final[BinaryReader] = BinaryReader(
            binary, binary.arch, binary.get_offset_from_address(self._typelinks.data_address)
        )
        self._reader: Final[BinaryReader] = BinaryReader(binary, binary.arch)

    def to_dict(self) -> dict:
        """Returns the dictionary of all the runtime type information.

        Returns:
            The dictionary of all the runtime type information.
        """
        return self._output

    def parse_types(self) -> None:
        """Walk all types from typelinks and parse them."""
        # Typelinks is an array of 32 bit offsets from the toplevel types.
        for _i in range(self._typelinks.length):
            type_offset: int = self._typelink_reader.read_int(4)

            self._parse_type(self._types + type_offset)

    def _parse_type(self, address: int) -> None:
        """Parse runtime type and recurse to parse any associated types.

        Type layout is in go/src/cmd/compile/internal/reflectdata/reflect.go
        Here's a brief overview:
        +----------------- 0 -----------------+
        | common data, or the rtype           |
        +----------------- A -----------------+
        | type-specific info, if any. for     |
        | primitive types this will be empty  |
        +----------------- B -----------------+
        | uncommon data, this only exists if  |
        | the type is named or has methods    |
        +----------------- C -----------------+
        | type-specific array, if any. this   |
        | applies to structs, funcs, and      |
        | interfaces, for now.                |
        +----------------- D -----------------+
        | uncommon methods                    |
        +-------------------------------------+
        Specific type definitions are found in go/src/internal/abi/type.go

        Args:
            address (int): Address of runtime type
        """
        # Skip any type we've already visited to prevent infinite recursion
        # Types like ptr have cyclic references to the type they point to
        if address in self._parsed:
            return
        self._parsed.add(address)

        # +----------------- 0 -----------------+
        rtype: dict[str, int] = self._parse_common_type(self._binary.get_offset_from_address(address))

        # +----------------- A -----------------+ (also parses C)
        type_info: dict = {}
        kind: int = rtype["_kind"] & Kind.MASK
        type_info["Kind"] = Kind(kind).name
        extra_address: int = self._reader.offset

        flags: Final[list[TFlag]] = [tf for tf in TFlag if rtype["_tflag"] & tf.value == tf.value]
        uncommon: Final[bool] = TFlag.UNCOMMON in flags
        uncommon_offset: int = self._reader.offset
        if uncommon:
            extra_address += 16

        type_info["Address"] = hex(self._binary.get_address_from_offset(extra_address))
        type_info["Extra"] = None

        # Not all types are included in typelinks, the rest are discovered
        # recursively inside the fields of these types
        match kind:
            case Kind.ARRAY:
                uncommon_offset = self._parse_array_type()
            case Kind.CHAN:
                uncommon_offset = self._parse_chan_type()
            case Kind.FUNC:
                uncommon_offset, type_info["Extra"] = self._parse_func_type(uncommon)
            case Kind.INTERFACE:
                uncommon_offset, type_info["Extra"] = self._parse_interface_type(uncommon)
            case Kind.MAP:
                uncommon_offset = self._parse_map_type()
            case Kind.POINTER:
                uncommon_offset = self._parse_pointer_type()
            case Kind.SLICE:
                uncommon_offset = self._parse_slice_type()
            case Kind.STRUCT:
                uncommon_offset, type_info["Extra"] = self._parse_struct_type(uncommon)
            case _:
                pass

        # +----------------- D -----------------+ (also parses B)
        uncommon_data: dict | None = None
        if uncommon:
            uncommon_data = self._parse_uncommon_type(uncommon_offset)

        # '*' prepended to type name by default, strip if it isn't a pointer
        type_name: str = self._read_name(self._types + rtype["_str"] + 1)[1:]
        if TFlag.EXTRASTAR not in flags:
            type_name = "ptr_" + type_name  # SRE typenames cannot contain '*'

        self._output[hex(address)] = {
            "Name": "GOTYPE_" + type_name + "_" + hex(address),
            "Str": hex(rtype["_str"] + self._types),
            "Type Information": type_info,
            "Uncommon Data": uncommon_data,
        }

    def _parse_common_type(self, offset: int) -> dict[str, int]:
        """Parse the common data (rtype) at an offset.

        Args:
            offset (int): The offset to parse the rtype at.

        Returns:
            The rtype dictionary associated with the type.
        """
        # Definition of rtype: go/src/internal/abi/type.go.
        self._reader.offset = offset
        rtype: dict[str, int] = {}
        rtype["_size"] = self._reader.read_word(offset)
        rtype["_ptrdata"] = self._reader.read_word()
        rtype["_hash"] = self._reader.read_int(4)
        rtype["_tflag"] = self._reader.read_int(1)
        rtype["_align"] = self._reader.read_int(1)
        rtype["_fieldAlign"] = self._reader.read_int(1)
        rtype["_kind"] = self._reader.read_int(1)
        rtype["_equal"] = self._reader.read_word()
        rtype["_gcdata"] = self._reader.read_word()
        rtype["_str"] = self._reader.read_int(4)
        rtype["_ptrToThis"] = self._reader.read_int(4)

        return rtype

    def _parse_uncommon_type(self, offset: int) -> dict:
        """Parse uncommon data of a type, if any.

        Args:
            offset (int): The offset of the uncommon data to parse
        """
        # Stash uncommon data for final output dictionary
        uncommon_data: dict = {}
        uncommon_address: Final[int] = self._binary.get_address_from_offset(offset)
        uncommon_data["Address"] = hex(uncommon_address)
        self._reader.offset = offset

        # See go/src/internal/abi/type.go for UncommonType definition.
        _pkg_path: Final[int] = self._reader.read_int(4)
        _mcount: Final[int] = self._reader.read_int(2)
        _xcount: Final[int] = self._reader.read_int(2)
        _moff: Final[int] = self._reader.read_int(4)
        _unused: Final[int] = self._reader.read_int(4)

        # Stash uncommon method type structs to make in Disassembler
        self._reader.offset = offset + _moff
        method_addrs: list[int] = []
        # method_type_offsets: list[int] = []

        # See go/src/internal/abi/type.go for Method definition.
        for _i in range(_mcount):
            method_addrs.append(self._binary.get_address_from_offset(self._reader.offset))
            _name: int = self._reader.read_int(4)
            _mtyp: int = self._reader.read_int(4)
            _ifn: int = self._reader.read_int(4)
            _tfn: int = self._reader.read_int(4)
            # method_type_offsets.append(_mtyp)

        uncommon_data["Methods"] = list(map(hex, method_addrs))
        return uncommon_data

        # TODO: Issue with Mtyp being written to binary,
        # some are just unusable offsets like 0xffffffff.
        # for method_type_offset in method_type_offsets:
        #     self._parse_type(self._types + method_type_offset)

    def _parse_array_type(self) -> int:
        """Parse array type and recursively parse its fields.

        Returns:
            int: The offset for the Uncommon Type struct
        """
        _elem: Final[int] = self._reader.read_word()
        _slice: Final[int] = self._reader.read_word()
        _len: Final[int] = self._reader.read_word()

        uncommon_offset = self._reader.offset

        self._parse_type(_elem)
        self._parse_type(_slice)

        return uncommon_offset

    def _parse_chan_type(self) -> int:
        """Parse channel type and recursively parse its fields.

        Returns:
            int: The offset for the Uncommon Type struct
        """
        _elem: Final[int] = self._reader.read_word()
        _dirs: Final[int] = self._reader.read_word()

        uncommon_offset = self._reader.offset

        self._parse_type(_elem)

        return uncommon_offset

    def _parse_func_type(self, uncommon: bool) -> tuple[int, list[str]]:
        """Parse function type and recursively parse its fields.

        Args:
            uncommon (bool): Whether this type has uncommon data.

        Returns:
            tuple[int, list[str]]: The offset for the Uncommon Type struct and
            hexadecimal addresses of the func's parameter types.
        """
        _in_count: Final[int] = self._reader.read_int(2)
        # MSB in _out_count is set to 1 if the function is variadic,
        # this clears the variadic bit
        _out_count: Final[int] = self._reader.read_int(2) & 0x7FFF

        # Fix byte alignment for 64-bit systems
        if self._binary.arch in (Arch.AMD64, Arch.ARM64):
            self._reader.read_int(4)

        # Uncommon data is inserted between type and type array, skip it
        uncommon_offset = self._reader.offset
        if uncommon:
            self._reader.offset += 16

        # Extra data for JSON and types to parse
        param_info: list[int] = []
        param_type_addrs: list[int] = []

        for _i in range(_in_count + _out_count):
            param_info.append(self._binary.get_address_from_offset(self._reader.offset))
            _param_type: int = self._reader.read_word()
            param_type_addrs.append(_param_type)

        for param_type_addr in param_type_addrs:
            self._parse_type(param_type_addr)

        return uncommon_offset, list(map(hex, param_info))

    def _parse_interface_type(self, uncommon: bool) -> tuple[int, list[str]]:
        """Parse interface type and recursively parse its fields.

        Args:
            uncommon (bool): Whether this type has uncommon data.

        Returns:
            tuple[int, list[str]]: The offset for the Uncommon Type struct and
            hexadecimal addresses of the func's parameter types.
        """
        _pkg_path: Final[int] = self._reader.read_word()
        _imethods_ptr: Final[int] = self._reader.read_word()
        _num_imethods: Final[int] = self._reader.read_word()
        _num_imethods_cap: Final[int] = self._reader.read_word()

        # Uncommon data is inserted between type and type array, skip it
        uncommon_offset = self._reader.offset
        if uncommon:
            self._reader.offset += 16

        # Extra data for JSON and types to parse
        imethod_info: list[int] = []
        imethod_type_offsets: list[int] = []
        for _i in range(_num_imethods):
            imethod_info.append(self._binary.get_address_from_offset(self._reader.offset))
            _name: int = self._reader.read_int(4)
            _type: int = self._reader.read_int(4)
            imethod_type_offsets.append(_type)

        for imethod_type_offset in imethod_type_offsets:
            self._parse_type(self._types + imethod_type_offset)

        return uncommon_offset, list(map(hex, imethod_info))

    def _parse_map_type(self) -> int:
        """Parse map type and recursively parse its fields.

        Returns:
            int: The offset for the Uncommon Type struct
        """
        # New SwissMap is still in experimental mode, lookout for
        # the update in Go1.25 (go/src/cmd/compile/internal/reflectdata)
        _key: Final[int] = self._reader.read_word()
        _elem: Final[int] = self._reader.read_word()
        _bucket: Final[int] = self._reader.read_word()
        _hasher: Final[int] = self._reader.read_word()
        _key_size: Final[int] = self._reader.read_int(1)
        _value_size: Final[int] = self._reader.read_int(1)
        _bucket_size: Final[int] = self._reader.read_word(2)
        _flags: Final[int] = self._reader.read_word(4)

        uncommon_offset = self._reader.offset

        self._parse_type(_key)
        self._parse_type(_elem)
        self._parse_type(_bucket)

        return uncommon_offset

    def _parse_pointer_type(self) -> int:
        """Parse pointer type and recursively parse its fields.

        Returns:
            int: The offset for the Uncommon Type struct
        """
        _elem: Final[int] = self._reader.read_word()

        uncommon_offset = self._reader.offset

        self._parse_type(_elem)

        return uncommon_offset

    def _parse_slice_type(self) -> int:
        """Parse slice type and recursively parse its fields.

        Returns:
            int: The offset for the Uncommon Type struct
        """
        _elem: Final[int] = self._reader.read_word()

        uncommon_offset = self._reader.offset

        self._parse_type(_elem)

        return uncommon_offset

    def _parse_struct_type(self, uncommon: bool) -> tuple[int, list[str]]:
        """Parse struct type and recursively parse its fields.

        Args: uncommon (bool): Whether this type has uncommon data.

        Returns:
            tuple[int, list[str]]: The offset for the Uncommon Type struct and
            hexadecimal addresses of the func's parameter types.
        """
        _pkg_path: Final[int] = self._reader.read_word()
        _fields_ptr: Final[int] = self._reader.read_word()
        _num_fields: Final[int] = self._reader.read_word()
        _num_fields_cap: Final[int] = self._reader.read_word()

        # Extra data for JSON and types to parse
        field_info: list[int] = []
        field_type_addrs: list[int] = []

        # Uncommon data is inserted between type and type array, skip it
        uncommon_offset = self._reader.offset
        if uncommon:
            self._reader.offset += 16

        for _i in range(_num_fields):
            field_info.append(self._binary.get_address_from_offset(self._reader.offset))
            _name: int = self._reader.read_word()
            _typ: int = self._reader.read_word()
            _offset: int = self._reader.read_word()
            field_type_addrs.append(_typ)

        for field_type_addr in field_type_addrs:
            self._parse_type(field_type_addr)

        return uncommon_offset, list(map(hex, field_info))

    def _read_name(self, address: int) -> str:
        """Read type name at a given address (length may be encoded).

        Args:
            address (int): Address to read the type name at

        Returns:
            str: The string that was read
        """
        if address in self._names:
            return self._names[address]

        """Encoding is found in go/src/encoding/binary/varint.go.
        TODO: Fix varint encoding for Go1.16 and before.
        Previously: go/src/cmd/compile/internal/gc/reflect.go
        l := 1 + 2 + len(name)
        Currently: go/src/cmd/compile/internal/reflectdata/reflect.go
        l := 1 + nameLenLen + len(name)
        """
        size: int = 0
        match self._binary.arch:
            case Arch.AMD64 | Arch.ARM64:
                size = 10

            case Arch.X86 | Arch.ARM:
                size = 5

            # For 16-bit systems, probably useless but oh well
            case _:
                size = 3

        # This decoder is translated from the runtime's encoder in Go
        offset: int = self._binary.get_offset_from_address(address)
        buffer: Final[bytes] = self._reader.read_bytes(size, offset)
        str_len: int = 0
        shift: int = 0
        len_len: int = 0
        for i, byte in enumerate(buffer):
            if byte < 0x80:  # noqa: PLR2004
                if i > 9 or (i == 9 and byte > 1):  # noqa: PLR2004
                    return ""  # error with string encoding
                str_len |= byte << shift
                len_len = i + 1
                break
            str_len |= (byte & 0x7F) << shift
            shift += 7

        # Update offset to the start of the string, then collect the chars
        self._reader.offset = self._binary.get_offset_from_address(address + len_len)
        chr_list: list[int] = [self._reader.read_int(1) for i in range(str_len)]
        str_res: Final[str] = "".join(chr(i) for i in chr_list)

        # Cache the string
        self._names[address] = str_res
        return str_res
