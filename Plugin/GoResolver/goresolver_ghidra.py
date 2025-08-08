## ###
# GoGrapher
##
# GoGrapher plugin for Ghidra
# @category: Examples.Python
# @runtime PyGhidra


import logging
from pathlib import Path
from typing import TYPE_CHECKING, Final, override

from common.action_modes import ActionModes
from common.chan_dirs import ChanDir
from common.plugin_exceptions import UserCancellationError
from common.sre_interface import SREInterface
from common.type_flag import TFlag
from common.type_kind import Kind
from ghidra.program.flatapi import FlatProgramAPI  # type: ignore
from ghidra.program.model.address import Address, AddressFactory  # type: ignore
from ghidra.program.model.data import (
    DataType,
    DataTypeConflictHandler,
    DataTypeManager,
    DWordDataType,
    EnumDataType,
    PointerDataType,
    StructureDataType,
    TypedefDataType,
    UnsignedCharDataType,
    WordDataType,
)  # type: ignore
from ghidra.program.model.listing import Function  # type: ignore
from ghidra.program.model.symbol import ReferenceManager, RefType, SourceType  # type: ignore
from ghidra.util.exception import CancelledException, DuplicateNameException, InvalidInputException  # type: ignore
from java.lang import IllegalArgumentException, String  # type: ignore
from java.util import ArrayList  # type: ignore

if TYPE_CHECKING:
    from ghidra.ghidra_builtins import (  # type: ignore
        askChoice,
        askFile,
        currentProgram,
        getFunctionAt,
        print,
    )


logging.basicConfig()
logger: Final[logging.Logger] = logging.getLogger(f"volexity.goresolver_plugin.{__name__}")
volexity_logger: Final[logging.Logger] = logging.getLogger("volexity")

logging.getLogger("volexity.goresolver_plugin").setLevel(logging.INFO)


class GhidraInterface(SREInterface):
    """GoResolver's Ghidra interface."""

    def __init__(self) -> None:
        """Initialize a new GhidraInterface instance."""
        super().__init__()

    @override
    def initializeGoTypedefs(self, gotypes_address: int) -> dict[str, DataType]:
        """Define all necessary types, enums, and structs for the binary.

        Args:
            gotypes_address: Address of the Go runtime types used for offsets
        """
        # Necessary tools to make custom types inside Ghidra
        address_factory: Final[AddressFactory] = currentProgram.getAddressFactory()
        data_type_manager: Final[DataTypeManager] = currentProgram.getDataTypeManager()
        flat_program_api: Final[FlatProgramAPI] = FlatProgramAPI(currentProgram)
        handler: Final[DataTypeConflictHandler] = DataTypeConflictHandler.DEFAULT_HANDLER

        # Name the toplevel types address
        types_address: Final[Address] = address_factory.getAddress(hex(gotypes_address))
        flat_program_api.createLabel(types_address, "_gotypes", True)  # noqa: FBT003

        # Golang typedefs
        uint8_type: Final[TypedefDataType] = data_type_manager.addDataType(
            TypedefDataType("uint8", UnsignedCharDataType()), handler
        )
        uint16_type: Final[TypedefDataType] = data_type_manager.addDataType(
            TypedefDataType("uint16", WordDataType()), handler
        )
        uint32_type: Final[TypedefDataType] = data_type_manager.addDataType(
            TypedefDataType("uint32", DWordDataType()), handler
        )
        uintptr_type: Final[TypedefDataType] = data_type_manager.addDataType(
            TypedefDataType("uintptr", PointerDataType()), handler
        )
        ptrsize: Final[int] = uintptr_type.getLength()

        # Create a TFlag enum with byte-sized entries
        tflag_enum: EnumDataType = EnumDataType("GOTFLAG", 1)
        for tflag in TFlag:
            tflag_enum.add(tflag.name, tflag.value)
        data_type_manager.addDataType(tflag_enum, handler)

        # Create a TFlag enum with byte-sized entries
        kind_enum: EnumDataType = EnumDataType("GOKIND", 1)
        for kind in Kind:
            kind_enum.add(kind.name, kind.value)
        # Taken out for compliance with IDA Pro bitmasking
        kind_enum.add("DIRECTIFACE", 1 << 5)
        data_type_manager.addDataType(kind_enum, handler)

        # Create a ChanDir enum with uintptr-sized entries
        chandir_enum: EnumDataType = EnumDataType("GOCHANDIR", ptrsize)
        for chan_dir in ChanDir:
            chandir_enum.add(chan_dir.name, chan_dir.value)
        data_type_manager.addDataType(chandir_enum, handler)

        # Issue with dynamic pointer sizes in Ghidra, the constructor defaults
        # the size to 4, it is only resolved to 4/8 after it's been added
        # into the DataTypeManager, this avoids the issue by using ptrsize
        # which I calculated after I added my custom uintptr typedef.
        # The rest can just be auto-sized with -1.
        # Go runtime Type struct definition
        ghidra_struct_dict: dict[str, dict[str, tuple(DataType, int)]] = {
            "GOTYPE": {
                "Size_": (uintptr_type, ptrsize),
                "PtrBytes": (uintptr_type, ptrsize),
                "Hash": (uint32_type, -1),
                "TFlag": (tflag_enum, -1),
                "Align_": (uint8_type, -1),
                "FieldAlign_": (uint8_type, -1),
                "Kind_": (kind_enum, -1),
                "Equal": (uintptr_type, ptrsize),
                "GCData": (uintptr_type, ptrsize),
                "Str": (uint32_type, -1),
                "PtrToThis": (uint32_type, -1),
            },
            "GOARRAY": {
                "Elem": (uintptr_type, ptrsize),
                "Slice": (uintptr_type, ptrsize),
                "Len": (uintptr_type, ptrsize),
            },
            "GOCHAN": {"Elem": (uintptr_type, ptrsize), "Dirs": (chandir_enum, -1)},
            "GOFUNC": {"InCount": (uint16_type, -1), "OutCount": (uint16_type, -1)},
            "GOINTERFACE": {
                "PkgPath": (uintptr_type, ptrsize),
                "IMethods": (uintptr_type, ptrsize),
                "NumIMethods": (uintptr_type, ptrsize),
                "NumIMethodsCap": (uintptr_type, ptrsize),
            },
            "GOMAP": {
                "Key": (uintptr_type, ptrsize),
                "Elem": (uintptr_type, ptrsize),
                "Bucket": (uintptr_type, ptrsize),
                "Hasher": (uintptr_type, ptrsize),
                "KeySize": (uint8_type, -1),
                "ElemSize": (uint8_type, -1),
                "BucketSize": (uint16_type, -1),
                "Flags": (uint32_type, -1),
            },
            "GOPOINTER": {"Elem": (uintptr_type, ptrsize)},
            "GOSLICE": {"Elem": (uintptr_type, ptrsize)},
            "GOSTRUCT": {
                "PkgPath": (uintptr_type, ptrsize),
                "Fields": (uintptr_type, ptrsize),
                "NumFields": (uintptr_type, ptrsize),
                "NumFieldsCap": (uintptr_type, ptrsize),
            },
            "GOPARAMETER": {"Offset": (uintptr_type, ptrsize)},
            "GOIMETHOD": {"Name": (uint32_type, -1), "Typ": (uint32_type, -1)},
            "GOSTRUCTFIELD": {
                "Name": (uintptr_type, ptrsize),
                "Typ": (uintptr_type, ptrsize),
                "Offset": (uintptr_type, ptrsize),
            },
            "GOUNCOMMON": {
                "Name": (uint32_type, -1),
                "Mcount": (uint16_type, -1),
                "Xcount": (uint16_type, -1),
                "Moff": (uint32_type, -1),
                "Unused": (uint32_type, -1),
            },
            "GOUNCOMMONMETHOD": {
                "Name": (uint32_type, -1),
                "Mtyp": (uint32_type, -1),
                "Ifn": (uint32_type, -1),
                "Tfn": (uint32_type, -1),
            },
        }
        # Stash necessary Java class info
        sre_class_dict: dict[str, DataType] = {
            "uintptr": uintptr_type  # to recover ptrsize
        }
        # Make each of the structs in the Ghidra DB
        for struct_name, struct_fields in ghidra_struct_dict.items():
            struct_type: StructureDataType = StructureDataType(struct_name, 0)
            for field_name, (field_type, field_size) in struct_fields.items():
                struct_type.add(field_type, field_size, field_name, None)
            data_type_manager.addDataType(struct_type, handler)
            sre_class_dict[struct_name] = struct_type

        return sre_class_dict

    @override
    def makeType(self, sre_class_dict: dict, type_address: int, type_dict: dict) -> None:
        """Make the Go runtime type (and all associated information) at a specified address.

        Args:
            sre_class_dict: Java class dictionary for Ghidra structures
            type_address: Address of the type to be made
            type_dict: Dictionary associated with all the type information
        """
        allowed_chars_set: set(chr) = set("_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
        filtered_name: str = "".join([c if c in allowed_chars_set else "_" for c in type_dict["Name"]])

        # Class to make all data in the Ghidra database
        flat_program_api: Final[FlatProgramAPI] = FlatProgramAPI(currentProgram)
        address_factory: Final[AddressFactory] = currentProgram.getAddressFactory()

        # Set type name in database to GOTYPE_<type string>
        address: Final[Address] = address_factory.getAddress(hex(type_address))
        flat_program_api.createLabel(address, filtered_name, True)  # noqa: FBT003

        # Rename type string address for readability
        type_str_address: Final[Address] = address_factory.getAddress(type_dict["Str"])
        flat_program_api.createLabel(
            type_str_address,
            "typestr_" + type_dict["Str"][2:],
            True,  # noqa: FBT003
        )
        # Also make the Str field clickable, instead of a 32-bit offset
        ptrsize: Final[int] = sre_class_dict["uintptr"].getLength()
        reference_manager: Final[ReferenceManager] = currentProgram.getReferenceManager()
        str_field_address: Final[Address] = address_factory.getAddress(hex(type_address + 8 + 4 * ptrsize))
        reference_manager.addMemoryReference(
            str_field_address, type_str_address, RefType.DATA, SourceType.USER_DEFINED, 0
        )

        # Make the runtime Type struct in the database
        self.cleanData(address, sre_class_dict["GOTYPE"])
        flat_program_api.createData(address, sre_class_dict["GOTYPE"])

        # If the type kind has extra information, write it here:
        type_kind: Final[str] = "GO" + type_dict["Type Information"]["Kind"]
        extra_address: Final[Address] = address_factory.getAddress(type_dict["Type Information"]["Address"])
        if type_kind in sre_class_dict:
            self.cleanData(extra_address, sre_class_dict[type_kind])
            flat_program_api.createData(extra_address, sre_class_dict[type_kind])

        # Some types like func, interface, and struct have an extra array
        # of data associated with it. This will write it if need be.
        extra_kind: str | None = None
        match type_kind:
            case "GOFUNC":
                extra_kind = "GOPARAMETER"
            case "GOINTERFACE":
                extra_kind = "GOIMETHOD"
            case "GOSTRUCT":
                extra_kind = "GOSTRUCTFIELD"

        # Iterate through the array (if it exists) and make each element
        if extra_kind is not None:
            for address in type_dict["Type Information"]["Extra"]:
                array_address: Final[Address] = address_factory.getAddress(address)
                self.cleanData(array_address, sre_class_dict[extra_kind])
                flat_program_api.createData(array_address, sre_class_dict[extra_kind])

        # Write uncommon data if it exists
        if type_dict["Uncommon Data"]:
            uncommon_address: Final[Address] = address_factory.getAddress(type_dict["Uncommon Data"]["Address"])
            self.cleanData(uncommon_address, sre_class_dict["GOUNCOMMON"])
            flat_program_api.createData(uncommon_address, sre_class_dict["GOUNCOMMON"])
            # Write any methods associated with the uncommon type
            for address in type_dict["Uncommon Data"]["Methods"]:
                method_address: Final[Address] = address_factory.getAddress(address)
                self.cleanData(method_address, sre_class_dict["GOUNCOMMONMETHOD"])
                flat_program_api.createData(method_address, sre_class_dict["GOUNCOMMONMETHOD"])

    def cleanData(self, address: Address, data_type: DataType) -> None:
        """Remove any data defined by Ghidra in the types area.

        Args:
            address: Address of the type to clear space for
            data_type: Type of data we need to clear space for
        """
        # Unfortunately, after autoanalysis Ghidra may create data where type
        # information needs to be stored, and createData() cannot overwrite it
        flat_program_api: Final[FlatProgramAPI] = FlatProgramAPI(currentProgram)

        for i in range(data_type.getLength()):
            new_address: Final[Address] = address.add(i)
            if flat_program_api.getDataAt(new_address) is not None:
                try:
                    flat_program_api.removeDataAt(new_address)
                except Exception:  # noqa: BLE001
                    logger.error("Error cleaning data for types.")

    def getPath(self, title: str, button_text: str, *, default: Path | None = None) -> Path:
        """Prompt the user to open a file.

        Args:
            title: The dialog title.
            button_text: The text displayed on the approve button.
            default: (Optional) Path to use when the user is unable to answer.

        Raise:
            UserCancellationError: If the user cancelled the file dialog

        Returns: The path to the file selected by the user.
        """
        try:
            return Path(str(askFile(title, button_text)))
        except IllegalArgumentException:  # Triggered when in Headless mode
            pass
        except CancelledException:
            pass

        if default is not None:
            return default
        raise UserCancellationError

    def getMode(self, restrict: list[ActionModes] | None = None) -> ActionModes:
        """Prompt the user for the mode of operation.

        Args:
            restrict: Disable the select action modes.

        Returns: Selected mode of operation.
        """
        try:
            title: Final[str] = "Mode selection"
            message: Final[str] = "Please select the mode to use"
            choices: list[str] = (
                ActionModes._member_names_
                if restrict is None
                else ([mode.name for mode in ActionModes._member_map_.values() if mode not in restrict])
            )

            choice: Final[str] = str(
                askChoice(String(title), String(message), ArrayList([String(s) for s in choices]), String(choices[0]))
            )
            return ActionModes[choice]
        except IllegalArgumentException:
            pass
        except CancelledException:
            pass

        raise UserCancellationError

    @override
    def setMethodName(self, method_address: int, method_name: str) -> bool:
        """Set the same of a method at an address.

        Args:
            method_address: Address of the method to rename.
            method_name: New name of the method.

        Return: Status.
        """
        try:
            method_name = method_name.replace(" ", "_")

            addr: Address = currentProgram.getAddressFactory().getAddress(hex(method_address))
            func: Final[Function | None] = getFunctionAt(addr)
            if func is not None:
                func.setName(method_name, SourceType.IMPORTED)
                return True
        except DuplicateNameException:
            pass
        except InvalidInputException as e:
            msg = f"Couldn't set method name ! {e}"
            logger.exception(msg)
        return False

    @override
    def getMethodName(self, method_address: int) -> str | None:
        """Get the same of a method at an address.

        Args:
            method_address: Address of the method's name to retrieve.

        Return: The name of the method if any.
        """
        addr: Address = currentProgram.getAddressFactory().getAddress(hex(method_address))
        func: Final[Function | None] = getFunctionAt(addr)
        if func is not None:
            return func.getName()
        return None

    @override
    def getCurrentFile(self) -> Path:
        """Returns the path of the file opened in the SRE.

        Returns: Path of the file opened in the SRE.
        """
        return Path(str(currentProgram.executablePath)).resolve()

    @override
    def getHomeDir(self) -> Path:
        """Returns the path to the home directory of the SRE.

        Returns: Path to the home directory.
        """
        return (Path.home() / ".ghidra").resolve()

    @override
    def getAction(self, restrict: list[ActionModes] | None = None) -> tuple[ActionModes, Path | None]:
        """Prompt the user for the action mode and report path.

        Args:
            restrict: Disable the select action modes.

        Returns: Action mode and report path.
        """
        mode: Final[ActionModes] = self.getMode(restrict)
        report_path: Path | None = None

        match mode:
            case ActionModes.ANALYZE:
                try:
                    report_path = self.getPath("GoGrapher report save path", "Save")
                except UserCancellationError:
                    pass
            case ActionModes.IMPORT:
                report_path = self.getPath("Import GoGrapher report", "Import")

        return (mode, report_path)

    @override
    def print(self, string: str) -> None:
        """Print a message to the SRE's console.

        Args:
            string: Message to be printed.
        """
        print(string)


from common.sre_stream_handler import SREStreamHandler

SRE: Final[SREInterface] = GhidraInterface()
HANDLER: Final[SREStreamHandler] = SREStreamHandler(SRE)
volexity_logger.handlers.clear()
if not any(map(lambda h: isinstance(h, HANDLER.__class__), volexity_logger.handlers)):
    volexity_logger.addHandler(HANDLER)


def entry() -> None:
    """The entrypoint of the Ghidra plugin."""
    try:
        from common.goresolver_plugin import GoResolverPlugin  # noqa: PLC0415

        plugin: Final[GoResolverPlugin] = GoResolverPlugin(SRE)
        plugin.start()
    except Exception as e:
        logger.exception(f"PLUGIN EXCEPTION:\n{e.__class__}: {e}")
    except SystemExit:
        pass


entry()
