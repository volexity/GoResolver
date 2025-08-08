"""GoResolver's IDA Pro interface."""

import logging
from pathlib import Path
from typing import Final, override

import ida_idaapi  # type: ignore[import-untyped,import-not-found]
import ida_name  # type: ignore[import-untyped,import-not-found]
import ida_typeinf  # type: ignore[import-untyped,import-not-found]
import idaapi  # type: ignore[import-untyped,import-not-found]
from common.action_modes import ActionModes
from common.chan_dirs import ChanDir
from common.plugin_exceptions import UserCancellationError
from common.sre_interface import SREInterface
from common.type_flag import TFlag
from common.type_kind import Kind
from ida_config_form import IDAConfigForm
from ida_typeinf import tinfo_t

logging.basicConfig()
logger: Final[logging.Logger] = logging.getLogger(f"volexity.goresolver_plugin.{__name__}")
volexity_logger: Final[logging.Logger] = logging.getLogger("volexity")

logging.getLogger("volexity.goresolver_plugin").setLevel(logging.INFO)


class IDAInterface(SREInterface):
    """GoResolver's IDA Pro interface."""

    def __init__(self) -> None:
        """Initialize a new IDAInterface instace."""
        super().__init__()

    @override
    def initializeGoTypedefs(self, gotypes_address: int) -> dict:
        """Define all necessary types, enums, and structs for the binary.

        Args:
            gotypes_address: Address of the Go runtime types used for offsets
        """
        # Name the toplevel types address
        ida_name.set_name(gotypes_address, "_gotypes")

        # Golang typedefs, void* will work nicely with 32/64 bit binaries
        typedefs_map: Final[dict[str, str]] = {
            "unsigned __int32": "uint32",
            "unsigned __int16": "uint16",
            "unsigned __int8": "uint8",
            "void*": "uintptr",
        }
        for cpp_type, go_type in typedefs_map.items():
            ida_typeinf.idc_parse_types(f"typedef {cpp_type} {go_type};", ida_typeinf.HTI_PAKDEF | ida_typeinf.HTI_DCL)

        # Stash dynamic pointer size after type def for enum width later
        ptrsize: Final[int] = ida_typeinf.calc_type_size(None, bytes("uintptr", "utf-8"))

        # Create TFlag enum as a bitmask enum to collect all type flags
        tflag_tif: tinfo_t = ida_typeinf.tinfo_t()
        if tflag_tif.create_enum(ida_typeinf.BTF_BYTE):
            tflag_tif.set_enum_is_bitmask(ida_typeinf.tinfo_t.ENUMBM_ON)
            tflag_tif.set_named_type(None, "GOTFLAG")
        for tflag in TFlag:
            tflag_tif.add_edm(tflag.name, tflag.value)

        # Create Kind enum as a bitmask enum to collect all kinds
        kind_tif: tinfo_t = ida_typeinf.tinfo_t()
        if kind_tif.create_enum(ida_typeinf.BTF_BYTE):
            kind_tif.set_enum_is_bitmask(ida_typeinf.tinfo_t.ENUMBM_ON)
            kind_tif.set_named_type(None, "GOKIND")
        kind_tif.add_edm("KINDMASK", (1 << 5) - 1)  # = 0x1f
        for kind in Kind:
            kind_tif.add_edm(kind.name, kind.value, 0x1F)
        kind_tif.add_edm("DIRECTIFACE", 1 << 5, 0x20)  # mask cannot ruin 0x1f

        # Create ChanDir enum, FIXME: investigate how to get ptrsize for this
        chandir_tif: tinfo_t = ida_typeinf.tinfo_t()
        if chandir_tif.create_enum(ida_typeinf.BTF_BYTE):
            chandir_tif.set_enum_width(ptrsize)
            chandir_tif.set_enum_is_bitmask(ida_typeinf.tinfo_t.ENUMBM_OFF)
            chandir_tif.set_named_type(None, "GOCHANDIR")
        for chan_dir in ChanDir:
            chandir_tif.add_edm(chan_dir.name, chan_dir.value)

        # This is ugly, but good luck finding a better way from the API
        # Without using old idc calls, I haven't found a way to get __offset
        ida_struct_dict: dict[str, str] = {
            "GOTYPE": f"""struct GOTYPE {{
                              uintptr Size_;
                              uintptr PtrBytes;
                              uint32 Hash;
                              GOTFLAG TFlag;
                              uint8 Align_;
                              uint8 FieldAlign_;
                              GOKIND Kind_;
                              uintptr Equal __offset(NOZEROES);
                              uintptr GCData __offset(NOZEROES);
                              uint32 Str __offset(OFF32|NOZEROES|NOONES, {hex(gotypes_address)});
                              uint32 PtrToThis __offset(OFF32|NOZEROES, {hex(gotypes_address)});
                          }}""",
            "GOARRAY": """struct GOARRAY {
                              uintptr Elem __offset(NOZEROES);
                              uintptr Slice __offset(NOZEROES);
                              uintptr Len;
                          }""",
            "GOCHAN": """struct GOCHAN {
                             uintptr Elem __offset(NOZEROES);
                             GOCHANDIR Dirs;
                         }""",
            "GOFUNC": """struct GOFUNC {
                            uint16 InCount;
                            uint16 OutCount;
                         }""",
            "GOINTERFACE": """struct GOINTERFACE {
                                  uintptr PkgPath __offset(NOZEROES);
                                  uintptr IMethods __offset(NOZEROES);
                                  uintptr NumIMethods;
                                  uintptr NumIMethodsCap;
                              }""",
            "GOMAP": """struct GOMAP {
                            uintptr Key __offset(NOZEROES);
                            uintptr Elem __offset(NOZEROES);
                            uintptr Bucket __offset(NOZEROES);
                            uintptr Hasher __offset(NOZEROES);
                            uint8 KeySize;
                            uint8 ElemSize;
                            uint16 BucketSize;
                            uint32 Flags;
                        }""",
            "GOPOINTER": """struct GOPOINTER {
                                uintptr Elem __offset(NOZEROES);
                            }""",
            "GOSLICE": """struct GOSLICE {
                              uintptr Elem __offset(NOZEROES);
                          }""",
            "GOSTRUCT": """struct GOSTRUCT {
                               uintptr PkgPath __offset(NOZEROES);
                               uintptr Fields __offset(NOZEROES);
                               uintptr NumFields;
                               uintptr NumFieldsCap;
                           }""",
            "GOPARAMETER": """struct GOPARAMETER {
                                  uintptr Offset __offset(NOZEROES);
                          }""",
            "GOIMETHOD": f"""struct GOIMETHOD {{
                                uint32 Name __offset(OFF32|NOZEROES, {hex(gotypes_address)});
                                uint32 Typ __offset(OFF32|NOZEROES, {hex(gotypes_address)});
                             }}""",
            "GOSTRUCTFIELD": """struct GOSTRUCTFIELD {
                                    uintptr Name __offset(NOZEROES);
                                    uintptr Typ __offset(NOZEROES);
                                    uintptr Offset;
                                }""",
            "GOUNCOMMON": f"""struct GOUNCOMMON {{
                                 uint32 Name __offset(OFF32|NOZEROES, {hex(gotypes_address)});
                                 uint16 Mcount;
                                 uint16 Xcount;
                                 uint32 Moff;
                                 uint32 Unused;
                              }}""",
            "GOUNCOMMONMETHOD": f"""struct GOUNCOMMONMETHOD {{
                                        uint32 Name __offset(OFF32|NOZEROES, {hex(gotypes_address)});
                                        uint32 Mtyp __offset(OFF32|NOZEROES, {hex(gotypes_address)});
                                        uint32 Ifn __offset(OFF32|NOZEROES, {hex(gotypes_address)});
                                        uint32 Tfn __offset(OFF32|NOZEROES, {hex(gotypes_address)});
                                    }}""",
        }
        # Stash necessary C++ tinfo_t class information
        sre_class_dict: dict = {}
        # Make each of the structs in the IDB
        for struct_name, struct_str in ida_struct_dict.items():
            struct_tif = ida_typeinf.tinfo_t(struct_str)
            struct_tif.set_named_type(None, struct_name)
            sre_class_dict[struct_name] = struct_tif

        # Return class info to make structs in the disassembly
        return sre_class_dict

    @override
    def makeType(self, sre_class_dict: dict, type_address: int, type_dict: dict) -> None:
        """Make the Go runtime type (and all associated information) at a specified address.

        Args:
            sre_class_dict: C++ class dictionary for IDA Pro structures
            type_address: Address of the type to be made
            type_dict: Dictionary associated with all the type information
        """
        # Set type name in database to GOTYPE_<type string>
        ida_name.set_name(type_address, type_dict["Name"])

        # Rename type string address for readability, strip hex prefix
        type_str_address: Final[int] = int(type_dict["Str"], 16)
        ida_name.set_name(type_str_address, "typestr_" + type_dict["Str"][2:])

        # Make the runtime Type struct in the database
        ida_typeinf.apply_tinfo(type_address, sre_class_dict["GOTYPE"], ida_typeinf.TINFO_DEFINITE)

        # If the type kind has extra information, write it here:
        type_kind = "GO" + type_dict["Type Information"]["Kind"]
        extra_address = int(type_dict["Type Information"]["Address"], 16)
        if type_kind in sre_class_dict:
            ida_typeinf.apply_tinfo(extra_address, sre_class_dict[type_kind], ida_typeinf.TINFO_DEFINITE)

        # Some types like func, interface, and struct have an extra array
        # of data associated with it. This will write it if need be.
        extra_kind = None
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
                array_address = int(address, 16)
                ida_typeinf.apply_tinfo(array_address, sre_class_dict[extra_kind], ida_typeinf.TINFO_DEFINITE)

        # Write uncommon data if it exists
        if type_dict["Uncommon Data"]:
            uncommon_address = int(type_dict["Uncommon Data"]["Address"], 16)
            ida_typeinf.apply_tinfo(uncommon_address, sre_class_dict["GOUNCOMMON"], ida_typeinf.TINFO_DEFINITE)
            # Write any methods associated with the uncommon type
            for address in type_dict["Uncommon Data"]["Methods"]:
                method_address = int(address, 16)
                ida_typeinf.apply_tinfo(method_address, sre_class_dict["GOUNCOMMONMETHOD"], ida_typeinf.TINFO_DEFINITE)

    @override
    def setMethodName(self, method_address: int, method_name: str) -> bool:
        """Set the same of a method at an address.

        Args:
            method_address: Address of the method to rename.
            method_name: New name of the method.

        Return: Status.
        """
        return ida_name.set_name(
            method_address, method_name, flags=ida_name.SN_NOCHECK | ida_name.SN_FORCE | ida_name.SN_NOWARN
        )

    @override
    def getMethodName(self, method_address: int) -> str | None:
        """Get the same of a method at an address.

        Args:
            method_address: Address of the method's name to retrieve.

        Return: The name of the method if any.
        """
        return ida_name.get_name(method_address)

    @override
    def getCurrentFile(self) -> Path:
        """Returns the path of the file opened in the SRE.

        Returns: Path of the file opened in the SRE.
        """
        return Path(idaapi.get_input_file_path()).resolve()

    @override
    def getHomeDir(self) -> Path:
        """Returns the path to the home directory of the SRE.

        Returns: Path to the home directory.
        """
        return Path(idaapi.get_user_idadir()) / "GoResolver_data"

    @override
    def getAction(self, restrict: list[ActionModes] | None = None) -> tuple[ActionModes, Path | None]:
        """Prompt the user for the action mode and report path.

        Args:
            restrict: Disable the select action modes.

        Returns: Action mode and report path.
        """
        form: Final[IDAConfigForm] = IDAConfigForm(restrict=restrict)
        if form.show():
            mode: Final[ActionModes] = form.mode
            report_path: Final[Path | None] = form.report_path

            return (mode, report_path)
        raise UserCancellationError

    @override
    def print(self, string: str) -> None:
        """Print a message to the SRE's console.

        Args:
            string: Message to be printed
        """
        print(string)


from common.sre_stream_handler import SREStreamHandler

SRE: Final[SREInterface] = IDAInterface()
HANDLER: Final[SREStreamHandler] = SREStreamHandler(SRE)
volexity_logger.handlers.clear()
if not any(map(lambda h: isinstance(h, HANDLER.__class__), volexity_logger.handlers)):
    volexity_logger.addHandler(HANDLER)


class GoResolverPlugmod(ida_idaapi.plugmod_t):
    """GoResolver IDA Pro plugin's module class."""

    def __init__(self) -> None:
        """Initialize a new GoResolverPlugmod instance."""
        super().__init__()
        print(">>>GoResolverPlugin: Init called.")

    def __del__(self) -> None:
        """Free a GoResolverPlugmod instance."""
        print(">>> GoResolverPlugmod: destructor called.")

    def run(self, arg) -> None:
        """Run the plugin's business logic.

        Args:
            arg: Eventual arguments.
        """
        try:
            from common.goresolver_plugin import GoResolverPlugin  # noqa: PLC0415

            plugin: Final[GoResolverPlugin] = GoResolverPlugin(SRE)
            plugin.start()
        except Exception as e:
            logger.exception(f"PLUGIN EXCEPTION:\n{e.__class__}: {e}")
        except SystemExit:
            pass


class GoResolverPlugin(ida_idaapi.plugin_t):
    """GoResolver IDA Pro plugin's registration class."""

    flags = ida_idaapi.PLUGIN_UNL | ida_idaapi.PLUGIN_MULTI
    comment = "GoResolver plugin for IDA Pro"
    help = "This plugin imports GoResolver reports in the current database"
    wanted_name = "GoResolver"
    wanted_hotkey = "Shift-G"

    def init(self) -> ida_idaapi.plugmod_t:
        """Initialize a new GoResolverPlugmod instance."""
        return GoResolverPlugmod()


def PLUGIN_ENTRY() -> ida_idaapi.plugin_t:
    """The entrypoint of the IDA Pro plugin."""
    return GoResolverPlugin()
