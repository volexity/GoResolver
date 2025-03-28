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
from common.plugin_exceptions import UserCancellationError
from common.sre_interface import SREInterface
from ghidra.program.model.address import Address  # type: ignore
from ghidra.program.model.listing import Function  # type: ignore
from ghidra.program.model.symbol import SourceType  # type: ignore
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
        from common.goresolver_plugin import GoResolverPlugin

        plugin: Final[GoResolverPlugin] = GoResolverPlugin(SRE)
        plugin.start()
    except Exception as e:
        logger.exception(f"PLUGIN EXCEPTION:\n{e.__class__}: {e}")
    except SystemExit:
        pass


entry()
