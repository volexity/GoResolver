"""GoResolver's IDA Pro interface."""

import logging
from pathlib import Path
from typing import Final, override

import ida_idaapi  # type: ignore[import-untyped,import-not-found]
import ida_name  # type: ignore[import-untyped,import-not-found]
import idaapi  # type: ignore[import-untyped,import-not-found]
from common.action_modes import ActionModes
from common.plugin_exceptions import UserCancellationError
from common.sre_interface import SREInterface
from ida_config_form import IDAConfigForm

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
            from common.goresolver_plugin import GoResolverPlugin

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
