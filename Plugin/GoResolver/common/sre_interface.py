"""SRE base class defining actions to be realised across all SRE tools."""

import json
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Final

from .action_modes import ActionModes
from .plugin_exceptions import ReportDecodeError

logger: Final[logging.Logger] = logging.getLogger(f"volexity.goresolver_plugin.{__name__}")


class SREInterface(ABC):
    """SRE base class defining actions to be realised across all SRE tools."""

    @abstractmethod
    def initializeGoTypedefs(self, gotypes_address: int) -> dict:
        """Define all necessary types, enums, and structs for the binary.

        Args:
            gotypes_address: Address of the Go runtime types used for offsets

        Returns:
            dict: SRE-specific type class dictionary
        """

    @abstractmethod
    def makeType(self, sre_class_dict: dict, address: int, name: str) -> None:
        """Make the Go runtime type at a specified address.

        Args:
            sre_class_dict: SRE-specific type class dictionary
            address: Address of the type to be made
            name: Name of the type to be made
        """

    @abstractmethod
    def setMethodName(self, method_address: int, method_name: str) -> bool:
        """Set the same of a method at an address.

        Args:
            method_address: Address of the method to rename.
            method_name: New name of the method.

        Return: Status.
        """

    @abstractmethod
    def getMethodName(self, method_address: int) -> str | None:
        """Get the same of a method at an address.

        Args:
            method_address: Address of the method's name to retrieve.

        Return: The name of the method if any.
        """

    @abstractmethod
    def getCurrentFile(self) -> Path:
        """Returns the path of the file opened in the SRE.

        Returns: Path of the file opened in the SRE.
        """

    @abstractmethod
    def getHomeDir(self) -> Path:
        """Returns the path to the home directory of the SRE.

        Returns: Path to the home directory.
        """

    @abstractmethod
    def getAction(self, *, restrict: list[ActionModes] | None = None) -> tuple[ActionModes, Path | None]:
        """Prompt the user for the action mode and report path.

        Args:
            restrict: Disable the select action modes.

        Returns: Action mode and report path.
        """

    @abstractmethod
    def print(self, string: str) -> None:
        """Print a message to the SRE's console.

        Args:
            string: Message to be printed
        """

    def importReportData(self, report_data: str) -> None:
        """Import a serialized GoResolver report into Ghidra's DB.

        Args:
            report_data: The serialized GoResolver report data.

        Raise:
            ReportDecodeError: When the supplied report file can't be decoded properly.
        """
        try:
            report: dict = json.loads(report_data)
            logger.debug(f'Importing report for "{report["Sample"]["Name"]}"')
            for entry, symbol in report["Symbols"].items():
                symbol_name: str = symbol["Name"]
                address: int = int(entry, 16)
                old_symbol_name: str = self.getMethodName(address) or ""
                if self.setMethodName(address, symbol_name):
                    logger.debug(f'Renamed "{old_symbol_name}" to "{symbol_name}" at {address:#0x}')

            # If the GoResolver report extracted types, make them
            gotypes_address: str | None = report["GoTypes Address"]
            if gotypes_address:
                gotypes_address: int = int(gotypes_address, 16)

                # Stash C++ constructor for the Type struct
                sre_class_dict: dict[str, str] = self.initializeGoTypedefs(gotypes_address)

                for type_address, type_dict in report["Types"].items():
                    int_type_address = int(type_address, 16)
                    self.makeType(sre_class_dict, int_type_address, type_dict)

        except json.JSONDecodeError:
            raise ReportDecodeError
