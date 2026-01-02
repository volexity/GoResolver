"""Implements the business logic of the GoResolver plugin."""

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from .action_modes import ActionModes
from .goresolver_interface import GoResolverInterface
from .plugin_exceptions import ReportDecodeError, UserCancellationError
from .sre_interface import SREInterface

if TYPE_CHECKING:
    from .sre_action import SREAction

logger: logging.Logger = logging.getLogger(f"volexity.goresolver_plugin.{__name__}")


class GoResolverPlugin:
    """Implements the business logic of the GoResolver plugin."""

    def __init__(self, sre: SREInterface) -> None:
        """Initialize a new instance of the GoResolverPlugin.

        Args:
            sre: SREInterface instance to use.
        """
        self._sre: SREInterface = sre

    def start(self) -> None:
        """Execute the plugin."""
        try:
            action: SREAction = self._sre.getAction()
            report_data: str = ""

            match action.mode:
                case ActionModes.ANALYZE:
                    file_path: Path = self._sre.getCurrentFile().resolve()
                    logger.debug(f"file_path = {file_path}")

                    report_data: str = GoResolverInterface.resolve(file_path, action.go_versions)

                    if action.path is not None:
                        with action.path.open("w") as report_file:
                            report_file.write(report_data)

                case ActionModes.IMPORT:
                    if action.path is not None:
                        with action.path.open("r") as report_file:
                            report_data = report_file.read()
                    else:
                        raise ValueError
                case _:
                    raise ValueError

            logger.debug("Importing compare report ...")
            self._sre.importReportData(report_data)
        except FileNotFoundError:
            logger.info("The report you wish to import cannot be found.")
        except ReportDecodeError:
            logger.error("Invalid report file !")
        except UserCancellationError:
            pass
