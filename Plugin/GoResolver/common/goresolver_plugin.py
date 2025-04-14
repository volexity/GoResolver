"""Implements the business logic of the GoResolver plugin."""

import logging
from pathlib import Path
from typing import Final

from .action_modes import ActionModes
from .plugin_exceptions import ReportDecodeError, UserCancellationError
from .sre_interface import SREInterface

logger: Final[logging.Logger] = logging.getLogger(f"volexity.goresolver_plugin.{__name__}")


VOLEXITY_LIBS_INSTALLED: bool
try:
    raise ImportError  # Analysis feature dissabled. # noqa: TRY301

    from gographer import CompareReport

    from volexity.goresolver.go_compare import GoCompare
    from volexity.gostrap.sample_generator import SampleGenerator

    VOLEXITY_LIBS_INSTALLED = True
except ImportError:
    VOLEXITY_LIBS_INSTALLED = False


class GoResolverPlugin:
    """Implements the business logic of the GoResolver plugin."""

    def __init__(self, sre: SREInterface) -> None:
        """Initialize a new instance of the GoResolverPlugin.

        Args:
            sre: SREInterface instance to use.
        """
        self._sre: Final[SREInterface] = sre

    def start(self) -> None:
        """Execute the plugin."""
        try:
            mode, report_path = self._sre.getAction(
                restrict=[ActionModes.ANALYZE] if not VOLEXITY_LIBS_INSTALLED else None
            )
            report_data: str = ""

            match mode:
                case ActionModes.ANALYZE:
                    if not VOLEXITY_LIBS_INSTALLED:
                        return

                    file_path: Final[Path] = self._sre.getCurrentFile()
                    home_path: Final[Path] = self._sre.getHomeDir()
                    logger.debug(f"file_path = {file_path}")
                    logger.debug(f"home_path = {home_path}")

                    logger.debug("Initializing sample generator ...")
                    generator: Final[SampleGenerator] = SampleGenerator(home_path / "GoResolver_data")

                    logger.debug("Initializing go comparator ...")
                    go_comparator: Final[GoCompare] = GoCompare(generator, file_path)

                    logger.debug("Generating compare report ...")
                    report: Final[CompareReport] = go_comparator.compare()
                    report_data = report.to_json()

                    if report_path is not None:
                        with report_path.open("w") as report_file:
                            report_file.write(report_data)

                case ActionModes.IMPORT:
                    if report_path is not None:
                        with report_path.open("r") as report_file:
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
