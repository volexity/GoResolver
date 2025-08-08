"""CLI Arguments data model."""

# Builtins.
import sys

# Installables.
from argparse import ArgumentParser, Namespace

# Builtins.
from pathlib import Path
from typing import Final


class CLIArguments:
    """CLI Arguments data model."""

    def __init__(self, argv: list[str]) -> None:
        """Initialize a new instance of the CLI Arguments data model.

        Args:
            argv: Raw CLI arguments.
        """
        parser: Final[ArgumentParser] = ArgumentParser(prog=Path(argv[0]).name)

        parser.add_argument("sample_path", help="Path to the GO sample to analyze.")
        parser.add_argument("reference_path", nargs="?", help="Path to the GO reference sample to compare to (if any).")
        parser.add_argument(
            "-l", "--libs", metavar="LIBS", nargs="*", help="List of GO libs to include in the generated samples."
        )
        parser.add_argument(
            "-v", "--go-version", metavar="VERSION", help="The GO version to build the reference samples with."
        )
        parser.add_argument("-f", "--force", action="store_true", help="Force build existing samples.")
        parser.add_argument("-s", "--show", action="store_true", help="Show available go versions.")
        parser.add_argument("-r", "--compare-report", help="Path to an already generated GoGrapher report.")
        parser.add_argument("-b", "--backup-path", help="Path where to save the intermediary GoGrapher report.")
        parser.add_argument("-o", "--output", help="Path of the output JSON report.")
        parser.add_argument(
            "-t", "--threshold", type=float, default=0.9, help="Value at which matches are considered significant."
        )
        parser.add_argument("-q", "--quiet", action="store_true", help="Reduce the amount of logs.")
        parser.add_argument("-x", "--extract", action="store_true", help="Extract symbols from the Go sample.")
        parser.add_argument(
            "-g", "--graph", action="store_true", help="Compare the Go sample against generated references."
        )
        parser.add_argument("-y", "--types", action="store_true", help="Parse runtime types from the Go sample.")

        parsed_args: Final[Namespace] = parser.parse_args(argv[1:])

        if len(argv) <= 1:
            parser.print_usage()
            sys.exit()

        self._sample_path: Final[Path] = Path(parsed_args.sample_path).resolve()
        self._reference_path: Final[Path | None] = (
            Path(parsed_args.reference_path).resolve() if parsed_args.reference_path else None
        )

        self._libs: Final[list[str]] = (
            [lib for row in (libs.split(",") for libs in parsed_args.libs) for lib in row] if parsed_args.libs else []
        )

        self._go_versions: Final[list[str]] = [parsed_args.go_version] if parsed_args.go_version is not None else []

        self._force: Final[bool] = parsed_args.force
        self._show: Final[bool] = parsed_args.show

        self._compare_report: Final[Path | None] = (
            Path(parsed_args.compare_report) if parsed_args.compare_report else None
        )
        self._backup_path: Final[Path | None] = Path(parsed_args.backup_path) if parsed_args.backup_path else None

        self._output: Final[Path | None] = Path(parsed_args.output).resolve() if parsed_args.output else None
        self._threshold: Final[float] = parsed_args.threshold
        self._quiet: Final[bool] = parsed_args.quiet

        self._use_extract: Final[bool] = parsed_args.extract or not parsed_args.graph
        self._use_graph: Final[bool] = parsed_args.graph or not parsed_args.extract

        self._parse_types: Final[bool] = parsed_args.types

    @property
    def sample_path(self) -> Path:
        """Returns the path to the GO sample to analyze.

        Returns:
            Path to the GO sample to analyze.
        """
        return self._sample_path

    @property
    def reference_path(self) -> Path | None:
        """Returns the path to the GO reference to analyze (if any).

        Returns:
            Path to the GO reference to analyze (if any).
        """
        return self._reference_path

    @property
    def libs(self) -> list[str]:
        """Returns the list of GO libraries to use.

        Returns:
            The necessary GO libraries.
        """
        return self._libs.copy()

    @property
    def go_versions(self) -> list[str]:
        """Returns the targetted GO version.

        Returns:
            GO versions to build with.
        """
        return self._go_versions.copy()

    @property
    def force(self) -> bool:
        """Return wether samples should be forced built.

        Returns:
            Whether samples should be forced built.
        """
        return self._force

    @property
    def show(self) -> bool:
        """Returns wether to show available GO versions.

        Returns:
            Whether to show available GO versions.
        """
        return self._show

    @property
    def compare_report(self) -> Path | None:
        """Returns the path to an eventual previously generated GoGrapher report.

        Returns:
            Returns the path to an eventual previously generated GoGrapher report.
        """
        return self._compare_report

    @property
    def backup_path(self) -> Path | None:
        """Returns the path where to save the intermediary GoGrapher report.

        Returns:
            Path the the intermediary GoGrapher report save location.
        """
        return self._backup_path

    @property
    def output(self) -> Path | None:
        """Returns the path of the output JSON report.

        Returns:
            The path of the output JSON report.
        """
        return self._output

    @property
    def threshold(self) -> float:
        """Return the value at which matches are considered significant.

        Returns:
            The value at which matches are considered significant.
        """
        return self._threshold

    @property
    def quiet(self) -> bool:
        """Returns whethere to reduce logging.

        Returns:
            Whether to reduce logging.
        """
        return self._quiet

    @property
    def use_extract(self) -> bool:
        """Returns whethere to use the Go symbol extraction algorithm.

        Returns:
            Whether to use the Go symbol extraction algorithm.
        """
        return self._use_extract

    @property
    def use_graph(self) -> bool:
        """Returns whethere to use the Control Flow Graph comparison algorithm.

        Returns:
            Whether to use the Control Flow Graph comparison algorithm.
        """
        return self._use_graph

    @property
    def parse_types(self) -> bool:
        """Returns whether to extract runtime type information.

        Returns:
            Whether to extract runtime type information.
        """
        return self._parse_types
