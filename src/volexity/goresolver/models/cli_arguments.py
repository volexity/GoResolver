"""CLI Arguments data model."""

# Builtins.
import sys

# Installables.
from argparse import ArgumentParser, Namespace, _SubParsersAction

# Builtins.
from pathlib import Path
from typing import Final


class CLIArguments:
    """CLI Arguments data model."""

    @staticmethod
    def parse_args(argv: list[str]) -> "CLIArguments":
        """Initialize a new instance of the CLI Arguments data model.

        Args:
            argv: Raw CLI arguments.
        """
        parser: Final[ArgumentParser] = ArgumentParser(prog=Path(argv[0]).name)
        parser.add_argument("-q", "--quiet", action="store_true", help="Reduce the amount of logs.")

        sub_parsers: _SubParsersAction = parser.add_subparsers(title="commands")
        # Parse the resolve arguments.
        CLIResolveArguments.install_parser(sub_parsers)
        # Parse the manage arguments.
        CLIManageArguments.install_parser(sub_parsers)

        parsed_args: Final[Namespace] = parser.parse_args(argv[1:])

        if len(argv) <= 1:
            parser.print_usage()
            sys.exit()

        return parsed_args.args_class(parsed_args)

    def __init__(self, args: Namespace) -> None:
        self._quiet: Final[bool] = args.quiet

    @property
    def quiet(self) -> bool:
        """Returns whethere to reduce logging.

        Returns:
            Whether to reduce logging.
        """
        return self._quiet


class CLIResolveArguments(CLIArguments):
    """CLI Arguments data model for the resolve command."""

    @staticmethod
    def install_parser(sub_parsers: _SubParsersAction) -> None:
        """Add the resolve command's arguments to the provided SubParser.

        Args:
            sub_parsers: Target SubParser.
        """
        resolve_parser: ArgumentParser = sub_parsers.add_parser("resolve", help="Resolve the symbols from a GO binary.")
        resolve_parser.add_argument("sample_path", help="Path to the GO sample to analyze.")
        resolve_parser.add_argument(
            "reference_path", nargs="?", help="Path to the GO reference sample to compare to (if any)."
        )
        resolve_parser.add_argument(
            "-l", "--libs", metavar="LIBS", nargs="*", help="List of GO libs to include in the generated samples."
        )
        resolve_parser.add_argument(
            "-v", "--go-version", metavar="VERSION", help="The GO version to build the reference samples with."
        )
        resolve_parser.add_argument("-f", "--force", action="store_true", help="Force build existing samples.")
        resolve_parser.add_argument("-r", "--compare-report", help="Path to an already generated GoGrapher report.")
        resolve_parser.add_argument("-b", "--backup-path", help="Path where to save the intermediary GoGrapher report.")
        resolve_parser.add_argument("-o", "--output", help="Path of the output JSON report.")
        resolve_parser.add_argument(
            "-t", "--threshold", type=float, default=0.9, help="Value at which matches are considered significant."
        )
        resolve_parser.add_argument("-x", "--extract", action="store_true", help="Extract symbols from the Go sample.")
        resolve_parser.add_argument(
            "-g", "--graph", action="store_true", help="Compare the Go sample against generated references."
        )
        resolve_parser.add_argument(
            "-y", "--types", action="store_true", help="Parse runtime types from the Go sample."
        )
        resolve_parser.set_defaults(args_class=CLIResolveArguments)

    def __init__(self, args: Namespace) -> None:
        super().__init__(args)

        self._sample_path: Final[Path] = Path(args.sample_path).resolve()
        self._reference_path: Final[Path | None] = Path(args.reference_path).resolve() if args.reference_path else None

        self._libs: Final[list[str]] = (
            [lib for row in (libs.split(",") for libs in args.libs) for lib in row] if args.libs else []
        )

        self._go_versions: Final[list[str]] = args.go_version.split(",") if args.go_version is not None else []
        self._force: Final[bool] = args.force

        self._compare_report: Final[Path | None] = Path(args.compare_report) if args.compare_report else None
        self._backup_path: Final[Path | None] = Path(args.backup_path) if args.backup_path else None

        self._output: Final[Path | None] = Path(args.output).resolve() if args.output else None
        self._threshold: Final[float] = args.threshold

        self._use_extract: Final[bool] = args.extract or not args.graph
        self._use_graph: Final[bool] = args.graph or not args.extract

        self._parse_types: Final[bool] = args.types

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


class CLIManageArguments(CLIArguments):
    """CLI Arguments data model for the manage command."""

    @staticmethod
    def install_parser(sub_parsers: _SubParsersAction) -> None:
        """Add the manage command's arguments to the provided SubParser.

        Args:
            sub_parsers: Target SubParser.
        """
        manage_parser: ArgumentParser = sub_parsers.add_parser(
            "manage", help="Manage the available GO version for analysis."
        )
        manage_group = manage_parser.add_mutually_exclusive_group(required=True)
        manage_group.add_argument(
            "--list_available", action="store_true", help="List the GO versions available to install."
        )
        manage_group.add_argument(
            "--list_installed", action="store_true", help="List the currently installed GO versions."
        )
        manage_group.add_argument("-i", "--install", metavar="VERSIONS", help="The list of GO versions to install.")
        manage_group.add_argument("-u", "--uninstall", metavar="VERSIONS", help="The list of GO versions to uninstall.")
        manage_group.set_defaults(args_class=CLIManageArguments)

    def __init__(self, args: Namespace) -> None:
        super().__init__(args)

        self._list_available: bool = args.list_available
        self._list_installed: bool = args.list_installed
        self._install: list[str] = args.install.split(",") if args.install is not None else []
        self._uninstall: list[str] = args.uninstall.split(",") if args.uninstall is not None else []

    @property
    def list_available(self) -> bool:
        """Returns whether to list the available Go versions."""
        return self._list_available

    @property
    def list_installed(self) -> bool:
        """Returns whether to list the installed Go versions."""
        return self._list_installed

    @property
    def install(self) -> list[str]:
        """Returns the list of Go versions to install."""
        return self._install

    @property
    def uninstall(self) -> list[str]:
        """Returns the list of Go versions to uninstall."""
        return self._uninstall
