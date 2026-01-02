"""Implements the GoGrapher-py command line interface."""

import contextlib
import logging
import sys
from logging import INFO, Logger, basicConfig, getLogger
from pathlib import Path
from typing import TYPE_CHECKING, Final

import multiprocess  # type: ignore[import-untyped]
from gographer import CompareReport, UnsupportedBinaryFormat
from pygments import highlight  # type: ignore[reportUnknownVariableType]
from pygments.formatters import TerminalFormatter
from pygments.lexers.web import JsonLexer  # type: ignore[reportMissingTypeStubs]
from volexity.gostrap.sample_generator import SampleGenerator

from .go_compare import GoCompare
from .models.cli_arguments import CLIArguments, CLIManageArguments, CLIResolveArguments
from .models.symbol_report import SymbolReport
from .models.symbol_source import SymbolSource
from .models.symbol_tree import SymbolTree
from .sym.binary import Binary
from .sym.go_sym_parser import GoSymParser
from .sym.go_type_parser import GoTypeParser

if TYPE_CHECKING:
    from .sym.module_data_models.module_data import ModuleData

# Spawns fresh interpreter, avoids issues with fork() from global thread
with contextlib.suppress(RuntimeError):
    multiprocess.set_start_method("spawn")

basicConfig()
getLogger(__name__.rsplit(".", 1)[0]).setLevel(INFO)

logging.getLogger("volexity.gostrap").setLevel(logging.INFO)

logger: Final[Logger] = getLogger(__name__)


def run_cli() -> None:
    """Implements the GoResolver's command line interface."""
    args: Final[CLIArguments] = CLIArguments.parse_args(sys.argv)

    storage_path: Final[Path] = Path("./storage")
    generator: Final[SampleGenerator] = SampleGenerator(storage_path, display_progress=not args.quiet)

    match args:
        case CLIResolveArguments():
            return resolve(args, generator)
        case CLIManageArguments():
            return manage(args, generator)


def resolve(args: CLIResolveArguments, generator: SampleGenerator) -> None:
    """Implements GoResolver's resolve command."""
    symbol_tree: Final[SymbolTree] = SymbolTree()
    sample_bin: Final[Binary] = Binary(args.sample_path)
    compare_report: CompareReport | None = None

    # STEP 1: Extract symbols through similarities
    if args.use_graph:
        if args.compare_report is not None:
            with args.compare_report.open("r") as report_file:
                compare_report = CompareReport.from_json(report_file.read())
        else:
            go_comparator: Final[GoCompare] = GoCompare(
                generator, sample_bin, reference_path=args.reference_path, display_progress=not args.quiet
            )

            try:
                compare_report = go_comparator.compare(args.go_versions, args.libs)
            except UnsupportedBinaryFormat as e:
                logger.error(e)  # noqa: TRY400
                logger.warning("Skipping similarity analysis ...")

        # STEP 1.1: Optionally save the intermediary compare report.
        if args.backup_path is not None and compare_report is not None:
            with args.backup_path.open("w") as backup_file:
                backup_file.write(compare_report.to_json())
            logger.info(f"Intermediary report written to {args.backup_path}")

    # STEP 2: Extract embeded symbols
    if args.use_extract:
        sym_parser: Final[GoSymParser] = GoSymParser()
        symbols: Final[dict[int, str]] = sym_parser.extract(sample_bin)

        # STEP 2.1: Insert symbol in the tree
        for pc, symbol_name in symbols.items():
            try:
                symbol_tree.insert(pc, symbol_name, SymbolSource.EXTRACT)
            except ValueError as e:
                logger.debug(f"{pc:#0x} - {symbol_name} : {e}")

    # STEP 3: Parse types
    type_dict: dict | None = None
    gotypes_address: int | None = None
    if args.parse_types:
        moduledata: Final[ModuleData | None] = sym_parser.extract_moduledata(sample_bin)

        if moduledata is not None:
            type_parser: Final[GoTypeParser] = GoTypeParser(sample_bin, moduledata)
            type_parser.parse_types()

            type_dict = type_parser.to_dict()
            gotypes_address = moduledata.types

    # STEP 4: Cross-Reference with the compare report
    if compare_report is not None:
        for bin_matches in compare_report.matches:
            for method_match in bin_matches.matches:
                if len(method_match.resolved_name) > 0 and method_match.similarity >= args.threshold:
                    try:
                        symbol_tree.insert(method_match.malware_offset, method_match.resolved_name, SymbolSource.GRAPH)
                    except ValueError as e:
                        logger.debug(f"{method_match.malware_offset:#0x} - {method_match.resolved_name} : {e}")

    # STEP 5: Generate the final JSON report.
    report_json: str = SymbolReport(sample_bin.path, symbol_tree, gotypes_address, type_dict).to_json(pretty=True)

    # STEP 5.1: Print colorized report to the terminal.
    if sys.stdout.isatty():
        report_json = highlight(report_json, JsonLexer(), TerminalFormatter())

    print(report_json)  # noqa: T201

    # STEP 5.2: If required, then write report to disk.
    if args.output:
        with args.output.open("w") as output_file:
            output_file.write(report_json)
        logger.info(f"Report written to {args.output}")


def manage(args: CLIManageArguments, generator: SampleGenerator) -> None:
    """Implements GoResolver's manage command."""
    if args.list_available:
        for ver in generator.get_available_go_versions():
            print(ver)  # noqa: T201

    elif args.list_installed:
        for ver in generator.get_installed_go_versions():
            print(ver)  # noqa: T201

    elif args.install:
        generator.add_go_versions(*args.install)

    elif args.uninstall:
        generator.del_go_version(*args.uninstall)
