"""Implements the GoGrapher-py command line interface."""

import shutil
import sys
from cmd import Cmd
from logging import INFO, Logger, basicConfig, getLogger
from pathlib import Path
from typing import Final

from pygments import highlight
from pygments.formatters import TerminalFormatter
from pygments.lexers.web import JsonLexer
from volexity.gostrap.sample_generator import SampleGenerator

from gographer import CompareReport

from .go_compare import GoCompare
from .models.cli_arguments import CLIArguments
from .models.symbol_report import SymbolReport
from .models.symbol_source import SymbolSource
from .models.symbol_tree import SymbolTree
from .sym.go_sym_parser import GoSymParser

basicConfig()
getLogger(__name__.rsplit(".", 1)[0]).setLevel(INFO)

logger: Final[Logger] = getLogger(__name__)


def show_versions(generator: SampleGenerator) -> None:
    """Prints the available GO versions to the screen.

    Args:
        generator: Instance to retrieve the available versions from.
    """
    available: Final[list[str]] = [*generator.get_available_go_versions()]
    cmd: Final[Cmd] = Cmd()
    cmd.columnize(available, displaywidth=shutil.get_terminal_size().columns)
    sys.exit()


def run_cli() -> None:
    """Implements the GoGrapher-py command line interface."""
    storage_path: Final[Path] = Path("./storage")
    args: Final[CLIArguments] = CLIArguments(sys.argv)
    symbol_tree: Final[SymbolTree] = SymbolTree()

    generator: Final[SampleGenerator] = SampleGenerator(storage_path, display_progress=True)
    if args.show:
        show_versions(generator)

    # STEP 1: Extract symbols through similarities
    if args.use_graph:
        compare_report: CompareReport
        if args.compare_report is not None:
            with args.compare_report.open("r") as report_file:
                compare_report = CompareReport.from_json(report_file.read())
        else:
            go_comparator: Final[GoCompare] = GoCompare(
                generator, args.sample_path, reference_path=args.reference_path, display_progress=True
            )
            compare_report = go_comparator.compare(args.go_versions, args.libs)

        # STEP 1.1: Optionally save the intermediary compare report.
        if args.backup_path is not None:
            with args.backup_path.open("w") as backup_file:
                backup_file.write(compare_report.to_json())
            logger.info(f"Intermediary report written to {args.backup_path}")

    # STEP 2: Extract embeded symbols
    if args.use_extract:
        sym_parser: Final[GoSymParser] = GoSymParser()
        symbols: Final[dict[int, str]] = sym_parser.extract(args.sample_path)

        # STEP 2.1: Insert symbol in the tree
        for pc, symbol_name in symbols.items():
            symbol_tree.insert(pc, symbol_name, SymbolSource.EXTRACT)

    # STEP 3: Cross-Reference with the compare report
    if args.use_graph:
        for bin_matches in compare_report.matches:
            for method_match in bin_matches.matches:
                if len(method_match.resolved_name) > 0 and method_match.similarity >= args.threshold:
                    try:
                        symbol_tree.insert(method_match.malware_offset, method_match.resolved_name, SymbolSource.GRAPH)
                    except ValueError as e:
                        logger.debug(f"{method_match.malware_offset:#0x} - {method_match.resolved_name} : {e}")

    # STEP 4: Generate the final JSON report.
    report_json: Final[str] = SymbolReport(args.sample_path, symbol_tree).to_json(pretty=True)

    # STEP 4.1: Print colorized report to the terminal.
    if not args.quiet:
        report_colorized: Final[str] = highlight(report_json, JsonLexer(), TerminalFormatter())
        print(f"Report: {report_colorized}")  # noqa: T201

    # STEP 4.2: If required, then write report to disk.
    if args.output:
        with args.output.open("w") as output_file:
            output_file.write(report_json)
        logger.info(f"Report written to {args.output}")
