"""Final Go symbol recovery report of a sample."""

import json
from hashlib import md5, sha1, sha256
from pathlib import Path
from typing import Final

from .symbol_tree import SymbolTree, SymbolTreeEncoder


class SymbolReport:
    """Final Go symbol recovery report of a sample."""

    def __init__(
        self, sample_path: Path, symbol_tree: SymbolTree, gotypes_address: int | None, type_data: dict | None
    ) -> None:
        """Initialize a new SymbolReport.

        Args:
            sample_path: Path to the sample related to the report.
            symbol_tree: SymbolTree of the symbol from the sample.
            gotypes_address: Address of Go runtime types
            type_data: Dictionary of all runtime type information
        """
        self._sample_name: Final[str] = sample_path.name
        self._symbol_tree: Final[SymbolTree] = symbol_tree
        self._gotypes_address: Final[int | None] = gotypes_address
        self._type_data: Final[dict | None] = type_data

        with sample_path.open("rb") as sample_file:
            sample_data: Final[bytes] = sample_file.read()
            self._hash: Final[dict[str, str]] = {
                "SHA256": sha256(sample_data).hexdigest(),
                "SHA1": sha1(sample_data).hexdigest(),  # noqa: S324
                "MD5": md5(sample_data).hexdigest(),  # noqa: S324
            }

    def to_dict(self) -> dict:
        """Returns the dictionary representation of the SymbolReport.

        Returns:
            The dictionary representation of the SymbolReport.
        """
        return {
            "Sample": {"Name": self._sample_name, "Hash": self._hash},
            "Symbols": self._symbol_tree,
            "GoTypes Address": hex(self._gotypes_address) if self._gotypes_address else None,
            "Types": self._type_data,
        }

    def to_json(self, pretty: bool = False) -> str:
        """Returns the JSON representation of the SymbolReport.

        Args:
            pretty: Wheter to prettify the output or not.

        Returns:
            JSON text data.
        """
        return json.dumps(self.to_dict(), cls=SymbolTreeEncoder, indent=4 if pretty else None)
