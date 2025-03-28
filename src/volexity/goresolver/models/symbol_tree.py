"""The SymbolTree organize the symbols hierchally from their symbol names.

Additionally it also allows the merging and reslution of different symbol sources.
"""

import json
import re
from typing import Any, Final, override

from .symbol_source import SymbolSource

PARSE_REGEX: Final[str] = r"([^\.\[\]\{\}]+(?:[\[|\{].*[\]|\}])?)"
DEFAULT_INIT_WEIGHT: Final[int] = 1


class SymbolTreeEncoder(json.JSONEncoder):
    """SymbolTree JSON encoder."""

    @override
    def default(self, o: Any) -> Any:
        """Add support for serializing SymbolTree classes."""
        if isinstance(o, SymbolTree):
            return o.to_dict()
        if isinstance(o, SymbolTreeNode):
            return o.to_dict()
        return super().default(o)


class SymbolTreeNode:
    """Node class of the SymbolTree."""

    def __init__(
        self, source: SymbolSource | None = None, node_name: str | None = None, parent: "SymbolTreeNode | None" = None
    ) -> None:
        """Initialize a new SymbolTree node.

        Nodes without names are considered "root nodes" and don't appear in the node path.

        Args:
            source: Source of the symbol.
            node_name: Name of the symbol to initialize.
            parent: Parent of the symbol (if any).
        """
        self._root_node: Final[bool] = node_name is None
        self._node_name: Final[dict[str, int]] = {node_name if node_name is not None else "root": DEFAULT_INIT_WEIGHT}

        self._parent: Final[SymbolTreeNode | None] = parent
        self._sources: Final[dict[SymbolSource, int] | None] = {source: 1} if source else None

        self._nodes: Final[dict[str, SymbolTreeNode]] = {}

    def insert(self, path: list[str], source: SymbolSource) -> "SymbolTreeNode":
        """Insert a new node below the current node.

        Args:
            path: The path to the node to insert.
            source: The data source of the symbol.

        Returns:
            The leaf node where the symbol was inserted.
        """
        if len(path) > 0:
            node_name: Final[str] = path.pop(0)

            if self._nodes.get(node_name) is None:
                self._nodes[node_name] = SymbolTreeNode(source, node_name, self if not self._root_node else None)
            return self._nodes[node_name].insert(path, source)
        return self

    def add_reference(self, path: list[str], source: SymbolSource) -> None:
        """Increment the references of name and sources along the specified node path.

        Args:
            path: The path to the node to insert.
            source: The data source of the symbol.
        """
        if len(path) > 0:
            node_name: Final[str] = path.pop()
            self._node_name[node_name] = self._node_name.get(node_name, 0) + 1
            if self._sources is not None:
                self._sources[source] = self._sources.get(source, 0) + 1
            if self._parent is not None:
                self._parent.add_reference(path, source)

    def to_dict(self) -> dict:
        """Returns the dictionary representation of the current node.

        Returns:
            Dictionary representation of the current node.
        """
        return {"Name": self.path, "Sources": self._sources}

    @property
    def node_name(self) -> str:
        """Returns the most referenced name of the current node.

        In case of a tie, the top names are joined by a double undescore.

        Returns:
            The name of the curren Node
        """
        max_value: Final[int] = max(self._node_name.values())
        return "__".join(name for name in self._node_name if self._node_name[name] == max_value)

    @property
    def path(self) -> str:
        """Return the path of the curent node.

        This path is computed from the node location in the tree.

        Returns:
            The path of the current node.
        """
        if self._parent is not None:
            return f"{self._parent.path}.{self.node_name}"
        return self.node_name

    @property
    def path_len(self) -> int:
        """Returns the length of the path to the current node (in jumps).

        Returns:
            Length of the path to the current node.
        """
        if self._parent is not None:
            return self._parent.path_len + 1
        return 1


class SymbolTree:
    """The SymbolTree organize the symbols hierchally from their symbol names.

    Additionally it also allows the merging and reslution of different symbol sources.
    """

    def __init__(self) -> None:
        """Initialize a new Symbol tree."""
        self._nodes: Final[SymbolTreeNode] = SymbolTreeNode()
        self._leafs: dict[int, SymbolTreeNode] = {}

    @staticmethod
    def _parse_path(name: str) -> list[str]:
        """Parse a symbol name into the different component of a symbol path.

        Args:
            name: The symbol name to parse.

        Returns:
            The resulting symbol path.
        """
        path: Final[list[str]] = re.findall(PARSE_REGEX, name)
        if len(path) == 0:
            msg = "Invalid name"
            raise ValueError(msg)
        return path

    def insert(self, entry: int, name: str, source: SymbolSource) -> None:
        """Insert a symbol into the SymbolTree.

        If this symbol already exists, then its reference count for the specified source get incremented.

        Args:
            entry: Entry point of the symbol.
            name: Name of the symbol.
            source: The source of the symbol.
        """
        symbol_path: Final[list[str]] = SymbolTree._parse_path(name)
        if self._leafs.get(entry) is not None:
            if self._leafs[entry].path_len != len(symbol_path):
                msg = "Incompatible symbol path length !"
                raise ValueError(msg)
            self._leafs[entry].add_reference(symbol_path, source)
        else:
            leaf: Final[SymbolTreeNode] = self._nodes.insert(symbol_path, source)
            self._leafs[entry] = leaf

    def print_out(self) -> None:
        """Print the symbols of the tree in a concise, human readable form."""
        for pc, leaf in self._leafs.items():
            print(f"{pc:#0x} -> {leaf.path}")  # noqa: T201

    def to_dict(self) -> dict:
        """Returns the dictionary representation of the symbol tree.

        Returns:
            The dictionary representation of the symbol tree.
        """
        return {hex(key): self._leafs[key] for key in sorted(self._leafs)}
