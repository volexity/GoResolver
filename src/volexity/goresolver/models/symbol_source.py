"""Enumeration of the different available symbol sources."""

from enum import StrEnum, auto


class SymbolSource(StrEnum):
    """Enumeration of the different available symbol sources."""

    EXTRACT = auto()
    GRAPH = auto()
