"""SRE Action data model."""

from dataclasses import dataclass
from pathlib import Path

from .action_modes import ActionModes


@dataclass
class SREAction:
    """SRE Action data model."""

    mode: ActionModes
    path: Path | None
    go_versions: list[str]
