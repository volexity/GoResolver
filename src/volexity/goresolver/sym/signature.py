"""Signatures allow the matching of Yara string on arbitrary data."""

from typing import Final

import yara


class Signature:
    """Signatures allow the matching of Yara string on arbitrary data."""

    def __init__(self, signature: str) -> None:
        """Initialize a new signature.

        Args:
            signature: The signature's data.
        """
        sig: Final[str] = f"rule moduledata {{ strings: $moduledata = {signature} condition: any of them }}"
        self._rule: Final[yara.Rules] = yara.compile(source=sig)

    def match(self, bin_data: bytes) -> list[tuple[int, bytes]]:
        """Match the signature agains binary data.

        Args:
            bin_data: The data to match the signature on.

        Returns:
            The list of (offset, data) pairs for each matches.
        """
        matches: dict = self._rule.match(data=bin_data)
        return [
            (instance.offset, instance.matched_data) for match in matches for instance in match.strings[0].instances
        ]
