"""The GOVersion class parses and give abstract access to the componants of a Go version."""

from enum import StrEnum, auto
from re import Match, match
from typing import Final

GO_VER_REGEX: Final[str] = r"go(\d+)(?:.(\d+))?(?:.(\d+))?(?:(beta|rc)(\d+)?)?"


class GOVersionTag(StrEnum):
    """Go version tags."""

    BETA = auto()
    RC = auto()


class GOVersion:
    """The GOVersion class parses and give abstract access to the componants of a Go version."""

    def __init__(self, version_str: str) -> None:
        """Initialize a new Go version from a Go version string.

        Args:
            version_str: String representation of a Go version.
        """
        self.major: int | None = None
        self.minor: int | None = None
        self.micro: int | None = None

        self.tag: GOVersionTag | None = None
        self.rev: int = 0

        match_result: Final[Match[str] | None] = match(GO_VER_REGEX, version_str)
        if match_result:
            groups: Final[tuple] = match_result.groups()

            self.micro = int(groups[2]) if groups[2] else None
            self.minor = int(groups[1]) if groups[1] else 0 if self.micro is not None else None
            self.major = int(groups[0]) if groups[0] else 0 if self.minor is not None else None

            if groups[3]:
                self.tag = GOVersionTag(groups[3])
            if groups[4]:
                self.rev = int(groups[4])
        else:
            message: Final[str] = "Couldn't parse GO version"
            raise ValueError(message)

    def __repr__(self) -> str:
        """Returns the string representation of a Go version.

        Returns:
            String representation of a Go version.
        """
        return self.__str__()

    def __str__(self) -> str:
        """Returns the string representation of a Go version.

        Returns:
            String representation of a Go version.
        """
        v: str = "go"

        if self.major is not None:
            v += f"{self.major}"
        if self.minor is not None:
            v += f".{self.minor}"
        if self.micro is not None:
            v += f".{self.micro}"

        if self.tag:
            v += f"{self.tag}{self.rev}"

        return v

    def __hash__(self) -> int:
        """Returns the hash of a GOVersion instance.

        Returns:
            Hash of the current GOVersion instance.
        """
        return hash(self.__dict__.values())

    def __eq__(self, other: object) -> bool:
        """Tests the equality between this and another instance of GOVersion.

        Args:
            other: Instance of GOVersion to compare to.

        Returns:
            Whether the two instance are equals.
        """
        if not isinstance(other, GOVersion):
            return NotImplemented

        return (
            (self.major or 0) == (other.major or 0)
            and (self.minor or 0) == (other.minor or 0)
            and (self.micro or 0) == (other.micro or 0)
            and self.tag == other.tag
            and self.rev == other.rev
        )

    def __ne__(self, other: object) -> bool:
        """Tests the inequality between this and another instance of GOVersion.

        Args:
            other: Instance of GOVersion to compare to.

        Returns:
            Whether the two instance are not equals.
        """
        if not isinstance(other, GOVersion):
            return NotImplemented

        return not self.__eq__(other)

    def __gt__(self, other: object) -> bool:  # noqa: PLR0911
        """Tests whether version is greater than another.

        Args:
            other: Instance of GOVersion to compare to.

        Returns:
            If this instance is greater.
        """
        if not isinstance(other, GOVersion):
            return NotImplemented

        if (self.major or 0) > (other.major or 0):
            return True
        if (self.major or 0) == (other.major or 0):
            if (self.minor or 0) > (other.minor or 0):
                return True
            if (self.minor or 0) == (other.minor or 0):
                if (self.micro or 0) > (other.micro or 0):
                    return True
                if (self.micro or 0) == (other.micro or 0):
                    if not other.tag or (self.tag and self.tag > other.tag):
                        return True
                    if self.tag == other.tag and self.rev > other.rev:
                        return True
        return False

    def __ge__(self, other: object) -> bool:
        """Tests whether version is greater than or equal to another.

        Args:
            other: Instance of GOVersion to compare to.

        Returns:
            If this instance is greater or equal.
        """
        if not isinstance(other, GOVersion):
            return NotImplemented

        return self == other or self > other

    def __lt__(self, other: object) -> bool:  # noqa: PLR0911
        """Tests whether version is less than another.

        Args:
            other: Instance of GOVersion to compare to.

        Returns:
            If this instance is lesser.
        """
        if not isinstance(other, GOVersion):
            return NotImplemented

        if (self.major or 0) < (other.major or 0):
            return True
        if (self.major or 0) == (other.major or 0):
            if (self.minor or 0) < (other.minor or 0):
                return True
            if (self.minor or 0) == (other.minor or 0):
                if (self.micro or 0) < (other.micro or 0):
                    return True
                if (self.micro or 0) == (other.micro or 0):
                    if not self.tag or (other.tag and self.tag < other.tag):
                        return True
                    if self.tag == other.tag and self.rev < other.rev:
                        return True
        return False

    def __le__(self, other: object) -> bool:
        """Tests whether version is less than or equal to another.

        Args:
            other: Instance of GOVersion to compare to.

        Returns:
            If this instance is lesser or equal.
        """
        if not isinstance(other, GOVersion):
            return NotImplemented

        return self == other or self < other

    @staticmethod
    def from_str(version: str) -> "GOVersion | None":
        """Parse a GOVersion from its string representation, returning None in case of failure.

        Args:
            version: The version string to parse the GOVersion from.

        Returns:
            The parsed GOVersion (if successful).
        """
        try:
            return GOVersion(version)
        except ValueError:
            return None

    def is_release(self) -> bool:
        """Test if the GOVersion is a proper release or a release candidate build.

        Returns:
            Whether the curent verison is a proper release or not.
        """
        return self.tag is None
