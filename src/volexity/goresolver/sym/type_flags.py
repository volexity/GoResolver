"""Enumeration of the type flags in Go."""

from enum import Enum


class TFlag(Enum):
    """go/src/internal/abi/type.go.

    type TFlag uint8

    const (
        TFlagUncommon TFlag = 1 << 0
        TFlagExtraStar TFlag = 1 << 1
        TFlagNamed TFlag = 1 << 2
        TFlagRegularMemory TFlag = 1 << 3
        TFlagGCMaskOnDemand TFlag = 1 << 4
    )
    """

    UNCOMMON = 1 << 0
    EXTRASTAR = 1 << 1
    NAMED = 1 << 2
    REGULARMEMORY = 1 << 3
    GCMASKONDEMAND = 1 << 4
