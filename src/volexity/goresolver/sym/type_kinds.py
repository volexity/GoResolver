"""Enumeration of the kinds of types in Go."""

from enum import IntEnum, auto


class Kind(IntEnum):
    """go/src/internal/abi/type.go.

    type Kind uint8

    const (
        Invalid Kind = iota
        ...
        UnsafePointer
    )

    const (
        KindDirectIface Kind = 1 << 5
        KindMask        Kind = (1 << 5) - 1
    )
    """

    INVALID = 0
    BOOL = auto()
    INT = auto()
    INT8 = auto()
    INT16 = auto()
    INT32 = auto()
    INT64 = auto()
    UINT = auto()
    UINT8 = auto()
    UINT16 = auto()
    UINT32 = auto()
    UINT64 = auto()
    UINTPTR = auto()
    FLOAT32 = auto()
    FLOAT64 = auto()
    COMPLEX64 = auto()
    COMPLEX128 = auto()
    ARRAY = auto()
    CHAN = auto()
    FUNC = auto()
    INTERFACE = auto()
    MAP = auto()
    POINTER = auto()
    SLICE = auto()
    STRING = auto()
    STRUCT = auto()
    UNSAFEPOINTER = auto()

    DIRECTIFACE = 1 << 5
    MASK = (1 << 5) - 1
