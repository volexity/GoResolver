"""Enumeration of the directions of a Channel type in Go."""

from enum import IntEnum


class ChanDir(IntEnum):
    """go/src/internal/abi/type.go.

    Go1.2, Go1.16, Go1.20:

    type ChanDir int

    const (
        RecvDir ChanDir             = 1 << iota // <-chan
        SendDir                                 // chan<-
        BothDir = RecvDir | SendDir             // chan
    )

    -----------------------------------------------------

    Go 1.24, only change is Invalid
    const (
        RecvDir    ChanDir = 1 << iota         // <-chan
        SendDir                                // chan<-
        BothDir            = RecvDir | SendDir // chan
        InvalidDir ChanDir = 0
    )
    """

    RECVDIR = 1 << 0  # <-chan
    SENDDIR = 1 << 1  # chan<-
    BOTHDIR = RECVDIR | SENDDIR  # chan
    INVALIDDIR = 0
