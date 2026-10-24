"""Detector registry."""

from __future__ import annotations

from solsentry.detectors.access_control import MissingAccessControlDetector
from solsentry.detectors.base import Detector, DetectorInfo
from solsentry.detectors.integer import IntegerOverflowDetector
from solsentry.detectors.reentrancy import ReentrancyDetector
from solsentry.detectors.timestamp import TimestampDependenceDetector
from solsentry.detectors.tx_origin import TxOriginDetector
from solsentry.detectors.unchecked_call import UncheckedCallDetector
from solsentry.detectors.unprotected import (
    UnprotectedDelegatecallDetector,
    UnprotectedSelfdestructDetector,
)

ALL_DETECTORS: tuple[type[Detector], ...] = (
    ReentrancyDetector,
    TxOriginDetector,
    UncheckedCallDetector,
    UnprotectedSelfdestructDetector,
    UnprotectedDelegatecallDetector,
    MissingAccessControlDetector,
    IntegerOverflowDetector,
    TimestampDependenceDetector,
)

REGISTRY: dict[str, type[Detector]] = {cls.info.id: cls for cls in ALL_DETECTORS}


def detector_infos() -> list[DetectorInfo]:
    return [cls.info for cls in ALL_DETECTORS]


def select(ids: list[str] | None = None, exclude: list[str] | None = None) -> list[type[Detector]]:
    """Resolve detector ids (``None`` = all) minus ``exclude``; unknown ids raise ``ValueError``."""
    unknown = [i for i in [*(ids or []), *(exclude or [])] if i not in REGISTRY]
    if unknown:
        raise ValueError(f"unknown detector(s): {', '.join(unknown)}; known: {', '.join(REGISTRY)}")
    chosen = [REGISTRY[i] for i in ids] if ids else list(ALL_DETECTORS)
    return [cls for cls in chosen if cls.info.id not in set(exclude or [])]


__all__ = ["ALL_DETECTORS", "REGISTRY", "Detector", "DetectorInfo", "detector_infos", "select"]
