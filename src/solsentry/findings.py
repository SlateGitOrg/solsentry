"""Finding records produced by detectors."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from solsentry.source import Location


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return ["info", "low", "medium", "high"].index(self.value)

    @classmethod
    def parse(cls, text: str) -> Severity:
        try:
            return cls(text.lower())
        except ValueError as exc:
            choices = ", ".join(s.value for s in cls)
            raise ValueError(f"unknown severity {text!r}; choose from {choices}") from exc


class Confidence(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class RelatedLocation:
    location: Location
    message: str


@dataclass(frozen=True)
class Finding:
    detector: str
    title: str
    severity: Severity
    confidence: Confidence
    message: str
    location: Location
    contract: str
    function: str
    snippet: str = ""
    related: tuple[RelatedLocation, ...] = field(default_factory=tuple)

    @property
    def fingerprint(self) -> str:
        """Stable across unrelated edits: detector, scope and normalised snippet, not lines."""
        material = "\x1f".join(
            [
                self.detector,
                self.location.path,
                self.contract,
                self.function,
                " ".join(self.snippet.split()),
            ]
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]

    def sort_key(self) -> tuple[str, int, int, str]:
        return (self.location.path, self.location.start, -self.severity.rank, self.detector)

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector": self.detector,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "message": self.message,
            "contract": self.contract,
            "function": self.function,
            "location": _location_dict(self.location),
            "snippet": self.snippet,
            "related": [
                {"message": r.message, "location": _location_dict(r.location)} for r in self.related
            ],
            "fingerprint": self.fingerprint,
        }


def _location_dict(location: Location) -> dict[str, Any]:
    return {
        "path": location.path,
        "start": location.start,
        "length": location.length,
        "line": location.line,
        "column": location.column,
        "endLine": location.end_line,
        "endColumn": location.end_column,
    }
