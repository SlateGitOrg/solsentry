"""solsentry: a static security analyzer for Solidity over the solc compact JSON AST.

Typical use::

    from pathlib import Path
    from solsentry import analyze_path

    result = analyze_path(Path("Bank.json"))
    for finding in result.findings:
        print(finding.location.short(), finding.detector, finding.message)
"""

from __future__ import annotations

__version__ = "0.1.0"

from solsentry.engine import AnalysisResult, analyze_input, analyze_path
from solsentry.findings import Confidence, Finding, Severity

__all__ = [
    "AnalysisResult",
    "Confidence",
    "Finding",
    "Severity",
    "__version__",
    "analyze_input",
    "analyze_path",
]
