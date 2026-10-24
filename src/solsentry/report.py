"""Output formats: human-readable text, JSON and SARIF 2.1.0."""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from solsentry import __version__
from solsentry.detectors import detector_infos
from solsentry.detectors.base import DetectorInfo
from solsentry.engine import AnalysisResult
from solsentry.findings import Finding, Severity
from solsentry.source import Location

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_SARIF_LEVEL = {
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
#: GitHub code scanning reads ``security-severity`` (0.0-10.0) from rule properties.
_SECURITY_SEVERITY = {
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


def render_text(results: list[AnalysisResult], color: bool = False) -> str:
    lines: list[str] = []
    counts: Counter[str] = Counter()
    total = 0
    for result in results:
        for finding in result.findings:
            total += 1
            counts[finding.severity.value] += 1
            severity = finding.severity.value.upper()
            if color:
                code = {"HIGH": "31", "MEDIUM": "33", "LOW": "36", "INFO": "37"}[severity]
                severity = f"\x1b[{code}m{severity}\x1b[0m"
            lines.append(
                f"{finding.location.short()}: {severity} [{finding.detector}] {finding.message}"
            )
            lines.append(f"    in {finding.contract}.{finding.function}: {finding.snippet}")
            for related in finding.related:
                lines.append(f"    - {related.location.short()}: {related.message}")
        for name, reason in sorted(result.skipped.items()):
            lines.append(f"{result.origin}: note: skipped {name}: {reason}")
    functions = sum(r.functions_analyzed for r in results)
    breakdown = ", ".join(
        f"{counts[s.value]} {s.value}" for s in reversed(Severity) if counts[s.value]
    )
    summary = f"{total} finding(s) in {len(results)} input(s), {functions} function(s) analysed"
    lines.append(summary + (f" ({breakdown})" if breakdown else ""))
    return "\n".join(lines)


def render_json(results: list[AnalysisResult]) -> str:
    document = {
        "tool": {"name": "solsentry", "version": __version__},
        "inputs": [
            {
                "origin": r.origin,
                "compiler": r.compiler,
                "functionsAnalyzed": r.functions_analyzed,
                "cfgNodes": r.cfg_nodes,
                "suppressed": r.suppressed,
                "skipped": r.skipped,
                "findings": [f.to_dict() for f in r.findings],
            }
            for r in results
        ],
    }
    return json.dumps(document, indent=2, sort_keys=False)


def _region(location: Location) -> dict[str, int]:
    return {
        "startLine": location.line,
        "startColumn": location.column,
        "endLine": location.end_line,
        "endColumn": location.end_column,
        "charOffset": location.start,
        "charLength": location.length,
    }


def _physical(location: Location) -> dict[str, Any]:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": location.path, "uriBaseId": "SRCROOT"},
            "region": _region(location),
        }
    }


def _rule(info: DetectorInfo) -> dict[str, Any]:
    return {
        "id": info.id,
        "name": "".join(part.capitalize() for part in info.id.split("-")),
        "shortDescription": {"text": info.title},
        "fullDescription": {"text": info.description},
        "help": {
            "text": f"{info.remediation}\n\nSoundness limits: {info.soundness}",
            "markdown": f"{info.remediation}\n\n**Soundness limits.** {info.soundness}",
        },
        "defaultConfiguration": {"level": _SARIF_LEVEL[info.severity]},
        "properties": {
            "tags": ["security", info.cwe, info.swc],
            "precision": info.confidence.value,
            "security-severity": _SECURITY_SEVERITY[info.severity],
        },
    }


def _result(finding: Finding, rule_index: dict[str, int]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": finding.detector,
        "ruleIndex": rule_index[finding.detector],
        "level": _SARIF_LEVEL[finding.severity],
        "message": {"text": finding.message},
        "locations": [_physical(finding.location)],
        "partialFingerprints": {"solsentryFingerprint/v1": finding.fingerprint},
        "properties": {
            "severity": finding.severity.value,
            "confidence": finding.confidence.value,
            "contract": finding.contract,
            "function": finding.function,
        },
    }
    if finding.related:
        result["relatedLocations"] = [
            {"id": index, **_physical(r.location), "message": {"text": r.message}}
            for index, r in enumerate(finding.related, start=1)
        ]
    return result


def render_sarif(results: list[AnalysisResult]) -> str:
    infos = detector_infos()
    rule_index = {info.id: position for position, info in enumerate(infos)}
    document = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "solsentry",
                        "version": __version__,
                        "rules": [_rule(info) for info in infos],
                    }
                },
                "originalUriBaseIds": {
                    "SRCROOT": {"description": {"text": "Solidity source root"}}
                },
                "results": [_result(f, rule_index) for r in results for f in r.findings],
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "toolExecutionNotifications": [
                            {"level": "note", "message": {"text": f"skipped {name}: {reason}"}}
                            for r in results
                            for name, reason in sorted(r.skipped.items())
                        ],
                    }
                ],
            }
        ],
    }
    return json.dumps(document, indent=2)
