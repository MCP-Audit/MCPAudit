"""SARIF 2.1.0 report generation."""

from __future__ import annotations

from typing import Any

from mcts.reporting.models import Finding, ScanReport, Severity

SARIF_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}

SARIF_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
}


def write_sarif_report(report: ScanReport) -> str:
    """Serialize a scan report as SARIF 2.1.0 JSON."""
    import json

    payload = build_sarif(report)
    return json.dumps(payload, indent=2)


def build_sarif(report: ScanReport) -> dict[str, Any]:
    rules = _build_rules(report.findings)
    results = [_finding_to_result(finding, rules) for finding in report.findings]
    taxa = _collect_taxa(report.findings)

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "MCTS",
                "informationUri": "https://github.com/MCP-Audit/MCTS",
                "version": report.version,
                "rules": list(rules.values()),
            }
        },
        "results": results,
        "properties": {
            "target": report.target,
            "securityScore": report.score.overall,
            "riskIndex": report.score.risk_index,
        },
    }
    if taxa:
        run["taxa"] = taxa

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }


def _collect_taxa(findings: list[Finding]) -> list[dict[str, str]]:
    seen: set[str] = set()
    taxa: list[dict[str, str]] = []
    for finding in findings:
        tags = finding.evidence.get("attack_tags") or []
        if isinstance(tags, list):
            for tag in tags:
                if not isinstance(tag, str) or not tag.startswith("attack."):
                    continue
                if tag in seen:
                    continue
                seen.add(tag)
                taxa.append({"id": tag, "name": tag.replace("attack.", "").replace(".", " / ")})
        if finding.technique_id and finding.technique_id not in seen:
            seen.add(finding.technique_id)
            taxa.append({"id": finding.technique_id, "name": finding.technique_id})
    return taxa


def _build_rules(findings: list[Finding]) -> dict[str, dict[str, Any]]:
    rules: dict[str, dict[str, Any]] = {}
    for finding in findings:
        rule_id = finding.id
        if rule_id in rules:
            continue
        rules[rule_id] = {
            "id": rule_id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description},
            "helpUri": "https://github.com/MCP-Audit/MCTS",
            "properties": {
                "analyzer": finding.analyzer,
                "technique_id": finding.technique_id,
            },
        }
    return rules


def _finding_to_result(finding: Finding, rules: dict[str, dict[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": finding.id,
        "level": SARIF_SEVERITY[finding.severity],
        "message": {"text": finding.description},
        "properties": {
            "severity": finding.severity.value,
            "security-severity": SARIF_SECURITY_SEVERITY[finding.severity],
            "analyzer": finding.analyzer,
            "recommendation": finding.recommendation,
            "confidence": finding.confidence,
        },
    }
    taxa = _result_taxa(finding)
    if taxa:
        result["taxa"] = taxa
    if finding.tool:
        result["properties"]["tool"] = finding.tool
    if finding.technique_id:
        result["properties"]["technique_id"] = finding.technique_id
    if finding.mitigation_ids:
        result["properties"]["mitigation_ids"] = finding.mitigation_ids
    if finding.location:
        result["locations"] = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.location.file},
                    "region": {"startLine": finding.location.line or 1},
                }
            }
        ]
    if finding.id not in rules:
        rules[finding.id] = {
            "id": finding.id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description},
        }
    return result


def _result_taxa(finding: Finding) -> list[str]:
    tags: list[str] = []
    attack_tags = finding.evidence.get("attack_tags")
    if isinstance(attack_tags, list):
        tags.extend(str(tag) for tag in attack_tags if isinstance(tag, str))
    if finding.technique_id:
        tags.append(finding.technique_id)
    return tags
