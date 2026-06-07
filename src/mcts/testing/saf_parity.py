"""Evaluate MCTS detectors against vendored SAF-MCP test-logs.json fixtures."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcts.analyzers.autonomous_loop import detect_autonomous_loop_event
from mcts.analyzers.backdoored_install import detect_backdoored_install_event
from mcts.analyzers.behavioral_extraction import detect_behavioral_extraction
from mcts.analyzers.command_injection import detect_command_injection
from mcts.analyzers.context_memory_implant import detect_context_memory_implant
from mcts.analyzers.credential_access import detect_credential_file_access
from mcts.analyzers.cross_server_registry import detect_cross_server_shadowing
from mcts.analyzers.dns_poisoning import detect_dns_poisoning_event
from mcts.analyzers.exposed_endpoint import detect_exposed_endpoint
from mcts.analyzers.fake_tool_invocation import detect_fake_tool_invocation
from mcts.analyzers.inspector_rce import detect_inspector_rce_event
from mcts.analyzers.instruction_steganography import detect_instruction_steganography
from mcts.analyzers.line_jumping import detect_line_jumping
from mcts.analyzers.metadata_integrity import MetadataIntegrityAnalyzer
from mcts.analyzers.oauth_escalation_runtime import (
    detect_confused_deputy_event,
    detect_rogue_as_event,
    detect_scope_substitution_event,
)
from mcts.analyzers.oauth_mixup import detect_oauth_mixup_event
from mcts.analyzers.oauth_phishing import detect_oauth_phishing_config
from mcts.analyzers.oauth_token_persistence import detect_oauth_token_persistence_event
from mcts.analyzers.over_privileged import detect_over_privileged_process
from mcts.analyzers.path_traversal import detect_path_traversal_event
from mcts.analyzers.privilege_tool_abuse import detect_privilege_tool_abuse
from mcts.analyzers.prompt_injection import PromptInjectionAnalyzer
from mcts.analyzers.rug_pull import detect_rug_pull_event
from mcts.analyzers.sampling_abuse import detect_sampling_abuse
from mcts.analyzers.sandbox_escape import detect_sandbox_escape
from mcts.analyzers.schema_fsp import detect_schema_fsp
from mcts.analyzers.schema_surface import SchemaSurfaceAnalyzer
from mcts.analyzers.sigma_dedupe import dedupe_sigma_findings
from mcts.analyzers.sigma_metadata import SigmaMetadataAnalyzer
from mcts.analyzers.supply_chain_signals import detect_supply_chain_manifest
from mcts.analyzers.suspicious_registration import detect_suspicious_tool_registration
from mcts.analyzers.tool_output_injection import detect_tool_output_injection
from mcts.analyzers.tool_redefinition import (
    detect_tool_definition_file_event,
    detect_tool_redefinition_baseline,
)
from mcts.analyzers.tool_shadowing import detect_tool_shadowing
from mcts.analyzers.vector_poisoning import detect_vector_poisoning
from mcts.mcp.models import MCPServerInfo, MCPTool

FIXTURES_ROOT = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "saf_mcp"
PARITY_THRESHOLD = 80.0
PARITY_TECHNIQUES: tuple[str, ...] = (
    "SAF-T1001",
    "SAF-T1002",
    "SAF-T1003",
    "SAF-T1004",
    "SAF-T1005",
    "SAF-T1006",
    "SAF-T1007",
    "SAF-T1008",
    "SAF-T1009",
    "SAF-T1101",
    "SAF-T1102",
    "SAF-T1103",
    "SAF-T1104",
    "SAF-T1105",
    "SAF-T1112",
    "SAF-T1201",
    "SAF-T1205",
    "SAF-T1401",
    "SAF-T1501",
    "SAF-T1502",
    "SAF-T1301",
    "SAF-T1302",
    "SAF-T1303",
    "SAF-T1603",
    "SAF-T1306",
    "SAF-T1307",
    "SAF-T1308",
    "SAF-T1402",
    "SAF-T2106",
    "SAF-T1106",
    "SAF-T1109",
    "SAF-T1202",
    "SAF-T1203",
    "SAF-T1204",
)


@dataclass(frozen=True)
class ParityCase:
    case_id: str
    expect: bool
    payload: dict[str, Any]


@dataclass(frozen=True)
class ParityResult:
    technique_id: str
    total: int
    correct: int
    false_positives: list[str]
    false_negatives: list[str]

    @property
    def parity_pct(self) -> float:
        if self.total == 0:
            return 100.0
        return round(100.0 * self.correct / self.total, 1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "total": self.total,
            "correct": self.correct,
            "parity_pct": self.parity_pct,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
        }


def detect_metadata_poison(tool_name: str, description: str) -> bool:
    """Return True when metadata analyzers (post-dedupe) flag the tool."""
    tool = MCPTool(
        name=tool_name,
        description=description,
        input_schema={"type": "object", "properties": {}},
    )
    server = MCPServerInfo(name="parity", tools=[tool])
    findings: list = []
    findings.extend(PromptInjectionAnalyzer().analyze(server))
    findings.extend(MetadataIntegrityAnalyzer().analyze(server))
    findings.extend(SchemaSurfaceAnalyzer().analyze(server))
    findings.extend(SigmaMetadataAnalyzer().analyze(server))
    findings = [
        f
        for f in dedupe_sigma_findings(findings)
        if f.saf_technique_id not in {"SAF-T1008"}
    ]
    return any(f.tool == tool_name for f in findings)


def detect_shadowing_case(entry: dict[str, Any]) -> bool:
    schema = entry.get("parameters")
    input_schema: dict[str, Any] | None = None
    if isinstance(schema, dict):
        input_schema = {"type": "object", "properties": schema}
    return detect_tool_shadowing(
        tool_name=str(entry.get("tool_name", "")),
        description=str(entry.get("tool_description", "")),
        server_name=str(entry.get("server_name", "")),
        input_schema=input_schema,
    )


def detect_line_jumping_case(entry: dict[str, Any]) -> bool:
    log = entry.get("log_entry", entry)
    return detect_line_jumping(
        str(log.get("context_content", "")),
        context_position=int(log.get("context_position", 0)),
        content_source=str(log.get("content_source", "")),
        authenticated=bool(log.get("authenticated", False)),
    )


def detect_path_case(entry: dict[str, Any]) -> bool:
    return detect_path_traversal_event(
        tool_name=str(entry.get("tool_name", "")),
        path=str(entry.get("path", "")),
        result=entry.get("result"),
    )


def detect_command_case(entry: dict[str, Any]) -> bool:
    log = entry.get("log_entry", entry)
    return detect_command_injection(
        tool_name=str(log.get("tool_name", "")),
        tool_parameters=log.get("tool_parameters"),
    )


def detect_rug_pull_case(entry: dict[str, Any]) -> bool:
    log = entry.get("log_entry", entry)
    return detect_rug_pull_event(log)


def detect_oauth_case(entry: dict[str, Any]) -> bool:
    config = entry.get("config", entry)
    if isinstance(config, dict):
        return detect_oauth_phishing_config(config)
    return False


def detect_fsp_case(entry: dict[str, Any]) -> bool:
    schema = entry.get("input_schema")
    if isinstance(schema, dict):
        return detect_schema_fsp(schema)
    return False


def detect_oauth_mixup_case(entry: dict[str, Any]) -> bool:
    return detect_oauth_mixup_event(entry)


def detect_sampling_case(entry: dict[str, Any]) -> bool:
    return detect_sampling_abuse(entry)


def detect_credential_access_case(entry: dict[str, Any]) -> bool:
    return detect_credential_file_access(
        tool_name=str(entry.get("tool_name", "")),
        file_path=str(entry.get("file_path") or entry.get("path") or ""),
    )


def detect_tool_redefinition_case(entry: dict[str, Any]) -> bool:
    if "baseline_tools" in entry:
        return detect_tool_redefinition_baseline(
            baseline_tools=list(entry.get("baseline_tools") or []),
            current_tools=list(entry.get("current_tools") or []),
            metadata_changed=bool(entry.get("metadata_changed", False)),
        )
    return detect_tool_definition_file_event(entry)


def detect_over_privileged_case(entry: dict[str, Any]) -> bool:
    return detect_over_privileged_process(entry)


def detect_behavioral_extraction_case(entry: dict[str, Any]) -> bool:
    return detect_behavioral_extraction(entry)


def detect_exposed_endpoint_case(entry: dict[str, Any]) -> bool:
    return detect_exposed_endpoint(entry)


def detect_dns_poisoning_case(entry: dict[str, Any]) -> bool:
    return detect_dns_poisoning_event(entry)


def detect_supply_chain_case(entry: dict[str, Any]) -> bool:
    return detect_supply_chain_manifest(entry)


def detect_tool_output_case(entry: dict[str, Any]) -> bool:
    return detect_tool_output_injection(
        tool_output=str(entry.get("tool_output", "")),
        tool_name=str(entry.get("tool_name", "")),
    )


def detect_cross_server_registry_case(entry: dict[str, Any]) -> bool:
    return detect_cross_server_shadowing(entry)


def detect_privilege_tool_case(entry: dict[str, Any]) -> bool:
    return detect_privilege_tool_abuse(entry)


def detect_suspicious_registration_case(entry: dict[str, Any]) -> bool:
    return detect_suspicious_tool_registration(entry)


def detect_fake_tool_case(entry: dict[str, Any]) -> bool:
    return detect_fake_tool_invocation(entry)


def detect_sandbox_escape_case(entry: dict[str, Any]) -> bool:
    return detect_sandbox_escape(entry)


def detect_rogue_as_case(entry: dict[str, Any]) -> bool:
    return detect_rogue_as_event(entry)


def detect_confused_deputy_case(entry: dict[str, Any]) -> bool:
    return detect_confused_deputy_event(entry)


def detect_scope_substitution_case(entry: dict[str, Any]) -> bool:
    return detect_scope_substitution_event(entry)


def detect_instruction_steganography_case(entry: dict[str, Any]) -> bool:
    return detect_instruction_steganography(entry)


def detect_vector_poisoning_case(entry: dict[str, Any]) -> bool:
    return detect_vector_poisoning(entry)


def detect_autonomous_loop_case(entry: dict[str, Any]) -> bool:
    return detect_autonomous_loop_event(entry)


def detect_inspector_rce_case(entry: dict[str, Any]) -> bool:
    return detect_inspector_rce_event(entry)


def detect_oauth_token_persistence_case(entry: dict[str, Any]) -> bool:
    return detect_oauth_token_persistence_event(entry)


def detect_backdoored_install_case(entry: dict[str, Any]) -> bool:
    return detect_backdoored_install_event(entry)


def detect_context_memory_implant_case(entry: dict[str, Any]) -> bool:
    return detect_context_memory_implant(entry)


def load_cases(technique_id: str) -> list[ParityCase]:
    logs_path = FIXTURES_ROOT / technique_id / "test-logs.json"
    expected_path = FIXTURES_ROOT / technique_id / "expected.json"
    if not logs_path.exists() or not expected_path.exists():
        return []

    expected = json.loads(expected_path.read_text(encoding="utf-8"))

    if technique_id == "SAF-T2106":
        return _cases_ndjson(logs_path, expected)

    if technique_id == "SAF-T1001":
        return _cases_t1001(expected)

    raw = json.loads(logs_path.read_text(encoding="utf-8"))
    if technique_id == "SAF-T1008":
        return _cases_t1008(raw, expected)
    if technique_id == "SAF-T1105":
        return _cases_t1105(raw, expected)
    if technique_id == "SAF-T1401":
        return _cases_t1401(raw, expected)
    if technique_id in {"SAF-T1007", "SAF-T1501"}:
        return _cases_simple_array(raw, expected)
    if technique_id == "SAF-T1101":
        return _cases_t1101(raw, expected)
    if technique_id == "SAF-T1201":
        return _cases_t1201(raw, expected)
    if technique_id == "SAF-T1009":
        return _cases_t1009(raw, expected)
    if technique_id == "SAF-T1112":
        return _cases_simple_array(raw, expected)
    if technique_id == "SAF-T1502":
        return _cases_t1502(raw, expected)
    if technique_id == "SAF-T1205":
        return _cases_simple_array(raw, expected)
    if technique_id in {"SAF-T1104", "SAF-T1005", "SAF-T1301"}:
        return _cases_should_trigger_array(raw, expected)
    if technique_id == "SAF-T1603":
        return _cases_t1603(raw, expected)
    if technique_id == "SAF-T1004":
        return _cases_t1004(raw, expected)
    if technique_id in {"SAF-T1002", "SAF-T1003", "SAF-T1102", "SAF-T1006", "SAF-T1103", "SAF-T1303"}:
        return _cases_simple_array(raw, expected)
    if technique_id == "SAF-T1302":
        return _cases_simple_array(raw, expected)
    if technique_id == "SAF-T1306":
        return _cases_indexed_array(raw, expected)
    if technique_id == "SAF-T1307":
        return _cases_simple_array(raw, expected)
    if technique_id == "SAF-T1308":
        return _cases_t1308(raw, expected)
    if technique_id == "SAF-T1402":
        return _cases_indexed_array(raw, expected)
    if technique_id == "SAF-T1106":
        return _cases_t1106(raw, expected)
    if technique_id == "SAF-T1109":
        return _cases_t1109(raw, expected)
    if technique_id in {"SAF-T1202", "SAF-T1203"}:
        return _cases_scenarios(raw, expected)
    if technique_id == "SAF-T1204":
        return _cases_simple_array(raw, expected)
    return []


def _cases_t1001(expected: dict[str, bool]) -> list[ParityCase]:
    cases: list[ParityCase] = []
    logs_path = FIXTURES_ROOT / "SAF-T1001" / "test-logs.json"
    for line in logs_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        row = json.loads(line)
        tool_name = str(row.get("tool_name", "unknown"))
        cases.append(
            ParityCase(
                case_id=tool_name,
                expect=expected.get(tool_name, False),
                payload={"tool_name": tool_name, "tool_description": row.get("tool_description", "")},
            )
        )
    return cases


def _cases_t1008(raw: dict[str, Any], expected: dict[str, bool]) -> list[ParityCase]:
    cases: list[ParityCase] = []
    for category, entries in raw.items():
        if not isinstance(entries, list):
            continue
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                continue
            case_id = f"{category}:{entry.get('tool_name', index)}:{index}"
            cases.append(
                ParityCase(
                    case_id=case_id,
                    expect=expected.get(case_id, False),
                    payload=entry,
                )
            )
    return cases


def _cases_t1105(raw: dict[str, Any], expected: dict[str, bool]) -> list[ParityCase]:
    cases: list[ParityCase] = []
    for bucket in ("positive_test_cases", "negative_test_cases"):
        entries = raw.get(bucket, [])
        if not isinstance(entries, list):
            continue
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                continue
            case_id = f"{bucket}:{index}"
            cases.append(
                ParityCase(
                    case_id=case_id,
                    expect=expected.get(case_id, bucket.startswith("positive")),
                    payload=entry,
                )
            )
    return cases


def _cases_simple_array(raw: list[Any], expected: dict[str, bool]) -> list[ParityCase]:
    cases: list[ParityCase] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            continue
        case_id = str(entry.get("case_id", f"case_{index}"))
        cases.append(
            ParityCase(
                case_id=case_id,
                expect=expected.get(case_id, bool(entry.get("expect", False))),
                payload=entry,
            )
        )
    return cases


def _cases_t1101(raw: dict[str, Any], expected: dict[str, bool]) -> list[ParityCase]:
    cases: list[ParityCase] = []
    for index, entry in enumerate(raw.get("test_cases", [])):
        if not isinstance(entry, dict):
            continue
        case_id = str(entry.get("id", f"case_{index}"))
        cases.append(
            ParityCase(
                case_id=case_id,
                expect=expected.get(case_id, bool(entry.get("expected_detection", False))),
                payload=entry,
            )
        )
    return cases


def _cases_t1201(raw: list[Any], expected: dict[str, bool]) -> list[ParityCase]:
    cases: list[ParityCase] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            continue
        case_id = f"case:{index}"
        cases.append(
            ParityCase(
                case_id=case_id,
                expect=expected.get(case_id, bool(entry.get("should_trigger", False))),
                payload=entry,
            )
        )
    return cases


def _cases_t1009(raw: dict[str, Any], expected: dict[str, bool]) -> list[ParityCase]:
    cases: list[ParityCase] = []
    for index, entry in enumerate(raw.get("test_cases", [])):
        if not isinstance(entry, dict):
            continue
        case_id = str(entry.get("name", f"case_{index}"))
        cases.append(
            ParityCase(
                case_id=case_id,
                expect=expected.get(
                    case_id,
                    len(entry.get("expected_alerts") or []) > 0,
                ),
                payload=entry,
            )
        )
    return cases


def _cases_t1502(raw: list[Any], expected: dict[str, bool]) -> list[ParityCase]:
    cases: list[ParityCase] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            continue
        case_id = f"case:{index}"
        cases.append(
            ParityCase(
                case_id=case_id,
                expect=expected.get(case_id, bool(entry.get("expected_detection", False))),
                payload=entry,
            )
        )
    return cases


def _cases_should_trigger_array(raw: list[Any], expected: dict[str, bool]) -> list[ParityCase]:
    cases: list[ParityCase] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            continue
        case_id = f"case:{index}"
        cases.append(
            ParityCase(
                case_id=case_id,
                expect=expected.get(case_id, bool(entry.get("should_trigger", False))),
                payload=entry,
            )
        )
    return cases


def _cases_t1603(raw: dict[str, Any], expected: dict[str, bool]) -> list[ParityCase]:
    cases: list[ParityCase] = []
    for index, entry in enumerate(raw.get("test_cases", [])):
        if not isinstance(entry, dict):
            continue
        case_id = str(entry.get("id", f"case_{index}"))
        cases.append(
            ParityCase(
                case_id=case_id,
                expect=expected.get(case_id, entry.get("expected_result") == "detect"),
                payload=entry,
            )
        )
    return cases


def _cases_t1004(raw: list[Any], expected: dict[str, bool]) -> list[ParityCase]:
    cases: list[ParityCase] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            continue
        case_id = f"case:{index}"
        cases.append(
            ParityCase(
                case_id=case_id,
                expect=expected.get(case_id, bool(entry.get("expected_detection", False))),
                payload=entry,
            )
        )
    return cases


def _cases_t1106(raw: list[Any], expected: dict[str, bool]) -> list[ParityCase]:
    return [
        ParityCase(
            case_id="batch_positive",
            expect=expected.get("batch_positive", True),
            payload={"events": raw},
        ),
        ParityCase(
            case_id="single_event",
            expect=expected.get("single_event", False),
            payload={"events": raw[:1]},
        ),
        ParityCase(
            case_id="two_events",
            expect=expected.get("two_events", False),
            payload={"events": raw[:2]},
        ),
    ]


def _cases_t1109(raw: list[Any], expected: dict[str, bool]) -> list[ParityCase]:
    cases: list[ParityCase] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            continue
        log_entry = entry.get("log_entry", entry)
        cases.append(
            ParityCase(
                case_id=f"case:{index}",
                expect=expected.get(f"case:{index}", bool(entry.get("should_trigger", False))),
                payload={"log_entry": log_entry} if isinstance(log_entry, dict) else entry,
            )
        )
    return cases


def _cases_scenarios(raw: dict[str, Any], expected: dict[str, bool]) -> list[ParityCase]:
    cases: list[ParityCase] = []
    for bucket in ("test_scenarios", "benign_scenarios"):
        for scenario in raw.get(bucket, []):
            if not isinstance(scenario, dict):
                continue
            case_id = str(scenario.get("scenario_id", ""))
            cases.append(
                ParityCase(
                    case_id=case_id,
                    expect=expected.get(case_id, bool(scenario.get("expected_detection", False))),
                    payload={"logs": list(scenario.get("logs") or [])},
                )
            )
    return cases


def _cases_indexed_array(raw: list[Any], expected: dict[str, bool]) -> list[ParityCase]:
    cases: list[ParityCase] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            continue
        case_id = f"case:{index}"
        cases.append(
            ParityCase(
                case_id=case_id,
                expect=expected.get(case_id, False),
                payload=entry,
            )
        )
    return cases


def _cases_t1308(raw: dict[str, Any], expected: dict[str, bool]) -> list[ParityCase]:
    cases: list[ParityCase] = []
    for index, entry in enumerate(raw.get("test_cases", [])):
        if not isinstance(entry, dict):
            continue
        case_id = str(entry.get("test_id", f"case_{index}"))
        log_entry = entry.get("log_entry", entry)
        cases.append(
            ParityCase(
                case_id=case_id,
                expect=expected.get(case_id, bool(entry.get("expected_match", False))),
                payload={"log_entry": log_entry} if isinstance(log_entry, dict) else entry,
            )
        )
    return cases


def _cases_ndjson(logs_path: Path, expected: dict[str, bool]) -> list[ParityCase]:
    cases: list[ParityCase] = []
    for index, line in enumerate(logs_path.read_text(encoding="utf-8").splitlines()):
        line = line.strip()
        if not line:
            continue
        row = json.loads(line)
        case_id = f"line:{index}"
        cases.append(
            ParityCase(
                case_id=case_id,
                expect=expected.get(case_id, False),
                payload=row,
            )
        )
    return cases


def _cases_t1401(raw: list[Any], expected: dict[str, bool]) -> list[ParityCase]:
    cases: list[ParityCase] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            continue
        case_id = str(entry.get("test_case", f"case_{index}"))
        cases.append(
            ParityCase(
                case_id=case_id,
                expect=expected.get(case_id, bool(entry.get("expected_detection", False))),
                payload=entry,
            )
        )
    return cases


def detect_case(technique_id: str, case: ParityCase) -> bool:
    if technique_id == "SAF-T1001":
        return detect_metadata_poison(
            str(case.payload.get("tool_name", "")),
            str(case.payload.get("tool_description", "")),
        )
    if technique_id == "SAF-T1008":
        return detect_shadowing_case(case.payload)
    if technique_id == "SAF-T1105":
        return detect_path_case(case.payload)
    if technique_id == "SAF-T1401":
        return detect_line_jumping_case(case.payload)
    if technique_id == "SAF-T1101":
        return detect_command_case(case.payload)
    if technique_id == "SAF-T1201":
        return detect_rug_pull_case(case.payload)
    if technique_id == "SAF-T1007":
        return detect_oauth_case(case.payload)
    if technique_id == "SAF-T1501":
        return detect_fsp_case(case.payload)
    if technique_id == "SAF-T1009":
        return detect_oauth_mixup_case(case.payload)
    if technique_id == "SAF-T1112":
        return detect_sampling_case(case.payload)
    if technique_id == "SAF-T1502":
        return detect_credential_access_case(case.payload)
    if technique_id == "SAF-T1205":
        return detect_tool_redefinition_case(case.payload)
    if technique_id == "SAF-T1104":
        return detect_over_privileged_case(case.payload)
    if technique_id == "SAF-T1603":
        return detect_behavioral_extraction_case(case.payload)
    if technique_id == "SAF-T1005":
        return detect_exposed_endpoint_case(case.payload)
    if technique_id == "SAF-T1004":
        return detect_dns_poisoning_case(case.payload)
    if technique_id == "SAF-T1002":
        return detect_supply_chain_case({**case.payload, "saf_technique": "SAF-T1002"})
    if technique_id == "SAF-T1003":
        return detect_supply_chain_case({**case.payload, "saf_technique": "SAF-T1003"})
    if technique_id == "SAF-T1102":
        return detect_tool_output_case(case.payload)
    if technique_id == "SAF-T1301":
        return detect_cross_server_registry_case(case.payload)
    if technique_id == "SAF-T1302":
        return detect_privilege_tool_case(case.payload)
    if technique_id == "SAF-T1006":
        return detect_suspicious_registration_case(case.payload)
    if technique_id == "SAF-T1103":
        return detect_fake_tool_case(case.payload)
    if technique_id == "SAF-T1303":
        return detect_sandbox_escape_case(case.payload)
    if technique_id == "SAF-T1306":
        return detect_rogue_as_case(case.payload)
    if technique_id == "SAF-T1307":
        return detect_confused_deputy_case(case.payload)
    if technique_id == "SAF-T1308":
        return detect_scope_substitution_case(case.payload)
    if technique_id == "SAF-T1402":
        return detect_instruction_steganography_case(case.payload)
    if technique_id == "SAF-T2106":
        return detect_vector_poisoning_case(case.payload)
    if technique_id == "SAF-T1106":
        return detect_autonomous_loop_case(case.payload)
    if technique_id == "SAF-T1109":
        return detect_inspector_rce_case(case.payload)
    if technique_id == "SAF-T1202":
        return detect_oauth_token_persistence_case(case.payload)
    if technique_id == "SAF-T1203":
        return detect_backdoored_install_case(case.payload)
    if technique_id == "SAF-T1204":
        return detect_context_memory_implant_case(case.payload)
    return False


def evaluate_technique(technique_id: str) -> ParityResult:
    cases = load_cases(technique_id)
    false_positives: list[str] = []
    false_negatives: list[str] = []
    correct = 0

    for case in cases:
        detected = detect_case(technique_id, case)
        if detected == case.expect:
            correct += 1
        elif detected and not case.expect:
            false_positives.append(case.case_id)
        else:
            false_negatives.append(case.case_id)

    return ParityResult(
        technique_id=technique_id,
        total=len(cases),
        correct=correct,
        false_positives=false_positives,
        false_negatives=false_negatives,
    )


def parity_summary() -> list[ParityResult]:
    results: list[ParityResult] = []
    if not FIXTURES_ROOT.exists():
        return results
    for technique_dir in sorted(FIXTURES_ROOT.iterdir()):
        if not technique_dir.is_dir():
            continue
        if not (technique_dir / "test-logs.json").exists():
            continue
        if not (technique_dir / "expected.json").exists():
            continue
        results.append(evaluate_technique(technique_dir.name))
    return results


def write_parity_report(path: Path) -> list[ParityResult]:
    summary = parity_summary()
    payload = {
        "threshold_pct": PARITY_THRESHOLD,
        "techniques": [row.to_dict() for row in summary],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return summary
