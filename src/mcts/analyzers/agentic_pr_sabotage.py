"""Malicious agent-authored pull request sabotage (MCTS-T-1065)."""

from __future__ import annotations

import re
from typing import Any

_PR_EVENTS = frozenset(
    {
        "pull_request.opened",
        "pull_request.synchronize",
        "pull_request.edited",
        "pull_request",
    }
)

_BOT_SUFFIXES = ("[bot]", "-bot", "-agent", "dependabot", "github-actions")
_SENSITIVE_PATH_MARKERS = (
    ".github/workflows/",
    ".gitlab-ci.yml",
    "jenkinsfile",
    "azure-pipelines.yml",
    "dockerfile",
    "k8s/",
    "infra/",
    "deploy/",
    "terraform/",
    "ansible/",
    "extensions/",
    "vs-code/",
    "vscode/",
)

_SUSPICIOUS_DIFF_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bcurl\s+", re.I),
    re.compile(r"\bwget\s+", re.I),
    re.compile(r"invoke-webrequest", re.I),
    re.compile(r"\bpowershell\b", re.I),
    re.compile(r"\bbash\s+-c\b", re.I),
    re.compile(r"\bsh\s+-c\b", re.I),
    re.compile(r"\bbase64\b", re.I),
    re.compile(r"\baws\s+s3\s+rm\b", re.I),
    re.compile(r"\baws\s+ec2\s+terminate-instances\b", re.I),
    re.compile(r"factory-state|delete.*file.?system", re.I),
)


def detect_agentic_pr_sabotage(event: dict[str, Any]) -> bool:
    """Detect bot/agent PRs touching CI/CD or infra with suspicious diffs."""
    event_type = str(event.get("event_type") or "").lower()
    if event_type not in _PR_EVENTS and "pull_request" not in event_type:
        return False

    actor = str(event.get("actor_login") or event.get("author") or "").lower()
    if not _is_bot_actor(actor):
        return False

    file_path = str(event.get("file_path") or event.get("path") or "").lower()
    if not any(marker in file_path for marker in _SENSITIVE_PATH_MARKERS):
        changed = event.get("changed_files") or event.get("files")
        if isinstance(changed, list):
            if not any(any(m in str(f).lower() for m in _SENSITIVE_PATH_MARKERS) for f in changed):
                return False
        else:
            return False

    diff = str(event.get("diff_added") or event.get("patch") or event.get("diff") or "")
    if diff and any(p.search(diff) for p in _SUSPICIOUS_DIFF_PATTERNS):
        return True

    title = str(event.get("pull_request_title") or event.get("title") or "").lower()
    if any(word in title for word in ("wip", "fix ci", "update workflow")) and diff:
        return any(p.search(diff) for p in _SUSPICIOUS_DIFF_PATTERNS[:6])

    return bool(event.get("agentic_pr_sabotage") or event.get("suspicious_agent_pr"))


def _is_bot_actor(actor: str) -> bool:
    if not actor:
        return False
    return any(actor.endswith(suffix) or suffix in actor for suffix in _BOT_SUFFIXES)
