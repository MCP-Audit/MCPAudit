"""RAG backdoor trigger with skewed retrieval (MCTS-T-1060)."""

from __future__ import annotations

from typing import Any


def detect_rag_backdoor(event: dict[str, Any]) -> bool:
    """Detect rare trigger n-grams paired with skewed retrieval and policy violations."""
    if (
        event.get("policy_violation")
        and float(event.get("top_domain_share") or 0) >= 0.6
        and float(event.get("topk_entropy") or 1.0) <= 0.9
    ):
        return True
    trigger = str(event.get("trigger_ngram") or event.get("prompt") or "")
    if (
        trigger
        and event.get("trigger_rarity_score") is not None
        and float(event["trigger_rarity_score"]) <= 0.05
        and float(event.get("top_domain_share") or 0) >= 0.6
    ):
        return True
    domains = event.get("retrieved_domains") or event.get("top_domains")
    if isinstance(domains, list) and len(domains) >= 2:
        counts: dict[str, int] = {}
        for domain in domains:
            counts[str(domain)] = counts.get(str(domain), 0) + 1
        total = sum(counts.values())
        if (
            total
            and max(counts.values()) / total >= 0.6
            and (event.get("policy_violation") or event.get("safety_filter_bypassed"))
        ):
            return True
    return bool(event.get("rag_backdoor_detected"))
