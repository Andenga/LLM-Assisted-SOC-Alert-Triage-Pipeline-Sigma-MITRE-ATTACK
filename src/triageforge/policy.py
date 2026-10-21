def decide(verdict, rule_level, asset_criticality, problems):
    """Return 'escalate' (human looks) or 'deprioritize' (lower priority, never deleted)."""
    if problems or verdict.needs_human_review:
        return "escalate"
    if asset_criticality == "critical" or rule_level in ("high", "critical"):
        return "escalate"
    if verdict.verdict == "likely_benign" and verdict.confidence >= 0.85:
        return "deprioritize"
    return "escalate"