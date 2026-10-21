import re


def sanitize(value, max_len=1500):
    """Clean one field value before it reaches the LLM."""
    value = "".join(ch for ch in str(value) if ch.isprintable() or ch in "\n\t")
    # Stop attackers closing our <alert_data> wrapper early
    value = re.sub(r"</?\s*alert_data\s*>", "[alert_data-tag-removed]", value, flags=re.IGNORECASE)
    return value[:max_len]


def sanitize_alert(enriched):
    """Return a copy of an EnrichedAlert with every field value sanitized."""
    clean = enriched.model_copy(deep=True)
    clean.alert.fields = {k: sanitize(v) for k, v in clean.alert.fields.items()}
    return clean


def validate(verdict, alert_text, valid_ids):
    """Check a verdict against the alert it came from."""
    problems = []
    if verdict.technique_id and verdict.technique_id not in valid_ids:
        problems.append("invalid_technique_id")
    for e in verdict.evidence:
        if e not in alert_text:
            problems.append("evidence_not_in_alert")
            break
    return problems


def problems_from_stats(stats):
    """Same checks, read from the stats that run_triage() already computed."""
    problems = []
    if stats.get("parse_failed"):
        problems.append("parse_failed")
    if stats.get("invalid_technique"):
        problems.append("invalid_technique_id")
    if stats.get("evidence_found", 0) < stats.get("evidence_total", 0):
        problems.append("evidence_not_in_alert")
    return problems