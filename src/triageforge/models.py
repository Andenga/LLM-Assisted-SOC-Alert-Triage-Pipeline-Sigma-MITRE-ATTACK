from pydantic import BaseModel
from typing import Literal


class Alert(BaseModel):
    alert_id: str
    timestamp: str
    host: str
    rule_title: str
    rule_level: str          # low / medium / high / critical
    rule_tags: list[str]     # e.g. ["attack.t1059.001"]
    fields: dict             # process, command line, user, etc.
    source_file: str         # which log file it came from (used for labeling)


class TriageVerdict(BaseModel):
    verdict: Literal["likely_malicious", "suspicious", "likely_benign"]
    confidence: float
    technique_id: str | None = None
    severity: Literal["low", "medium", "high", "critical"]
    evidence: list[str]
    reasoning: str
    recommended_actions: list[str]
    needs_human_review: bool