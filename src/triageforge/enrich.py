import json
from collections import Counter
import yaml
from pydantic import BaseModel
from .models import Alert


class EnrichedAlert(BaseModel):
    alert: Alert
    techniques: list[dict]          # [{"id","name","tactics","description"}]
    unknown_technique_ids: list[str]
    asset_criticality: str
    rule_host_count: int            # how often this rule fired on this host


def load_attack(path="data/attack/enterprise-attack.json"):
    data = json.load(open(path, encoding="utf-8"))
    techniques = {}
    for o in data["objects"]:
        if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        for ref in o.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                techniques[ref["external_id"]] = {
                    "name": o["name"],
                    "tactics": [p["phase_name"] for p in o.get("kill_chain_phases", [])],
                    "description": o.get("description", "")[:600],
                }
    return techniques


def technique_ids_from_tags(tags):
    """attack.t1059.001 -> T1059.001"""
    return [t.split("attack.")[1].upper() for t in tags
            if t.startswith("attack.t") and t[8:9].isdigit()]


def load_assets(path="data/assets.yaml"):
    return yaml.safe_load(open(path, encoding="utf-8"))


def enrich_all(alerts, techniques, assets):
    freq = Counter((a.rule_title, a.host) for a in alerts)
    out = []
    for a in alerts:
        found, unknown = [], []
        for tid in technique_ids_from_tags(a.rule_tags):
            info = techniques.get(tid) or techniques.get(tid.split(".")[0])
            if info:
                found.append({"id": tid, **info})
            else:
                unknown.append(tid)
        crit = assets.get("hosts", {}).get(a.host, assets.get("default", "medium"))
        out.append(EnrichedAlert(alert=a, techniques=found, unknown_technique_ids=unknown,
                                 asset_criticality=crit,
                                 rule_host_count=freq[(a.rule_title, a.host)]))
    return out


def to_context(e: EnrichedAlert, max_val=1200) -> str:
    """Text shown to the LLM. NOTE: source_file is deliberately excluded
    because file names like 'T1059_powershell.evtx' leak the answer."""
    a = e.alert
    lines = [
        f"alert_id: {a.alert_id}",
        f"timestamp: {a.timestamp}",
        f"host: {a.host}",
        f"asset_criticality: {e.asset_criticality}",
        f"rule_title: {a.rule_title}",
        f"rule_level: {a.rule_level}",
        f"times_this_rule_fired_on_this_host: {e.rule_host_count}",
    ]
    for t in e.techniques:
        lines.append(f"attack_technique: {t['id']} {t['name']} (tactics: {', '.join(t['tactics'])})")
        lines.append(f"attack_description: {t['description']}")
    lines.append("event_fields:")
    for k, v in a.fields.items():
        lines.append(f"  {k}: {str(v)[:max_val]}")
    return "\n".join(lines)