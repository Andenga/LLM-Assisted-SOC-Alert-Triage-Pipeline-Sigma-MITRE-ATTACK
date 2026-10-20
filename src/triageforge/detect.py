import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from .models import Alert

# Only keep fields useful for triage (keeps LLM prompts small and cheap)
KEEP_FIELDS = [
    "Image", "CommandLine", "ParentImage", "ParentCommandLine", "User",
    "OriginalFileName", "CurrentDirectory", "Hashes",
    "TargetFilename", "TargetObject", "Details",
    "SourceIp", "DestinationIp", "DestinationPort",
    "NewProcessName", "ProcessName", "SubjectUserName", "TargetUserName",
    "LogonType", "IpAddress", "ServiceName", "ImagePath", "ScriptBlockText",
]
MAX_FIELD_LEN = 2000  # truncate giant command lines / scripts


def _parse_ts(ts):
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _event_id(system):
    eid = system.get("EventID")
    if isinstance(eid, dict):
        eid = eid.get("#text")
    return eid


def _to_alert(det: dict) -> Alert:
    doc = det.get("document", {})
    if isinstance(doc, list):          # aggregate detections can be lists
        doc = doc[0] if doc else {}
    data = doc.get("data", {}) or {}
    event = data.get("Event", data)
    system = event.get("System", {}) or {}
    edata = event.get("EventData", {}) or {}

    fields = {}
    for key in KEEP_FIELDS:
        if key in edata and edata[key] not in (None, ""):
            fields[key] = str(edata[key])[:MAX_FIELD_LEN]
    fields["EventID"] = _event_id(system)
    fields["Channel"] = system.get("Channel")

    ts = det.get("timestamp") or system.get("TimeCreated_attributes", {}).get("SystemTime", "")

    return Alert(
        alert_id="TMP",
        timestamp=str(ts),
        host=str(system.get("Computer", "unknown")),
        rule_title=det.get("name", "unknown rule"),
        rule_level=str(det.get("level", "medium")).lower(),
        rule_tags=det.get("tags", []) or [],
        fields=fields,
        source_file=Path(doc.get("path", "unknown")).name,
    )


def dedupe(alerts: list[Alert], window_seconds: int = 60) -> list[Alert]:
    """Merge alerts with same rule+host+file that occur within window_seconds."""
    groups = defaultdict(list)
    for a in alerts:
        groups[(a.rule_title, a.host, a.source_file)].append(a)

    out = []
    for items in groups.values():
        items.sort(key=lambda a: a.timestamp)
        current, count = items[0], 1
        last = _parse_ts(current.timestamp)
        for nxt in items[1:]:
            t = _parse_ts(nxt.timestamp)
            if last and t and (t - last).total_seconds() <= window_seconds:
                count += 1
                last = t
            else:
                current.fields["duplicate_count"] = count
                out.append(current)
                current, count, last = nxt, 1, t
        current.fields["duplicate_count"] = count
        out.append(current)

    out.sort(key=lambda a: a.timestamp)
    for i, a in enumerate(out, 1):
        a.alert_id = f"A{i:04d}"
    return out


def load_alerts(path: str, dedup: bool = True) -> list[Alert]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = [data]
    alerts = [_to_alert(d) for d in data]
    return dedupe(alerts) if dedup else alerts


if __name__ == "__main__":
    from collections import Counter

    raw = load_alerts("data/alerts/attack_alerts.json", dedup=False)
    clean = load_alerts("data/alerts/attack_alerts.json")
    print(f"Raw alerts: {len(raw)}  |  After de-duplication: {len(clean)}")
    print("By level:", dict(Counter(a.rule_level for a in clean)))
    print("\nFirst three:")
    for a in clean[:3]:
        print(a.model_dump_json(indent=2))
    Path("data/alerts/alerts_clean.json").write_text(
        json.dumps([a.model_dump() for a in clean], indent=2), encoding="utf-8"
    )
    print("\nSaved data/alerts/alerts_clean.json")