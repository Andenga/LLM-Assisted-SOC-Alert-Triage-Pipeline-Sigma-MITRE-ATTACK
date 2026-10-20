from triageforge.detect import load_alerts
from triageforge.enrich import load_attack, load_assets, enrich_all, to_context

alerts = load_alerts("data/alerts/attack_alerts.json")
techniques = load_attack()
assets = load_assets()
enriched = enrich_all(alerts, techniques, assets)

print(f"Valid ATT&CK technique IDs loaded: {len(techniques)}")
print(f"Alerts: {len(enriched)}")
mapped = sum(1 for e in enriched if e.techniques)
unknown = sum(len(e.unknown_technique_ids) for e in enriched)
print(f"Alerts with >=1 technique mapped: {mapped}/{len(enriched)}; unknown IDs: {unknown}")
print("\n--- Example context ---\n")
print(to_context(enriched[0]))