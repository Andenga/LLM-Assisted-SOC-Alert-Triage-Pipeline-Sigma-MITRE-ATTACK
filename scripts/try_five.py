import json
import statistics

import requests

from triageforge.detect import load_alerts
from triageforge.enrich import load_attack, load_assets, enrich_all, to_context
from triageforge.triage import run_triage, triage_local

# ---- Choose your models here ----
# One model to start. To compare two, first run: ollama pull llama3.2:3b
# then remove the # from the second line.
providers = {
    "llama3.1:8b": lambda ctx: triage_local(ctx, model="llama3.1:8b"),
    # "llama3.2:3b": lambda ctx: triage_local(ctx, model="llama3.2:3b"),
}

alerts = load_alerts("data/alerts/attack_alerts.json")
techniques = load_attack()
enriched = enrich_all(alerts, techniques, load_assets())

# Pick 5 alerts from 5 DIFFERENT rules for variety
picked, seen = [], set()
for e in enriched:
    if e.alert.rule_title not in seen:
        seen.add(e.alert.rule_title)
        picked.append(e)
    if len(picked) == 5:
        break

# Warm-up: load each model into memory so timings are fair
for name in providers:
    print(f"Warming up {name} ...")
    try:
        requests.post(
            "http://localhost:11434/api/chat",
            timeout=300,
            json={"model": name, "stream": False,
                  "messages": [{"role": "user", "content": "hi"}]},
        )
    except Exception as ex:
        print(f"  Warm-up failed for {name}: {ex}")

results = []
for e in picked:
    ctx = to_context(e)
    print("=" * 70)
    print(ctx[:800])
    for name, fn in providers.items():
        v, s = run_triage(fn, ctx, techniques)
        print(f"\n[{name}] {v.verdict} (conf {v.confidence}) severity={v.severity} "
              f"technique={v.technique_id} review={v.needs_human_review}")
        print("  reasoning:", v.reasoning)
        print("  actions:", v.recommended_actions)
        print("  stats:", {k: (round(x, 2) if isinstance(x, float) else x) for k, x in s.items()})
        results.append({
            "alert_id": e.alert.alert_id,
            "provider": name,
            "verdict": v.model_dump(),
            "stats": s,
        })

with open("eval/results/try_five.jsonl", "w", encoding="utf-8") as f:
    for r in results:
        f.write(json.dumps(r) + "\n")

print("\n" + "=" * 70)
print("SUMMARY")
for name in providers:
    rs = [r for r in results if r["provider"] == name]
    if not rs:
        continue
    print(f"{name}: median sec {statistics.median(r['stats']['seconds'] for r in rs):.1f}, "
          f"avg in tokens {statistics.mean(r['stats']['in_tokens'] for r in rs):.0f}, "
          f"avg out tokens {statistics.mean(r['stats']['out_tokens'] for r in rs):.0f}, "
          f"parse failures {sum(r['stats']['parse_failed'] for r in rs)}/{len(rs)}, "
          f"invalid techniques {sum(r['stats']['invalid_technique'] for r in rs)}, "
          f"evidence found {sum(r['stats']['evidence_found'] for r in rs)}/"
          f"{sum(r['stats']['evidence_total'] for r in rs)}")