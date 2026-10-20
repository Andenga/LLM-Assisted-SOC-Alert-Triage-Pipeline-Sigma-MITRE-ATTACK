from triageforge.detect import dedupe
from triageforge.models import Alert


def make(ts):
    return Alert(alert_id="x", timestamp=ts, host="H", rule_title="R",
                 rule_level="high", rule_tags=[], fields={}, source_file="f.evtx")


def test_dedupe_merges_close_alerts():
    out = dedupe([make("2024-01-01T00:00:00Z"),
                  make("2024-01-01T00:00:30Z"),
                  make("2024-01-01T01:00:00Z")])
    assert len(out) == 2
    assert out[0].fields["duplicate_count"] == 2