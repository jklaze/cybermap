"""Test the pipeline stats summary line."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "DataServer"))

import DataServer as ds  # noqa: E402


def test_stats_summary_reports_all_counters(monkeypatch):
    monkeypatch.setattr(ds, "lines_read", 100)
    monkeypatch.setattr(ds, "event_count", 12)
    monkeypatch.setattr(ds, "parse_misses", 80)
    monkeypatch.setattr(ds, "ignored_count", 3)
    monkeypatch.setattr(ds, "geo_misses", 5)
    assert ds.stats_summary() == (
        "read=100 published=12 parse_miss=80 ignored=3 geo_miss=5"
    )
