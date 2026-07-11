"""Tests for the throttled Stats message and the tracked-IP cap.

Events no longer carry the full running tallies; instead DataServer
periodically publishes a compact Stats message with pre-ranked top-N lists,
and prunes ips_tracked so memory stays bounded.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "DataServer"))

import DataServer as ds  # noqa: E402


def test_build_stats_message_ranks_top_entries(monkeypatch):
    monkeypatch.setattr(ds, "event_count", 42)
    monkeypatch.setattr(ds, "countries_tracked", {"France": 5, "China": 9, "Peru": 1})
    monkeypatch.setattr(ds, "ips_tracked", {"1.1.1.1": 3, "2.2.2.2": 7})
    monkeypatch.setattr(ds, "country_to_code", {"France": "FR", "China": "CN", "Peru": "PE"})
    monkeypatch.setattr(ds, "ip_to_code", {"1.1.1.1": "AU", "2.2.2.2": "FR"})
    monkeypatch.setattr(ds, "unknowns", {"country": 2})

    msg = ds.build_stats_message()

    assert msg["msg_type"] == "Stats"
    assert msg["event_count"] == 42
    assert msg["unique_ips"] == 2
    assert msg["unique_countries"] == 3
    assert msg["top_countries"][0] == {"label": "China", "count": 9, "code": "CN"}
    assert [c["label"] for c in msg["top_countries"]] == ["China", "France", "Peru"]
    assert msg["top_sources"] == [
        {"label": "2.2.2.2", "count": 7, "code": "FR"},
        {"label": "1.1.1.1", "count": 3, "code": "AU"},
    ]


def test_build_stats_message_limits_list_length(monkeypatch):
    monkeypatch.setattr(ds, "ips_tracked", {f"10.0.0.{i}": i for i in range(50)})
    monkeypatch.setattr(ds, "ip_to_code", {})
    msg = ds.build_stats_message()
    assert len(msg["top_sources"]) == ds.STATS_TOP_N
    # highest counts first
    assert msg["top_sources"][0]["count"] == 49


def test_prune_tracked_ips_keeps_highest_counts(monkeypatch):
    ips = {f"10.0.0.{i}": i for i in range(100)}  # counts 0..99
    codes = {ip: "US" for ip in ips}
    monkeypatch.setattr(ds, "ips_tracked", ips)
    monkeypatch.setattr(ds, "ip_to_code", codes)

    ds.prune_tracked_ips(cap=50)

    assert len(ds.ips_tracked) == 25  # pruned to half the cap
    assert min(ds.ips_tracked.values()) == 75  # the top counts survive
    assert set(ds.ip_to_code) == set(ds.ips_tracked)  # codes pruned in lockstep


def test_prune_tracked_ips_noop_under_cap(monkeypatch):
    ips = {"1.1.1.1": 5}
    monkeypatch.setattr(ds, "ips_tracked", ips)
    monkeypatch.setattr(ds, "ip_to_code", {"1.1.1.1": "AU"})
    ds.prune_tracked_ips(cap=50)
    assert ds.ips_tracked == {"1.1.1.1": 5}
