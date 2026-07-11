"""Tests for AttackMapServer message shaping: lean Traffic events, Stats passthrough."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "AttackMapServer"))

import AttackMapServer as ams  # noqa: E402


def traffic_payload():
    return {
        "msg_type": "Traffic",
        "protocol": "SSH",
        "src_ip": "1.2.3.4",
        "dst_ip": "0.0.0.0",
        "src_port": "4444",
        "dst_port": "22",
        "city": "Paris",
        "country": "France",
        "iso_code": "FR",
        "latitude": 48.85,
        "longitude": 2.35,
        "dst_lat": 52.35,
        "dst_long": 4.74,
        "event_time": "11-07-2026 10:00:00",
    }


def test_shape_traffic_message_maps_coords_and_color():
    msg = ams.shape_message(traffic_payload())
    assert msg["type"] == "Traffic"
    assert msg["src_lat"] == 48.85
    assert msg["src_long"] == 2.35
    assert msg["dst_lat"] == 52.35
    assert msg["dst_long"] == 4.74
    assert msg["color"] == ams.SERVICE_RGB["SSH"]
    assert msg["src_ip"] == "1.2.3.4"
    assert msg["iso_code"] == "FR"


def test_shape_traffic_message_drops_tallies():
    payload = traffic_payload()
    payload["ips_tracked"] = {"1.2.3.4": 9}
    payload["countries_tracked"] = {"France": 9}
    msg = ams.shape_message(payload)
    assert "ips_tracked" not in msg
    assert "countries_tracked" not in msg


def test_shape_stats_message_passes_through():
    payload = {
        "msg_type": "Stats",
        "event_count": 7,
        "unique_ips": 3,
        "unique_countries": 2,
        "top_countries": [{"label": "France", "count": 5, "code": "FR"}],
        "top_sources": [{"label": "1.2.3.4", "count": 5, "code": "FR"}],
    }
    msg = ams.shape_message(payload)
    assert msg["type"] == "Stats"
    assert msg["event_count"] == 7
    assert msg["top_countries"][0]["label"] == "France"
