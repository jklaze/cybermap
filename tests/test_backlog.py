"""Initial-load backlog: data-server keeps recent events in Redis; new clients get them first."""

import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "DataServer"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "AttackMapServer"))

import AttackMapServer as ams  # noqa: E402
import DataServer as ds  # noqa: E402


class FakeSyncRedis:
    def __init__(self):
        self.lists = {}

    def pipeline(self, transaction=True):
        return self

    def lpush(self, key, value):
        self.lists.setdefault(key, []).insert(0, value)

    def ltrim(self, key, start, end):
        self.lists[key] = self.lists[key][start:end + 1]

    def execute(self):
        return []


def test_remember_recent_keeps_newest_n_per_kind(monkeypatch):
    monkeypatch.setattr(ds, "RECENT_EVENTS", 3)
    r = FakeSyncRedis()
    for i in range(5):
        ds.remember_recent(r, f"attack{i}", scan=False)
    ds.remember_recent(r, "scan0", scan=True)
    assert r.lists[ds.RECENT_KEY] == ["attack4", "attack3", "attack2"]
    assert r.lists[ds.RECENT_SCANS_KEY] == ["scan0"]


def _traffic(ip, protocol="SSH"):
    return json.dumps({"msg_type": "Traffic", "protocol": protocol, "src_ip": ip, "dst_port": "22"})


class FakeAsyncRedis:
    def __init__(self, data):
        self.data = data

    def pipeline(self, transaction=True):
        outer = self

        class Pipe:
            def __init__(self):
                self.calls = []

            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            def lrange(self, key, *_):
                self.calls.append(outer.data.get(key, []))

            def get(self, key):
                self.calls.append(outer.data.get(key))

            async def execute(self):
                return self.calls

        return Pipe()

    async def aclose(self):
        pass


class FakeClient:
    def __init__(self):
        self.sent = []

    def write_message(self, msg):
        self.sent.append(json.loads(msg))


def test_welcome_sends_backlog_oldest_first_then_joins_live(monkeypatch):
    ch = "attack-map-production"
    data = {
        f"{ch}:recent": [_traffic("3.3.3.3"), _traffic("2.2.2.2")],  # newest first
        f"{ch}:recent-scans": [_traffic("9.9.9.9", "SCAN")],
        f"{ch}:stats": json.dumps({"msg_type": "Stats", "event_count": 42}),
    }
    monkeypatch.setattr(ams.redis, "from_url", lambda *a, **k: FakeAsyncRedis(data))
    hub = ams.ClientHub("redis://x", ch)
    client = FakeClient()
    asyncio.run(hub.welcome(client))

    traffic = [m for m in client.sent if m["type"] == "Traffic"]
    assert [m["src_ip"] for m in traffic] == ["9.9.9.9", "2.2.2.2", "3.3.3.3"]
    assert all(m["replay"] for m in traffic)
    assert client.sent[-1]["type"] == "Stats" and client.sent[-1]["event_count"] == 42
    assert client in hub._clients


def test_welcome_survives_redis_errors(monkeypatch):
    def boom(*a, **k):
        raise ConnectionError("down")

    monkeypatch.setattr(ams.redis, "from_url", boom)
    hub = ams.ClientHub("redis://x", "c")
    client = FakeClient()
    asyncio.run(hub.welcome(client))
    assert client.sent == [] and client in hub._clients
