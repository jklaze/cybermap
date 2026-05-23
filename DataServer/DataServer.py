#!/usr/bin/env python3
"""
Tails one or more syslog files, parses attack events using a declarative
regex config, geolocates the source IP against the MaxMind GeoLite2-City
database, and publishes the result to Redis.

Configuration is via environment variables:
  REDIS_HOST          (default 127.0.0.1)
  REDIS_PORT          (default 6379)
  REDIS_CHANNEL       (default attack-map-production)
  SYSLOG_PATHS        Comma-separated list of files to tail.
                      Falls back to SYSLOG_PATH if unset.
  SYSLOG_PATH         (default /var/log/attack-map/syslog)
  PARSERS_PATH        (default /etc/cybermap/parsers.yml)
  GEOIP_DB_PATH       (default /geoip/GeoLite2-City.mmdb)
  HQ_IP               (default 8.8.8.8)
  TAIL_POLL_INTERVAL  (default 0.1)
"""

import fnmatch
import io
import json
import logging
import os
import queue
import re
import signal
import sys
import threading
from time import localtime, sleep, strftime

import maxminddb
import redis
import yaml

from const import META, PORTMAP

REDIS_HOST = os.environ.get("REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))
REDIS_CHANNEL = os.environ.get("REDIS_CHANNEL", "attack-map-production")
SYSLOG_PATH = os.environ.get("SYSLOG_PATH", "/var/log/attack-map/syslog")
SYSLOG_PATHS = [
    p.strip()
    for p in os.environ.get("SYSLOG_PATHS", "").split(",")
    if p.strip()
] or [SYSLOG_PATH]
PARSERS_PATH = os.environ.get("PARSERS_PATH", "/etc/cybermap/parsers.yml")
GEOIP_DB_PATH = os.environ.get("GEOIP_DB_PATH", "/geoip/GeoLite2-City.mmdb")
HQ_IP = os.environ.get("HQ_IP", "8.8.8.8")
TAIL_POLL_INTERVAL = float(os.environ.get("TAIL_POLL_INTERVAL", "0.1"))

REQUIRED_FIELDS = ("src_ip", "dst_ip", "src_port", "dst_port", "type_attack", "cve_attack")

# Built-in named formats: a user writes `format: <name>` in parsers.yml
# instead of authoring a regex. Each entry's `regex` uses named groups for
# whatever it can pull out of the line; the rest comes from `defaults`.
BUILTIN_FORMATS = {
    # Synthetic generator used by syslog-gen.py.
    "demo-csv": {
        "regex": r"(?P<src_ip>[^,\s]+),(?P<dst_ip>[^,\s]+),(?P<src_port>\d+),(?P<dst_port>\d+),(?P<type_attack>[^,\s]+),(?P<cve_attack>[^,\s]+)\s*$",
        "defaults": {},
    },
    # Linux sshd "Failed password" lines (Debian /var/log/auth.log,
    # RHEL /var/log/secure). Optional "invalid user" prefix handled.
    "sshd-auth": {
        "regex": r"sshd\[\d+\]:\s+Failed password for (?:invalid user )?\S+ from (?P<src_ip>\S+) port (?P<src_port>\d+)",
        "defaults": {
            "dst_ip": "0.0.0.0",
            "dst_port": "22",
            "type_attack": "ssh-bruteforce",
            "cve_attack": "N/A",
        },
    },
    # UFW firewall BLOCK lines (TCP/UDP). ICMP-only blocks lack SPT/DPT
    # and will not match — that's intentional.
    "ufw": {
        "regex": r"\[UFW BLOCK\].*SRC=(?P<src_ip>\S+).*DST=(?P<dst_ip>\S+).*PROTO=(?P<type_attack>\S+).*SPT=(?P<src_port>\d+).*DPT=(?P<dst_port>\d+)",
        "defaults": {"cve_attack": "N/A"},
    },
    # nginx "combined" access log (the default for most distros).
    "nginx-access": {
        "regex": r'^(?P<src_ip>\S+) \S+ \S+ \[[^\]]+\] "(?P<type_attack>\S+) [^"]*" \d+ \d+',
        "defaults": {
            "dst_ip": "0.0.0.0",
            "src_port": "0",
            "dst_port": "80",
            "cve_attack": "N/A",
        },
    },
    # Apache "combined" access log (same shape as nginx-combined).
    "apache-access": {
        "regex": r'^(?P<src_ip>\S+) \S+ \S+ \[[^\]]+\] "(?P<type_attack>\S+) [^"]*" \d+ \d+',
        "defaults": {
            "dst_ip": "0.0.0.0",
            "src_port": "0",
            "dst_port": "80",
            "cve_attack": "N/A",
        },
    },
    # fail2ban "Ban <ip>" action lines.
    "fail2ban": {
        "regex": r"fail2ban\.actions.*\[(?P<type_attack>[^\]]+)\] Ban (?P<src_ip>\S+)",
        "defaults": {
            "dst_ip": "0.0.0.0",
            "src_port": "0",
            "dst_port": "0",
            "cve_attack": "N/A",
        },
    },
}

log = logging.getLogger("data-server")

event_count = 0
continents_tracked: dict = {}
countries_tracked: dict = {}
ips_tracked: dict = {}
country_to_code: dict = {}
ip_to_code: dict = {}
unknowns: dict = {}


class Parser:
    __slots__ = ("name", "match", "regex", "defaults")

    def __init__(self, name: str, match: str, regex: str, defaults: dict):
        self.name = name
        self.match = match
        self.regex = re.compile(regex)
        self.defaults = defaults


def load_parsers(path: str) -> list:
    """Load and compile parser rules from a YAML file.

    Each entry must have `match:` plus either `format:` (a built-in name from
    BUILTIN_FORMATS) or `regex:` (a custom pattern with named groups). User
    `defaults:` are merged on top of the built-in defaults when using `format:`.
    """
    with open(path) as f:
        data = yaml.safe_load(f) or []
    if not isinstance(data, list):
        log.error("%s must contain a YAML list at the top level", path)
        sys.exit(1)
    parsers = []
    for i, entry in enumerate(data):
        try:
            match = entry["match"]
            user_defaults = entry.get("defaults") or {}

            if "format" in entry and "regex" in entry:
                log.error("parsers.yml entry #%d: use either `format:` or `regex:`, not both", i)
                sys.exit(1)

            if "format" in entry:
                fmt_name = entry["format"]
                fmt = BUILTIN_FORMATS.get(fmt_name)
                if not fmt:
                    log.error(
                        "parsers.yml entry #%d: unknown format %r (available: %s)",
                        i, fmt_name, sorted(BUILTIN_FORMATS),
                    )
                    sys.exit(1)
                regex = fmt["regex"]
                defaults = {**fmt["defaults"], **user_defaults}
                name = entry.get("name", fmt_name)
            elif "regex" in entry:
                regex = entry["regex"]
                defaults = user_defaults
                name = entry.get("name", f"parser-{i}")
            else:
                log.error("parsers.yml entry #%d: must specify `format:` or `regex:`", i)
                sys.exit(1)

            parsers.append(Parser(name=name, match=match, regex=regex, defaults=defaults))
        except (KeyError, re.error) as exc:
            log.error("invalid parser entry #%d in %s: %s", i, path, exc)
            sys.exit(1)
    if not parsers:
        log.error("no parsers defined in %s", path)
        sys.exit(1)
    log.info("loaded %d parser(s) from %s", len(parsers), path)
    return parsers


def parse_line(source_path: str, line: str, parsers: list):
    """Apply parsers in order. First entry that matches the source and produces all six fields wins."""
    for p in parsers:
        if not fnmatch.fnmatch(source_path, p.match):
            continue
        m = p.regex.search(line)
        if not m:
            continue
        out = dict(p.defaults)
        out.update({k: v for k, v in m.groupdict().items() if v is not None})
        if all(out.get(f) is not None for f in REQUIRED_FIELDS):
            return {f: out[f] for f in REQUIRED_FIELDS}
    return None


def clean_db(unclean: dict) -> dict:
    """Flatten the nested MaxMind response into the flat dict the rest of the pipeline expects."""
    selected = {}
    for tag in META:
        head = unclean.get(tag["tag"])
        for node in tag["path"]:
            if isinstance(head, dict) and node in head:
                head = head[node]
            else:
                head = None
                break
        selected[tag["lookup"]] = head
    return selected


def get_tcp_udp_proto(src_port, dst_port) -> str:
    try:
        src_port = int(src_port)
        dst_port = int(dst_port)
    except (TypeError, ValueError):
        return "OTHER"
    if src_port in PORTMAP:
        return PORTMAP[src_port]
    if dst_port in PORTMAP:
        return PORTMAP[dst_port]
    return "OTHER"


def lookup_ip(reader, ip: str):
    try:
        return reader.get(ip)
    except ValueError:
        return None


def find_hq_lat_long(reader, hq_ip: str) -> dict:
    raw = lookup_ip(reader, hq_ip)
    if not raw:
        log.error("Could not geolocate HQ IP %s - aborting", hq_ip)
        sys.exit(1)
    flat = clean_db(raw)
    return {"dst_lat": flat["latitude"], "dst_long": flat["longitude"]}


def merge_dicts(*args) -> dict:
    out = {}
    for arg in args:
        out.update(arg)
    return out


def track_flag(super_dict: dict, store: dict, key1: str, key2: str) -> None:
    val1 = super_dict.get(key1)
    val2 = super_dict.get(key2)
    if val1 is not None and val2 is not None and val1 not in store:
        store[val1] = val2


def track_stat(super_dict: dict, store: dict, key: str) -> None:
    node = super_dict.get(key)
    if node is None:
        unknowns[key] = unknowns.get(key, 0) + 1
        return
    store[node] = store.get(node, 0) + 1


def wait_for_file(path: str, what: str) -> None:
    """Block until `path` exists. Other services in the compose stack create these at startup."""
    logged = False
    while not os.path.exists(path):
        if not logged:
            log.info("waiting for %s at %s", what, path)
            logged = True
        sleep(1)


def connect_redis() -> "redis.Redis":
    while True:
        try:
            client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)
            client.ping()
            log.info("connected to redis at %s:%d", REDIS_HOST, REDIS_PORT)
            return client
        except redis.exceptions.RedisError as exc:
            log.warning("redis not ready (%s); retrying in 2s", exc)
            sleep(2)


def tail(path: str):
    """Yield lines appended to `path`, starting from EOF."""
    with io.open(path, "r", encoding="ISO-8859-1") as f:
        f.seek(0, io.SEEK_END)
        while True:
            where = f.tell()
            line = f.readline()
            if not line:
                sleep(TAIL_POLL_INTERVAL)
                f.seek(where)
                continue
            yield line


def tail_all(paths: list):
    """Yield (source_path, line) tuples from a shared queue fed by one tail thread per file."""
    q: queue.Queue = queue.Queue(maxsize=10_000)

    def worker(p: str) -> None:
        for line in tail(p):
            q.put((p, line))

    for p in paths:
        wait_for_file(p, "syslog input file")
        threading.Thread(target=worker, args=(p,), daemon=True).start()
        log.info("tailing %s", p)

    while True:
        yield q.get()


def report_stats() -> None:
    log.info("event_count=%d", event_count)
    log.info("continents=%s", continents_tracked)
    log.info("countries=%s", countries_tracked)
    log.info("ips=%d unique", len(ips_tracked))
    log.info("unknowns=%s", unknowns)


def install_signal_handlers() -> None:
    def _stop(signum, _frame):
        log.info("received signal %d", signum)
        report_stats()
        sys.exit(0)
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)


def main() -> None:
    global event_count
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    install_signal_handlers()

    wait_for_file(GEOIP_DB_PATH, "GeoLite2 database")
    wait_for_file(PARSERS_PATH, "parser config")
    parsers = load_parsers(PARSERS_PATH)

    reader = maxminddb.open_database(GEOIP_DB_PATH)
    hq_dict = find_hq_lat_long(reader, HQ_IP)

    r = connect_redis()
    log.info("publishing to channel %s", REDIS_CHANNEL)

    for source_path, line in tail_all(SYSLOG_PATHS):
        parsed = parse_line(source_path, line, parsers)
        if not parsed:
            continue

        raw_geo = lookup_ip(reader, parsed["src_ip"])
        if not raw_geo:
            continue

        event_count += 1
        flat_geo = clean_db(raw_geo)
        proto = get_tcp_udp_proto(parsed["src_port"], parsed["dst_port"])

        super_dict = merge_dicts(
            hq_dict,
            flat_geo,
            {"msg_type": "Traffic"},
            {"msg_type2": parsed["type_attack"]},
            {"msg_type3": parsed["cve_attack"]},
            {"protocol": proto},
            parsed,
        )

        track_stat(super_dict, continents_tracked, "continent")
        track_stat(super_dict, countries_tracked, "country")
        track_stat(super_dict, ips_tracked, "src_ip")
        track_flag(super_dict, country_to_code, "country", "iso_code")
        track_flag(super_dict, ip_to_code, "src_ip", "iso_code")

        super_dict["event_count"] = event_count
        super_dict["continents_tracked"] = continents_tracked
        super_dict["countries_tracked"] = countries_tracked
        super_dict["ips_tracked"] = ips_tracked
        super_dict["unknowns"] = unknowns
        super_dict["event_time"] = strftime("%d-%m-%Y %H:%M:%S", localtime())
        super_dict["country_to_code"] = country_to_code
        super_dict["ip_to_code"] = ip_to_code

        r.publish(REDIS_CHANNEL, json.dumps(super_dict))

        if event_count % 50 == 0:
            log.info("published %d events", event_count)


if __name__ == "__main__":
    main()
