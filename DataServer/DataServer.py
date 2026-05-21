#!/usr/bin/env python3
"""
Tails a syslog file, parses attack events, geolocates the source IP against
the MaxMind GeoLite2-City database, and publishes the result to Redis.

Configuration is via environment variables:
  REDIS_HOST          (default 127.0.0.1)
  REDIS_PORT          (default 6379)
  REDIS_CHANNEL       (default attack-map-production)
  SYSLOG_PATH         (default /var/log/attack-map/syslog)
  GEOIP_DB_PATH       (default /geoip/GeoLite2-City.mmdb)
  HQ_IP               (default 8.8.8.8)
  TAIL_POLL_INTERVAL  (default 0.1)
"""

import io
import json
import logging
import os
import signal
import sys
from time import localtime, sleep, strftime

import maxminddb
import redis

from const import META, PORTMAP

REDIS_HOST = os.environ.get("REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))
REDIS_CHANNEL = os.environ.get("REDIS_CHANNEL", "attack-map-production")
SYSLOG_PATH = os.environ.get("SYSLOG_PATH", "/var/log/attack-map/syslog")
GEOIP_DB_PATH = os.environ.get("GEOIP_DB_PATH", "/geoip/GeoLite2-City.mmdb")
HQ_IP = os.environ.get("HQ_IP", "8.8.8.8")
TAIL_POLL_INTERVAL = float(os.environ.get("TAIL_POLL_INTERVAL", "0.1"))

log = logging.getLogger("data-server")

event_count = 0
continents_tracked: dict = {}
countries_tracked: dict = {}
ips_tracked: dict = {}
country_to_code: dict = {}
ip_to_code: dict = {}
unknowns: dict = {}


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


def parse_syslog(line: str):
    """Default parser for the `src_ip,dst_ip,src_port,dst_port,type,cve` demo format."""
    parts = line.split()
    if not parts:
        return None
    fields = parts[-1].split(",")
    if len(fields) != 6:
        return None
    return {
        "src_ip": fields[0],
        "dst_ip": fields[1],
        "src_port": fields[2],
        "dst_port": fields[3],
        "type_attack": fields[4],
        "cve_attack": fields[5],
    }


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
    wait_for_file(SYSLOG_PATH, "syslog input file")

    reader = maxminddb.open_database(GEOIP_DB_PATH)
    hq_dict = find_hq_lat_long(reader, HQ_IP)

    r = connect_redis()
    log.info("tailing %s, publishing to %s", SYSLOG_PATH, REDIS_CHANNEL)

    for line in tail(SYSLOG_PATH):
        parsed = parse_syslog(line)
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
