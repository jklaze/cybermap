# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

A real-time GeoIP cyber-attack map. `DataServer` tails a syslog file, parses attack events, geolocates source IPs against MaxMind GeoLite2, and publishes JSON to Redis. `AttackMapServer` subscribes to that Redis channel and fans events over WebSocket to a browser client (`index.html` + `static/map.js`), which renders attack arcs on a MapBox map.

This is a modernized fork of `matthewclarkmay/geoip-attack-map`: upgraded to Tornado 6, `redis.asyncio`, Python 3.12, and Docker Compose deployment.

## Architecture

```
syslog file  →  DataServer.py  ──publish──►  Redis  ──subscribe──►  AttackMapServer.py  ──WebSocket──►  browser
                (tails + parses)              (redis:6379)            (Tornado 6, :8888)
```

- **`DataServer/DataServer.py`** — env-driven config, waits on startup for GeoIP DB and syslog file before processing. Publishes to `attack-map-production` channel. Running stats (`event_count`, `continents_tracked`, etc.) are module-level globals appended to every event; printed on `SIGTERM`.
- **`DataServer/const.py`** — `META` is the declarative GeoLite2 field-extraction spec used by `clean_db`; `PORTMAP` maps ports → protocol labels. Add protocol mappings here.
- **`AttackMapServer/AttackMapServer.py`** — Tornado 6. `ClientHub` holds a `redis.asyncio` subscriber task that broadcasts to all connected `WebSocketHandler` instances. `SERVICE_RGB` maps protocol labels to colors; every key that `PORTMAP` can produce must appear here.
- **`AttackMapServer/static/map.js`** — WebSocket URL built from `window.location` (no hardcoded host). MapBox token and HQ coords injected via Tornado template variables.
- **`DataServer/syslog-gen.py`** — appends synthetic events to `SYSLOG_PATH` directly (no `logger`/syslog dependency).

## Configuration

All config is via environment variables (no source edits required):

| Variable | Default | Where used |
|----------|---------|-----------|
| `REDIS_HOST` / `REDIS_PORT` | `127.0.0.1` / `6379` | Both services |
| `SYSLOG_PATH` | `/var/log/attack-map/syslog` | DataServer, syslog-gen |
| `GEOIP_DB_PATH` | `/geoip/GeoLite2-City.mmdb` | DataServer |
| `HQ_IP` | `8.8.8.8` | DataServer (geolocated to compute HQ lat/lng) |
| `MAPBOX_TOKEN` | — | AttackMapServer → index.html template |
| `HQ_LAT` / `HQ_LNG` | `37.3845` / `-122.0881` | AttackMapServer → index.html template |
| `EVENT_RATE` | `5` | syslog-gen (events per second) |
| `MAXMIND_LICENSE_KEY` | — | `scripts/download-geoip.sh` (init container) |

## Common commands

```sh
# Docker Compose (recommended)
cp .env.example .env  # fill in MAXMIND_LICENSE_KEY and MAPBOX_TOKEN
docker compose up --build

# Run a single service's logs
docker compose logs -f data-server

# Force refresh the GeoIP DB
docker compose rm -f geoip-init && docker compose up geoip-init
```

## Customizing the syslog parser

`parse_syslog()` in `DataServer/DataServer.py` is the only function that needs editing for real deployments. It must return a dict with `src_ip`, `dst_ip`, `src_port`, `dst_port`, `type_attack`, `cve_attack`, or `None` to skip the line. The default format is `<src_ip>,<dst_ip>,<sport>,<dport>,<type>,<cve>` as the last whitespace-separated token on each line.

## Dependencies

`requirements.txt` pins: `tornado==6.4.1`, `redis==5.0.8`, `maxminddb==1.5.4`. The `tornadoredis` package and the old `@tornado.web.asynchronous` / `@tornado.gen.engine` patterns are gone.
