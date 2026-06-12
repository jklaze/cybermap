## GeoIP Attack Map

Real-time visualization of network attacks on a MapBox globe. Source IPs are geolocated with MaxMind GeoLite2, attack arcs are colored by protocol, and stats are streamed to the browser over WebSocket.

[Demo video](https://www.youtube.com/watch?v=zTvLJjTzJnU) — originally by Matthew May; this fork modernizes the stack and adds Docker Compose support.

---

### Quick start (Docker Compose)

**Prerequisites:** Docker, a free [MaxMind account](https://www.maxmind.com/en/geolite2/signup), and a free [MapBox token](https://account.mapbox.com/access-tokens/).

```sh
git clone <this-repo>
cd geoip-attack-map

cp .env.example .env
# fill in MAXMIND_LICENSE_KEY and MAPBOX_TOKEN in .env

docker compose up --build
```

Open **http://localhost:8888** — you'll see demo attack traffic immediately.

`docker compose up` starts five services:

| Service | Role |
|---------|------|
| `redis` | Message broker |
| `geoip-init` | One-shot: downloads `GeoLite2-City.mmdb` into a shared volume |
| `syslog-gen` | Generates synthetic attack events at `EVENT_RATE` eps |
| `data-server` | Tails the syslog file, geolocates IPs, publishes events to Redis |
| `attack-map-server` | Tornado WebSocket server + browser UI on port 8888 |

The GeoIP database is cached in a Docker volume and only re-downloaded when it's older than `GEOIP_MAX_AGE_DAYS` (default 14).

Demo mode is the default. Set `SYSLOG_GEN_ENABLED=false` in `.env` to stop the synthetic generator without removing its container (see [Feeding real logs](#feeding-real-logs) for pointing the stack at real log files).

---

### Configuration

All settings live in `.env` (copy from `.env.example`):

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MAXMIND_LICENSE_KEY` | **Yes** | — | MaxMind free API key |
| `MAPBOX_TOKEN` | **Yes** | — | MapBox access token for map tiles |
| `HQ_IP` | No | `8.8.8.8` | Source IP used to compute HQ lat/lng (arc destination) |
| `HQ_LAT` / `HQ_LNG` | No | `37.3845` / `-122.0881` | Override HQ map marker position directly |
| `EVENT_RATE` | No | `5` | Demo events per second |
| `IGNORE_SRC_IPS` | No | — | Comma-separated source IPs/CIDRs (IPv4/IPv6) to drop before geolocation — e.g. your own IP so it doesn't flood the map |
| `LOG_LEVEL` | No | `INFO` | `data-server` log verbosity; set `DEBUG` for per-line parse-miss/geo-miss diagnostics |
| `ATTACK_MAP_PORT` | No | `8888` | Host port for the UI |
| `GEOIP_MAX_AGE_DAYS` | No | `14` | Days before refreshing the GeoIP DB |
| `SYSLOG_GEN_ENABLED` | No | `true` | `false` stops the synthetic generator; container stays created |
| `SYSLOG_PATH` | No | `/var/log/attack-map/syslog` | Container-side path `data-server` tails (the demo feed by default) |
| `SYSLOG_PATHS` | No | — | Comma-separated list of container-side files to tail in parallel. Takes precedence over `SYSLOG_PATH` |
| `HOST_PARSERS_PATH` | No | `./DataServer/parsers.yml` | Host path to a parser-rules YAML file bind-mounted at `/etc/cybermap/parsers.yml` |

Real host log sources are configured in `docker-compose.override.yml`, not `.env` — see [Feeding real logs](#feeding-real-logs).

---

### Feeding real logs

Real host logs are wired in with two files — no Python edits, no changes to the committed `docker-compose.yml`:

- **`docker-compose.override.yml`** (host-specific, gitignored) — one read-only bind mount per log source. Compose merges it into `docker-compose.yml` automatically.
- **`SYSLOG_PATHS`** — the container-side files `data-server` tails (set in the override or in `.env`).

Works with any number of sources, in any host directories, including rotated logs.

1. Stop the synthetic generator in `.env`: `SYSLOG_GEN_ENABLED=false`.

2. Copy the example override and adjust it to your sources:

   ```sh
   cp docker-compose.override.example.yml docker-compose.override.yml
   ```

   ```yaml
   services:
     data-server:
       volumes:
         - /var/log:/host-logs/system:ro
         - /opt/myapp/logs:/host-logs/myapp:ro
       environment:
         SYSLOG_PATHS: /host-logs/system/auth.log,/host-logs/myapp/access.log
   ```

   Two rules keep this robust:

   - **Mount directories, not files.** Logrotate replaces a rotated file with a new inode; a file bind mount keeps pointing at the old inode and your map silently goes quiet. A directory mount always sees the current file, and `data-server` detects rotation (rename *and* copytruncate) and reopens automatically.
   - **Don't gather sources with symlinks.** A symlink inside a bind-mounted folder resolves against the *container's* filesystem, where the target doesn't exist — it dangles. Mount each real directory instead, namespaced under `/host-logs/<name>`.

3. Open [DataServer/parsers.yml](DataServer/parsers.yml) and uncomment/add an entry for each log shape. The bundled built-in formats are:

   | `format:` | Matches |
   |-----------|---------|
   | `sshd-auth` | Linux sshd "Failed password" lines (`/var/log/auth.log`, `/var/log/secure`) |
   | `ufw` | UFW firewall BLOCK lines (TCP/UDP) |
   | `nginx-access` | nginx combined access log |
   | `apache-access` | Apache combined access log |
   | `fail2ban` | fail2ban "Ban &lt;ip&gt;" actions |
   | `demo-csv` | The bundled synthetic generator |

   A typical entry is two lines per source (`match:` is a glob over the container path):

   ```yaml
   - match: "/host-logs/system/auth.log"
     format: sshd-auth
   - match: "/host-logs/myapp/access.log"
     format: nginx-access
   ```

   If a format mostly works but a field is wrong, override it under `defaults:` (regex-captured fields always win — `defaults` only fills in what the regex doesn't capture). For unsupported log shapes, write a custom `regex:` with named groups — see the comments at the bottom of `parsers.yml`.

4. `docker compose up -d`. Repeat steps 2–3 and `docker compose up -d` again whenever you add a source.

`parsers.yml` is bind-mounted read-only, so editing it on the host and restarting `data-server` picks up the changes — no rebuilds. To keep your edits outside the repo, point `HOST_PARSERS_PATH` at any absolute host path in `.env`.

`data-server` tails every `SYSLOG_PATHS` entry in parallel (one thread per file, fed through a shared queue) and survives log rotation on each of them. To keep the demo feed running alongside real logs, include `/var/log/attack-map/syslog` in `SYSLOG_PATHS` and leave `SYSLOG_GEN_ENABLED=true`.

#### Troubleshooting: real logs produce no events

`data-server` logs a periodic pipeline tally so you can see where lines go:

```
pipeline: read=4213 published=0 parse_miss=4213 ignored=0 geo_miss=0
```

- **`parse_miss` high, `published=0`** — no parser matched. Almost always a
  `match:` glob that doesn't equal the `SYSLOG_PATHS` entry (e.g. `/host-syslog/...`
  vs `/host-logs/...`). Set `LOG_LEVEL=DEBUG` to see the exact unmatched lines and
  which source they came from.
- **`geo_miss` high** — lines parse, but the source IPs aren't in GeoLite2
  (private/internal ranges). Expected for LAN traffic; only public IPs render.
- **`read=0`** — nothing is being tailed: the file is quiet, or the mount/path is
  wrong. `data-server` logs `first line received from <path>` once per source when
  data starts flowing.

---

### Manual / bare-metal deploy

```sh
sudo apt install python3-pip redis-server
pip3 install -r requirements.txt

# Download GeoIP DB (requires MAXMIND_LICENSE_KEY in env)
GEOIP_DB_PATH=DataServerDB/GeoLite2-City.mmdb sh scripts/download-geoip.sh

# Unpack flag icons
cd AttackMapServer/static && unzip flags.zip && cd ../..

# Start services (each in its own terminal)
redis-server
REDIS_HOST=127.0.0.1 SYSLOG_PATH=/var/log/attack-map/syslog \
  PARSERS_PATH=DataServer/parsers.yml \
  GEOIP_DB_PATH=DataServerDB/GeoLite2-City.mmdb python3 DataServer/DataServer.py
SYSLOG_PATH=/var/log/attack-map/syslog python3 DataServer/syslog-gen.py
REDIS_HOST=127.0.0.1 MAPBOX_TOKEN=<token> python3 AttackMapServer/AttackMapServer.py
```

---

### Architecture

```
syslog file ──► DataServer.py ──publish──► Redis ──subscribe──► AttackMapServer.py ──WS──► browser
```

- **`DataServer/DataServer.py`** — tails every path in `SYSLOG_PATHS` (one thread per file, fed through a shared queue), parses each line via rules loaded from `PARSERS_PATH`, looks up the source IP in GeoLite2, appends running stats, and publishes JSON to Redis channel `attack-map-production`.
- **`DataServer/parsers.yml`** — declarative parser rules. Each entry maps a path glob to either a built-in `format:` name (defined in `BUILTIN_FORMATS` inside `DataServer.py`) or a custom `regex:`. Users uncomment entries for common log shapes without touching Python.
- **`DataServer/const.py`** — `META` describes which GeoLite2 fields to extract; `PORTMAP` maps port numbers to protocol labels. Both are the sole source of truth for their respective mappings.
- **`AttackMapServer/AttackMapServer.py`** — Tornado 6 app. A single background task subscribes to Redis and fans out messages to all connected WebSocket clients via `ClientHub`.
- **`AttackMapServer/static/map.js`** — browser client. Draws attack arcs on a MapBox/Leaflet map; WebSocket URL is derived from `window.location` so no source edits are needed for different host/port combos.
