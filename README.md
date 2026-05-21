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

Demo mode is the default. Set `SYSLOG_GEN_ENABLED=false` in `.env` to stop the synthetic generator without removing its container (see [Using real syslog](#using-real-syslog) for pointing the stack at a real log file).

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
| `ATTACK_MAP_PORT` | No | `8888` | Host port for the UI |
| `GEOIP_MAX_AGE_DAYS` | No | `14` | Days before refreshing the GeoIP DB |
| `SYSLOG_GEN_ENABLED` | No | `true` | `false` stops the synthetic generator; container stays created |
| `HOST_SYSLOG_PATH` | No | — | Host file/dir bind-mounted read-only into `data-server` at `/host-syslog` |
| `SYSLOG_PATH` | No | `/var/log/attack-map/syslog` | Container-side path `data-server` tails (set to `/host-syslog` when using a real log) |

---

### Using real syslog

Everything is driven from `.env` — no YAML edits required.

1. Stop the synthetic generator: `SYSLOG_GEN_ENABLED=false`.
2. Point at your host log:

   ```
   HOST_SYSLOG_PATH=/var/log/auth.log    # absolute host path to a file or directory
   SYSLOG_PATH=/host-syslog              # container-side path data-server tails
   ```

   If `HOST_SYSLOG_PATH` is a directory, set `SYSLOG_PATH=/host-syslog/<filename>` to pick the file inside it.

3. Edit `parse_syslog()` in [DataServer/DataServer.py](DataServer/DataServer.py) to match your log format. The function must return a dict with keys `src_ip`, `dst_ip`, `src_port`, `dst_port`, `type_attack`, `cve_attack`, or `None` to skip the line.

4. `docker compose up`.

#### Multiple host log files

`data-server` tails exactly one file (`SYSLOG_PATH`). For logs scattered across distinct host paths, drop a `docker-compose.override.yml` next to the main compose file — Compose auto-loads it — and add extra bind mounts:

```yaml
# docker-compose.override.yml
services:
  data-server:
    volumes:
      - /var/log/auth.log:/host-syslog/auth.log:ro
      - /var/log/firewall.log:/host-syslog/firewall.log:ro
```

Then merge upstream into one file the data-server can tail (e.g. a small `tail -F a b >> merged` sidecar, or host-side syslog forwarding). Native multi-file tailing in `DataServer.py` is a possible follow-up.

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
  GEOIP_DB_PATH=DataServerDB/GeoLite2-City.mmdb python3 DataServer/DataServer.py
SYSLOG_PATH=/var/log/attack-map/syslog python3 DataServer/syslog-gen.py
REDIS_HOST=127.0.0.1 MAPBOX_TOKEN=<token> python3 AttackMapServer/AttackMapServer.py
```

---

### Architecture

```
syslog file ──► DataServer.py ──publish──► Redis ──subscribe──► AttackMapServer.py ──WS──► browser
```

- **`DataServer/DataServer.py`** — tails `SYSLOG_PATH`, parses each line via `parse_syslog()`, looks up the source IP in GeoLite2, appends running stats, and publishes JSON to Redis channel `attack-map-production`.
- **`DataServer/const.py`** — `META` describes which GeoLite2 fields to extract; `PORTMAP` maps port numbers to protocol labels. Both are the sole source of truth for their respective mappings.
- **`AttackMapServer/AttackMapServer.py`** — Tornado 6 app. A single background task subscribes to Redis and fans out messages to all connected WebSocket clients via `ClientHub`.
- **`AttackMapServer/static/map.js`** — browser client. Draws attack arcs on a MapBox/Leaflet map; WebSocket URL is derived from `window.location` so no source edits are needed for different host/port combos.
