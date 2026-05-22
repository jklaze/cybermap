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
| `SYSLOG_PATHS` | No | — | Comma-separated list of container-side files to tail in parallel. Takes precedence over `SYSLOG_PATH` |
| `HOST_PARSERS_PATH` | No | `./DataServer/parsers.yml` | Host path to a parser-rules YAML file bind-mounted at `/etc/cybermap/parsers.yml` |

---

### Using real syslog

Everything is driven from `.env` and a YAML rules file — no Python edits required. For common log shapes you just uncomment a two-line entry.

1. Stop the synthetic generator in `.env`: `SYSLOG_GEN_ENABLED=false`.
2. Point at your host log:

   ```
   HOST_SYSLOG_PATH=/var/log/auth.log    # absolute host path to a file or directory
   SYSLOG_PATH=/host-syslog              # container-side path data-server tails
   ```

   If `HOST_SYSLOG_PATH` is a directory, set `SYSLOG_PATH=/host-syslog/<filename>` to pick the file inside it.

3. Open [DataServer/parsers.yml](DataServer/parsers.yml) and uncomment the entry for your log shape. The bundled built-in formats are:

   | `format:` | Matches |
   |-----------|---------|
   | `sshd-auth` | Linux sshd "Failed password" lines (`/var/log/auth.log`, `/var/log/secure`) |
   | `ufw` | UFW firewall BLOCK lines (TCP/UDP) |
   | `nginx-access` | nginx combined access log |
   | `apache-access` | Apache combined access log |
   | `fail2ban` | fail2ban "Ban &lt;ip&gt;" actions |
   | `demo-csv` | The bundled synthetic generator |

   A typical entry is just two lines:

   ```yaml
   - match: "/host-syslog"
     format: sshd-auth
   ```

   If a format mostly works but a field is wrong, override it under `defaults:` (regex-captured fields always win — `defaults` only fills in what the regex doesn't capture). For unsupported log shapes, write a custom `regex:` with named groups — see the comments at the bottom of `parsers.yml`.

4. `docker compose up`.

`parsers.yml` is bind-mounted read-only, so editing it on the host and restarting `data-server` picks up the changes — no rebuilds. To keep your edits outside the repo, point `HOST_PARSERS_PATH` at any absolute host path in `.env`.

#### Multiple host log files

`data-server` natively tails any number of files in parallel via a thread per source. To use this:

1. Bind-mount each host log into the container. The default `HOST_SYSLOG_PATH` mount accepts a directory, so the easiest setup is to point it at a directory containing (or symlinked to) every log you care about:

   ```
   HOST_SYSLOG_PATH=/var/log         # mounted at /host-syslog in the container
   SYSLOG_PATHS=/host-syslog/auth.log,/host-syslog/nginx/access.log
   ```

   If your logs live in unrelated host directories, drop a `docker-compose.override.yml` next to `docker-compose.yml` with extra read-only bind mounts:

   ```yaml
   services:
     data-server:
       volumes:
         - /var/log/auth.log:/host-syslog/auth.log:ro
         - /opt/nginx/access.log:/host-syslog/nginx-access.log:ro
   ```

   Compose auto-loads the override, no flags needed.

2. List each container path in `SYSLOG_PATHS` (comma-separated). `SYSLOG_PATHS` takes precedence over `SYSLOG_PATH`.

3. Make sure `parsers.yml` has an entry for each source. With built-in formats it's two lines per source:

   ```yaml
   - match: "/host-syslog/auth.log"
     format: sshd-auth
   - match: "/host-syslog/nginx-access.log"
     format: nginx-access
   ```

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
