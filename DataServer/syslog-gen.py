#!/usr/bin/env python3
"""
Generates fake attack events in the CSV format that DataServer's default
parser expects, and appends them to a file. Other side of the shared volume
in the Docker Compose stack.

Environment variables:
  SYSLOG_PATH    output file path (default /var/log/attack-map/syslog)
  EVENT_RATE     events per second (default 5)
  HQ_IP          destination IP put in each event (default 8.8.8.8)
"""

import os
import random
import sys
import time
from pathlib import Path
from time import localtime, sleep, strftime

from const import PORTMAP

SYSLOG_PATH = os.environ.get("SYSLOG_PATH", "/var/log/attack-map/syslog")
EVENT_RATE = float(os.environ.get("EVENT_RATE", "5"))
HQ_IP = os.environ.get("HQ_IP", "8.8.8.8")

INTERVAL = 1.0 / EVENT_RATE if EVENT_RATE > 0 else 1.0


def random_ip() -> str:
    return ".".join(str(random.randrange(1, 256)) for _ in range(4))


def random_event() -> str:
    port = random.choice(list(PORTMAP.keys()))
    type_attack = PORTMAP[port]
    cve_attack = f"CVE:{random.randrange(1, 2000)}:{random.randrange(100, 1000)}"
    return f"{random_ip()},{HQ_IP},{port},{port},{type_attack},{cve_attack}"


def main() -> None:
    out_path = Path(SYSLOG_PATH)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"[syslog-gen] writing to {out_path} at {EVENT_RATE} eps", flush=True)

    with open(out_path, "a", encoding="utf-8") as f:
        while True:
            ts = strftime("%b %d %H:%M:%S", localtime())
            line = f"{ts} attack-map-sample: {random_event()}\n"
            f.write(line)
            f.flush()
            sleep(INTERVAL)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
