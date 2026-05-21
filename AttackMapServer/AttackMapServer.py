#!/usr/bin/env python3
"""
WebSocket bridge: subscribes to the Redis `attack-map-production` channel
and fans events out to every connected browser client.
"""

import asyncio
import json
import logging
import os
import signal
from typing import Set

import redis.asyncio as redis
import tornado.ioloop
import tornado.web
import tornado.websocket

REDIS_HOST = os.environ.get("REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))
REDIS_CHANNEL = os.environ.get("REDIS_CHANNEL", "attack-map-production")
LISTEN_PORT = int(os.environ.get("PORT", "8888"))
MAPBOX_TOKEN = os.environ.get("MAPBOX_TOKEN", "")
HQ_LAT = float(os.environ.get("HQ_LAT", "37.3845"))
HQ_LNG = float(os.environ.get("HQ_LNG", "-122.0881"))

SERVICE_RGB = {
    "FTP": "#ff0000",
    "SSH": "#ff8000",
    "TELNET": "#ffff00",
    "EMAIL": "#80ff00",
    "WHOIS": "#00ff00",
    "DNS": "#00ff80",
    "HTTP": "#00ffff",
    "HTTPS": "#0080ff",
    "SQL": "#0000ff",
    "SNMP": "#8000ff",
    "SMB": "#bf00ff",
    "AUTH": "#ff00ff",
    "RDP": "#ff0060",
    "DoS": "#ff0000",
    "ICMP": "#ffcccc",
    "OTHER": "#6600cc",
}

FORWARDED_KEYS = (
    "src_ip", "dst_ip", "src_port", "dst_port",
    "city", "continent", "continent_code", "country", "iso_code", "postal_code",
    "event_count", "continents_tracked", "countries_tracked", "ips_tracked",
    "unknowns", "event_time", "country_to_code", "ip_to_code",
)

log = logging.getLogger("attack-map-server")


class ClientHub:
    """Holds the set of live WebSocket clients and the Redis subscriber task."""

    def __init__(self, redis_url: str, channel: str):
        self._redis_url = redis_url
        self._channel = channel
        self._clients: Set["WebSocketHandler"] = set()
        self._task: asyncio.Task | None = None

    def add(self, client: "WebSocketHandler") -> None:
        self._clients.add(client)

    def remove(self, client: "WebSocketHandler") -> None:
        self._clients.discard(client)

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run())

    async def _run(self) -> None:
        while True:
            try:
                client = redis.from_url(self._redis_url, decode_responses=True)
                pubsub = client.pubsub()
                await pubsub.subscribe(self._channel)
                log.info("subscribed to %s on %s", self._channel, self._redis_url)
                async for message in pubsub.listen():
                    if message.get("type") != "message":
                        continue
                    self._broadcast(message["data"])
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("redis subscriber crashed; reconnecting in 2s")
                await asyncio.sleep(2)

    def _broadcast(self, raw: str) -> None:
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            log.warning("dropping non-JSON message: %r", raw[:120])
            return

        msg = {key: payload.get(key) for key in FORWARDED_KEYS}
        msg["type"] = payload.get("msg_type")
        msg["type2"] = payload.get("msg_type2")
        msg["type3"] = payload.get("msg_type3")
        msg["protocol"] = payload.get("protocol")
        msg["src_lat"] = payload.get("latitude")
        msg["src_long"] = payload.get("longitude")
        msg["dst_lat"] = payload.get("dst_lat")
        msg["dst_long"] = payload.get("dst_long")
        msg["color"] = SERVICE_RGB.get(msg["protocol"], "#000000")

        encoded = json.dumps(msg)
        for client in list(self._clients):
            try:
                client.write_message(encoded)
            except tornado.websocket.WebSocketClosedError:
                self._clients.discard(client)


class IndexHandler(tornado.web.RequestHandler):
    async def get(self) -> None:
        self.render(
            "index.html",
            mapbox_token=MAPBOX_TOKEN,
            hq_lat=HQ_LAT,
            hq_lng=HQ_LNG,
        )


class HealthHandler(tornado.web.RequestHandler):
    def get(self) -> None:
        self.write({"status": "ok"})


class WebSocketHandler(tornado.websocket.WebSocketHandler):
    hub: "ClientHub"

    def check_origin(self, origin: str) -> bool:
        return True

    def open(self) -> None:
        log.info("websocket opened: %s", self.request.remote_ip)
        self.hub.add(self)

    def on_close(self) -> None:
        log.info("websocket closed: %s", self.request.remote_ip)
        self.hub.remove(self)


def make_app(hub: ClientHub) -> tornado.web.Application:
    WebSocketHandler.hub = hub
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    return tornado.web.Application(
        handlers=[
            (r"/", IndexHandler),
            (r"/websocket", WebSocketHandler),
            (r"/health", HealthHandler),
            (r"/static/(.*)", tornado.web.StaticFileHandler, {"path": static_dir}),
            (r"/flags/(.*)", tornado.web.StaticFileHandler, {"path": os.path.join(static_dir, "flags")}),
        ],
        template_path=os.path.dirname(__file__),
        debug=False,
    )


async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    redis_url = f"redis://{REDIS_HOST}:{REDIS_PORT}/0"
    hub = ClientHub(redis_url=redis_url, channel=REDIS_CHANNEL)
    hub.start()

    app = make_app(hub)
    app.listen(LISTEN_PORT)
    log.info("listening on :%d", LISTEN_PORT)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    await stop.wait()
    log.info("shutting down")


if __name__ == "__main__":
    asyncio.run(main())
