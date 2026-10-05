"""Tooltip text (summary/evidence) must explain the event without leaking host details."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "DataServer"))

import DataServer as ds  # noqa: E402

PARSERS = os.path.join(os.path.dirname(__file__), "..", "DataServer", "parsers.yml")


def _parse(source, line):
    return ds.parse_line(source, line, ds.load_parsers(PARSERS), ds.RecentConnections())


def _caddy(uri, status=404, host="secret.example.com"):
    return (
        '{"level":"info","ts":1.0,"logger":"http.log.access.log1","msg":"handled request",'
        '"request":{"remote_ip":"203.0.113.9","remote_port":"1","client_ip":"203.0.113.9",'
        f'"proto":"HTTP/1.1","method":"GET","host":"{host}","uri":"{uri}",'
        '"headers":{"User-Agent":["x"]}},"status":' + str(status) + "}\n"
    )


def test_ssh_tooltip_hides_username_and_account_existence():
    line = "Oct  5 21:00:00 main sshd[1]: Failed password for invalid user hunter2pass from 203.0.113.9 port 5 ssh2\n"
    out = _parse("/host-logs/system/auth.log", line)
    assert out["summary"].startswith("SSH password guessing")
    assert out["evidence"] == "sshd: Failed password from 203.0.113.9 port 5"
    assert "hunter2pass" not in str(out) and "invalid" not in out["evidence"]


def test_ufw_tooltip_hides_host_details():
    line = (
        "Oct  5 21:00:00 main kernel: [UFW BLOCK] IN=eth0 OUT= MAC=fa:16:3e:00:00:01:fa:16:3e:00:00:02:08:00 "
        "SRC=203.0.113.9 DST=198.51.100.25 LEN=44 TOS=0x00 PREC=0x00 TTL=242 ID=1 PROTO=TCP SPT=40000 "
        "DPT=8443 WINDOW=1024 RES=0x00 SYN URGP=0\n"
    )
    out = _parse("/host-logs/system/ufw.log", line)
    assert out["evidence"] == "UFW BLOCK TCP SRC=203.0.113.9 SPT=40000 DPT=8443 SYN"
    assert "198.51.100.25" not in out["evidence"] and "MAC" not in out["evidence"]


def test_caddy_tooltip_keeps_probe_path_but_drops_host_and_query():
    out = _parse("/host-logs/caddy/access.log", _caddy("/.env?token=abc123secret&x=1"))
    assert out["evidence"] == "GET /.env → 404"
    assert "secret.example.com" not in str(out)
    assert "not found" in out["summary"] and "probing" in out["summary"]


def test_caddy_status_hint_depends_on_status():
    assert "backend failed" in _parse("/host-logs/caddy/access.log", _caddy("/", 502))["summary"]
    assert "protected page" in _parse("/host-logs/caddy/access.log", _caddy("/", 401))["summary"]


def test_sanitize_path_masks_ids_and_emails_and_decodes_json():
    assert ds.sanitize_path("/-wVw1o5dPEhq/file") == "/*/file"
    assert ds.sanitize_path("/users/me@example.com") == "/users/*"
    assert ds.sanitize_path("/wp-login.php") == "/wp-login.php"
    out = _parse("/host-logs/caddy/access.log", _caddy("/a\\u0026b"))
    assert out["evidence"] == "GET /a&b → 404"


def test_tooltip_text_is_clipped_and_control_free():
    long = "/" + "a" * 500 + "\\u001b[31m"
    out = _parse("/host-logs/caddy/access.log", _caddy(long))
    assert len(out["evidence"]) <= ds.TOOLTIP_MAX_LEN
    assert "\x1b" not in out["evidence"]


def test_missing_template_fields_render_blank():
    assert ds.describe("a {nope} b", {}) == "a b"
    assert ds.describe(None, {}) is None
