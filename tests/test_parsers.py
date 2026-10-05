"""Built-in parser formats must extract all required fields from real log lines."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "DataServer"))

import DataServer as ds  # noqa: E402

CADDY_LINE = (
    '{"level":"info","ts":1791215804.2566173,"logger":"http.log.access.log7",'
    '"msg":"handled request","request":{"remote_ip":"10.0.0.2","remote_port":"10830",'
    '"client_ip":"192.53.169.77","proto":"HTTP/2.0","method":"GET","host":"vpn.jklaze.com",'
    '"uri":"/","headers":{"User-Agent":["curl"]},"tls":{"resumed":false,"version":772}},'
    '"bytes_read":0,"duration":0.02,"size":0,"status":401}\n'
)


def _parser(fmt, match="/host-logs/x/access.log"):
    spec = ds.BUILTIN_FORMATS[fmt]
    return ds.Parser(name=fmt, match=match, regex=spec["regex"], defaults=spec["defaults"])


def test_caddy_json_uses_client_ip_and_method():
    out = ds.parse_line("/host-logs/x/access.log", CADDY_LINE, [_parser("caddy-json")])
    assert out == {
        "src_ip": "192.53.169.77",
        "dst_ip": "0.0.0.0",
        "src_port": "0",
        "dst_port": "443",
        "type_attack": "GET",
        "cve_attack": "N/A",
    }


def test_caddy_json_ignores_non_access_entries():
    line = '{"level":"info","ts":1.0,"logger":"tls","msg":"certificate obtained successfully"}\n'
    assert ds.parse_line("/host-logs/x/access.log", line, [_parser("caddy-json")]) is None


def test_bundled_parsers_cover_caddy_access_log():
    path = os.path.join(os.path.dirname(__file__), "..", "DataServer", "parsers.yml")
    parsers = ds.load_parsers(path)
    out = ds.parse_line("/host-logs/caddy/access.log", CADDY_LINE, parsers)
    assert out and out["src_ip"] == "192.53.169.77"
