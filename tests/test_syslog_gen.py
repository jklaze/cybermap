"""syslog-gen must cap its output file so the demo volume can't grow forever."""

import importlib.util
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "DataServer"))

_spec = importlib.util.spec_from_file_location(
    "syslog_gen",
    os.path.join(os.path.dirname(__file__), "..", "DataServer", "syslog-gen.py"),
)
syslog_gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(syslog_gen)


def test_maybe_truncate_resets_file_over_cap(tmp_path):
    path = tmp_path / "syslog"
    with open(path, "a", encoding="utf-8") as f:
        f.write("x" * 100)
        f.flush()
        syslog_gen.maybe_truncate(f, max_bytes=50)
        f.write("after\n")
        f.flush()
    assert path.read_text() == "after\n"


def test_maybe_truncate_noop_under_cap(tmp_path):
    path = tmp_path / "syslog"
    with open(path, "a", encoding="utf-8") as f:
        f.write("keep\n")
        f.flush()
        syslog_gen.maybe_truncate(f, max_bytes=50)
    assert path.read_text() == "keep\n"
