"""Tests for DataServer.tail() — must keep following a file across logrotate."""

import os
import queue
import sys
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "DataServer"))
os.environ["TAIL_POLL_INTERVAL"] = "0.02"

import DataServer as ds  # noqa: E402


def append(path, text):
    with open(path, "a") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())


def start_tail(path):
    q = queue.Queue()
    gen = ds.tail(str(path))  # opens eagerly: lines appended from here on are seen

    def run():
        for line in gen:
            q.put(line)

    threading.Thread(target=run, daemon=True).start()
    return q


def expect_line(q, timeout=3.0):
    try:
        return q.get(timeout=timeout)
    except queue.Empty:
        pytest.fail(f"no line received within {timeout}s")


def test_yields_lines_appended_after_start(tmp_path):
    path = tmp_path / "syslog"
    append(path, "old line\n")  # pre-existing content must be skipped
    q = start_tail(path)
    append(path, "new line\n")
    assert expect_line(q) == "new line\n"


def test_follows_file_across_logrotate_rename(tmp_path):
    path = tmp_path / "syslog"
    append(path, "")
    q = start_tail(path)
    append(path, "before rotate\n")
    assert expect_line(q) == "before rotate\n"

    # classic logrotate: rename the file, recreate the path
    os.rename(path, tmp_path / "syslog.1")
    append(path, "after rotate\n")
    assert expect_line(q) == "after rotate\n"


def test_resumes_after_truncation(tmp_path):
    path = tmp_path / "syslog"
    append(path, "")
    q = start_tail(path)
    append(path, "before truncate\n")
    assert expect_line(q) == "before truncate\n"

    # logrotate copytruncate: same inode, size drops to zero
    with open(path, "w"):
        pass
    append(path, "after truncate\n")
    assert expect_line(q) == "after truncate\n"
