"""Tests for the source-IP ignore list (IGNORE_SRC_IPS + HQ_IP)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "DataServer"))

import DataServer as ds  # noqa: E402


def test_parses_plain_ips_and_cidrs():
    nets = ds.parse_ignore_networks("203.0.113.7, 10.0.0.0/8")
    assert ds.is_ignored_ip("203.0.113.7", nets)
    assert ds.is_ignored_ip("10.1.2.3", nets)


def test_ignores_non_matching_ip():
    nets = ds.parse_ignore_networks("203.0.113.7, 10.0.0.0/8")
    assert not ds.is_ignored_ip("8.8.8.8", nets)


def test_empty_spec_ignores_nothing():
    nets = ds.parse_ignore_networks("")
    assert nets == []
    assert not ds.is_ignored_ip("203.0.113.7", nets)


def test_skips_invalid_entries_without_crashing():
    nets = ds.parse_ignore_networks("not-an-ip, 203.0.113.7")
    assert ds.is_ignored_ip("203.0.113.7", nets)


def test_malformed_candidate_ip_is_not_ignored():
    nets = ds.parse_ignore_networks("10.0.0.0/8")
    assert not ds.is_ignored_ip("garbage", nets)


def test_ipv6_cidr():
    nets = ds.parse_ignore_networks("2001:db8::/32")
    assert ds.is_ignored_ip("2001:db8::1", nets)
    assert not ds.is_ignored_ip("2001:dead::1", nets)


def test_hq_ip_is_always_ignored():
    nets = ds.build_ignore_networks("", "198.51.100.25")
    assert ds.is_ignored_ip("198.51.100.25", nets)
    assert not ds.is_ignored_ip("198.51.100.26", nets)


def test_hq_ip_added_alongside_ignore_list():
    nets = ds.build_ignore_networks("203.0.113.7", "198.51.100.25")
    assert ds.is_ignored_ip("203.0.113.7", nets)
    assert ds.is_ignored_ip("198.51.100.25", nets)


def test_hq_ip_not_duplicated_when_already_covered():
    nets = ds.build_ignore_networks("198.51.100.0/24", "198.51.100.25")
    assert [str(n) for n in nets] == ["198.51.100.0/24"]


def test_invalid_hq_ip_is_skipped():
    nets = ds.build_ignore_networks("203.0.113.7", "not-an-ip")
    assert [str(n) for n in nets] == ["203.0.113.7/32"]
