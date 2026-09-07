"""Human output is bounded and safe; machine evidence remains lossless."""
from __future__ import annotations

import copy
import json
import re
import unicodedata

import pytest

from dnsprobe.report import encode, render_text


def report_fixture():
    return {
        "execution": {"status": "partial", "stop_reason": "max_attempts", "exit_code": 3},
        "assessment": {"status": "unknown"}, "duration_ms": 125.5,
        "coverage": {"planned": 4, "completed": 2, "inconclusive": 1, "skipped": 1,
                     "error": 0, "sufficient_for_assessment": False},
        "summary": {"headline": "Insufficient evidence", "recommended_resolver_id": None,
                    "recommendation_reason": "insufficient_comparable_samples"},
        "observations": [
            {"id": "o1", "path_id": "primary", "transport": "udp", "address_family": "ipv4",
             "outcome": "response", "sample_kind": "diagnostic", "timing": {"total_ms": 1.25}},
            {"id": "o2", "path_id": "primary", "transport": "udp", "address_family": "ipv4",
             "outcome": "timeout", "sample_kind": "repeat_observed", "timing": {"total_ms": 800}},
            {"id": "o3", "path_id": "encrypted", "transport": "doh", "address_family": "ipv6",
             "outcome": "response", "sample_kind": "diagnostic", "timing": {"total_ms": 2.5}},
        ],
        # Engine statistics describe repeat samples, never every observed probe.
        "statistics": {"primary": {"success_count": 3, "failure_count": 1, "cancelled_count": 2,
                       "sample_count": 4, "response_rate": .75, "p50_ms": 37.5, "p95_ms": None}},
        "checks": [{"test_id": "DNS.DNSSEC_VALIDATE", "path_id": "primary", "target_id": "example.test",
                    "status": "skipped", "reason_code": "MISSING_TRUST_ANCHOR"}],
        "findings": [{"id": "f1", "severity": "warning", "code": "UPSTREAM_TIMEOUT",
                      "message": "Resolver response timed out"}],
        "errors": [], "artifacts": {},
        "next_actions": [{"id": "a1", "reason_code": "CONFIRM_OR_COMPLETE",
                         "argv": ["dnsprobe", "run", "--agent", "--profile", "quick"], "mutates_system": False}],
    }


@pytest.mark.parametrize("case", ["full", "empty", "nullable", "error", "summary", "untrusted", "long",
                                  "answers", "negative_answers", "long_answers"])
def test_presentation_contract(case):
    report = report_fixture()
    if case == "empty":
        report = {}
    elif case == "nullable":
        report = {key: None for key in report}
    elif case == "error":
        report["execution"] = {"status": "error", "exit_code": 2, "stop_reason": "invalid_input"}
        report["errors"] = [{"code": "INVALID_REQUEST", "message": "Unknown option: budget"}]
        report["observations"] = []
        report["statistics"] = {}
    elif case == "summary":
        report.pop("observations")
        report.pop("statistics")
        report.pop("checks")
        report["truncated"] = True
        report["omitted"] = {"observations": 30, "checks": 10, "findings": 7}
    elif case == "untrusted":
        hostile = "evil\x1b[2J\x1b]52;c;dGVzdA==\x07\rFORGED\nLINE\x85\u2028\u2029\u202e\u2066.test"
        report["summary"]["headline"] = hostile
        report["observations"][0]["path_id"] = hostile
        report["findings"][0]["message"] = hostile
        report["errors"] = [{"code": hostile, "message": hostile}]
        report["checks"][0]["reason_code"] = hostile
        report["next_actions"][0]["argv"].append(hostile)
        report["observations"][0]["answers"] = [{"name": hostile, "type": "TXT", "ttl": None,
                                                   "values": [hostile]}]
    elif case == "long":
        report["summary"]["headline"] = "界" * 300
        report["findings"] *= 100
        report["findings"][0]["message"] = "x" * 1000
        report["next_actions"][0]["argv"] += ["x" * 2000]
    elif case == "answers":
        first = {"path_id": "primary", "outcome": "response", "qname": "www.example.test",
                 "qtype": "A", "rcode": "NOERROR", "answers": [
                     {"name": "www.example.test.", "type": "CNAME", "ttl": 60, "values": ["edge.example.test."]},
                     {"name": "edge.example.test.", "type": "A", "ttl": 30, "values": ["192.0.2.10", "192.0.2.11"]}]}
        other_path = copy.deepcopy(first)
        other_path["path_id"] = "encrypted"
        other_ttl = copy.deepcopy(first)
        other_ttl["answers"] = [{"name": "edge.example.test.", "type": "A", "ttl": 29, "values": ["192.0.2.10"]}]
        report["observations"] = [first, copy.deepcopy(first), other_path, other_ttl]
    elif case == "negative_answers":
        report["observations"] = [
            {"path_id": "primary", "outcome": "response", "qname": "missing.example.test", "qtype": "A",
             "rcode": "NXDOMAIN", "answers": []},
            {"path_id": "system", "outcome": "response", "qname": "host.example.test", "qtype": "A",
             "rcode": None, "answers": [{"name": "host.example.test.", "type": "A", "ttl": None,
                                          "values": ["192.0.2.99"]}]},
            {"path_id": "encrypted", "outcome": "response", "qname": "empty.example.test", "qtype": "TXT",
             "rcode": "NOERROR", "answers": [{"name": None, "type": "TXT", "ttl": None, "values": None}]},
        ]
    elif case == "long_answers":
        report["observations"] = [{"path_id": "primary", "outcome": "response", "answers": [
            {"name": "text.example.test.", "type": "TXT", "ttl": 0, "values": ['"hello world"']},
            {"name": "signed.example.test.", "type": "RRSIG", "ttl": 123, "values": ["A 13 3 123 " + "x" * 2000]},
            *[{"name": f"row{i}.example.test.", "type": "A", "ttl": i, "values": [f"192.0.2.{i}"]}
              for i in range(1, 80)]]}]

    original = copy.deepcopy(report)
    text = render_text(report)
    assert report == original, "Presentation must not mutate the report"
    assert isinstance(text, str) and text.strip()
    assert len(text.splitlines()) <= 100, "Terminal rendering must bound item counts"
    for line in text.split("\n"):
        assert all(not unicodedata.category(char).startswith("C") for char in line), "Untrusted terminal controls escaped"
        width = sum(2 if unicodedata.east_asian_width(char) in ("W", "F") else 1 for char in line)
        assert width <= 100, f"Terminal line is too wide: {width}"
    encoded = encode(report)
    assert json.loads(encoded) == original, "JSON evidence must remain lossless"
    assert len(encoded.splitlines()) == 1, "One encoded report must remain one NDJSON record"
    assert all(not unicodedata.category(char).startswith("C") and char not in "\u2028\u2029"
               for char in encoded), "JSON must escape terminal controls and Unicode line separators"

    lower = text.lower()
    if case == "full":
        for token in ("partial", "unknown", "coverage", "primary", "encrypted", "udp", "ipv4", "ipv6",
                      "p50", "p95", "37.5", "upstream_timeout", "missing_trust_anchor", "dnsprobe", "--agent"):
            assert token in lower
        assert "repeat" in lower, "Repeat statistics must be labelled separately from all observations"
        assert "max_attempts" in lower, "A partial run must expose its stop reason"
        assert re.search(r"(?:n/?a|unknown|--|insufficient|not enough)", lower)
    elif case == "error":
        assert "invalid_request" in lower and "unknown option" in lower
    elif case == "summary":
        assert "omitt" in lower or "truncat" in lower
        assert "30" in lower and "7" in lower
        assert "primary" not in lower, "Summary must not invent missing path observations"
    elif case == "answers":
        answer_lines = [line for line in text.splitlines() if "192.0.2." in line or "CNAME" in line]
        assert len(answer_lines) == 7, "Collapse repeated observations, preserving each path/value/TTL"
        assert sum("192.0.2.10" in line for line in answer_lines) == 3
        assert sum("192.0.2.11" in line for line in answer_lines) == 2
        assert any("primary" in line and "29" in line and "192.0.2.10" in line for line in answer_lines)
        assert any("encrypted" in line and "CNAME" in line and "edge.example.test." in line for line in answer_lines)
        assert "ttl" in lower and "owner" in lower and "full" in lower and "json" in lower
    elif case == "negative_answers":
        assert "NXDOMAIN" in text and "missing.example.test" in text
        row = next(line for line in text.splitlines() if "192.0.2.99" in line)
        assert re.search(r"\bA\s+-\s+192\.0\.2\.99", row), "Unobservable TTL must remain unknown"
        assert "no answer" in lower
    elif case == "long_answers":
        assert '"hello world"' in text and "RRSIG" in text
        assert "..." in text and "omitted" in lower and "full" in lower and "json" in lower
        assert sum("row" in line and "192.0.2." in line for line in text.splitlines()) < 79
    assert text.startswith("DNS Probe"), "Human product label must use the display name"
