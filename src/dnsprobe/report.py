"""Pure renderers and offline report operations. No DNS or environment discovery."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import math
import unicodedata
from collections import Counter, defaultdict
import uuid

SUMMARY_LIMIT = 8192
CORE_KEYS = ("schema_version", "engine_version", "catalog_version", "ruleset_version", "profile_version", "implementation_fingerprint", "run_id", "started_at", "duration_ms", "execution", "assessment", "coverage", "summary", "findings", "next_actions", "artifacts", "errors")


class OutputLimitError(ValueError):
    """A valid core report cannot be represented within the summary size cap."""


def escape_json_controls(text: str) -> str:
    """Keep JSON data lossless while preserving line framing and terminal safety."""
    return ''.join(json.dumps(char,ensure_ascii=True)[1:-1]
                   if char not in ('\n','\r','\t') and (unicodedata.category(char).startswith('C') or char in ('\u2028','\u2029'))
                   else char for char in text)


def encode(value) -> str:
    return escape_json_controls(json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False))


def _brief(value, depth=0):
    if isinstance(value, str):
        return value if len(value) <= 320 else value[:317] + "..."
    if isinstance(value, dict):
        if depth > 4:
            return {"omitted_fields": len(value)}
        return {key: _brief(val, depth + 1) for key, val in list(value.items())[:24]}
    if isinstance(value, list):
        return [_brief(val, depth + 1) for val in value[:4]]
    return value


def summarize(report: dict, max_bytes: int = SUMMARY_LIMIT) -> dict:
    """Keep decisions and coverage, with bounded, self-contained evidence snippets."""
    result = {key: copy.deepcopy(report[key]) for key in CORE_KEYS if key in report}
    observations = {o.get("id"): o for o in report.get("observations", [])}
    severity = {"error": 0, "warning": 1, "info": 2}
    findings = sorted(report.get("findings", []), key=lambda f: severity.get(f.get("severity"), 3))
    result["findings"] = []
    for finding in findings[:5]:
        item = _brief(finding)
        evidence = finding.get("evidence_summary") or [observations[i] for i in finding.get("evidence_ids", []) if i in observations]
        item["evidence_summary"] = [_brief(o) for o in evidence[:2]]
        result["findings"].append(item)
    result["next_actions"] = copy.deepcopy(report.get("next_actions", [])[:3])
    result["errors"] = [_brief(e) for e in report.get("errors", [])[:5]]
    result["omitted"] = {
        "findings": max(0, len(findings) - 5), "next_actions": max(0, len(report.get("next_actions", [])) - 3),
        "errors": max(0, len(report.get("errors", [])) - 5),
        "checks": len(report.get("checks", [])), "observations": len(report.get("observations", [])),
    }
    if "series" in report:
        result["series"] = {key: copy.deepcopy(value) for key, value in report["series"].items() if key != "samples"}
        result["series"]["target_statistics"] = result["series"].get("target_statistics", [])[:10]
        result["omitted"]["series_samples"] = len(report["series"].get("samples", []))
        result["omitted"]["series_targets"] = max(0, len(report["series"].get("target_statistics", [])) - 10)
    # Full observations are intentionally absent; mark every such omission.
    result["truncated"] = any(result["omitted"].values()) or any(len(encode(f)) > len(encode(_brief(f))) for f in findings[:5])
    while len(encode(result).encode("utf-8")) > max_bytes:
        if result["next_actions"]:
            result["next_actions"].pop()
            result["omitted"]["next_actions"] += 1
        elif len(result["findings"]) > 1:
            result["findings"].pop()
            result["omitted"]["findings"] += 1
        else:
            raise OutputLimitError(f"Core summary exceeds {max_bytes} bytes; use --detail full or --artifact-dir")
        result["truncated"] = True
    return result


def _terminal(value):
    """Escape response-controlled terminal commands without changing JSON evidence."""
    text = str(value) if value is not None else "-"
    return "".join((f"\\x{ord(char):02x}" if ord(char) < 256 else f"\\u{ord(char):04x}")
                   if unicodedata.category(char).startswith("C") or char in ('\u2028','\u2029') else char for char in text)


def _width(text):
    return sum(2 if unicodedata.east_asian_width(c) in ("W", "F") else 0 if unicodedata.combining(c) else 1 for c in text)


def _clip(value, limit=100):
    text = _terminal(value)
    if _width(text) <= limit:
        return text
    result, width = [], 0
    for char in text:
        size = _width(char)
        if width + size > limit - 3:
            break
        result.append(char); width += size
    return "".join(result) + "..."


def _table(headers, rows, widths):
    def row(cells):
        parts = [_clip(cell, width) for cell, width in zip(cells, widths)]
        return "  ".join(part + " " * max(0, width - _width(part)) for part, width in zip(parts, widths)).rstrip()
    return [row(headers), row(["-" * width for width in widths])] + [row(cells) for cells in rows]


def _milliseconds(value):
    return f"{value:.2f}".rstrip("0").rstrip(".") if isinstance(value, (int, float)) and math.isfinite(value) else "-"


def _answer_view(observations):
    """Present recorded answers, retaining path and TTL differences across attempts."""
    rows, seen = [], set()
    for observation in observations:
        if observation.get('outcome') != 'response':
            continue
        path = observation.get('path_id') or 'unknown'
        protocol = observation.get('transport')
        label = f'{path}/{protocol}' if protocol else path
        records = observation.get('answers')
        if records is None:
            continue
        candidates = []
        for record in records:
            for value in record.get('values') or [None]:
                candidates.append([label, record.get('name'), record.get('type'), record.get('ttl'), value])
        if not records:
            code = observation.get('rcode') or 'RCODE unavailable'
            candidates.append([label, observation.get('qname'), observation.get('qtype'), None,
                               f'{code}; no answer records'])
        for row in candidates:
            identity = encode([observation.get('path_id'), protocol, observation.get('address_family'), *row[1:]])
            if identity not in seen:
                seen.add(identity)
                rows.append(row)
    if not rows:
        return ['', 'No answer records available in this report.']
    widths = [14, 24, 8, 8, 32]
    visible = rows[:12]
    lines = ['', 'Observed answer records (repeat rows collapsed)']
    lines += _table(['Path/protocol', 'Owner', 'Type', 'TTL (s)', 'Value / response'], visible, widths)
    if len(rows) > len(visible):
        lines.append(f'{len(rows)-len(visible)} additional distinct answer rows omitted.')
    if any(_width(_terminal(cell)) > width for row in visible for cell, width in zip(row, widths)):
        lines.append('Some answer fields clipped with "...".')
    lines.append('Full values and every attempt: --detail full --json (observations[].answers).')
    return lines


def render_text(report: dict) -> str:
    """Bounded plain terminal view. Statistics retain their original sample scope."""
    if not isinstance(report, dict) or not report:
        return "DNS Probe\nNo report details available."
    if "execution" not in report:
        rows = json.dumps(report, ensure_ascii=False, indent=2).splitlines()
        return "\n".join(_clip(row) for row in rows[:98]) + ("\nMore details omitted; use JSON output." if len(rows)>98 else "")
    execution, assessment, coverage = (report.get(k) or {} for k in ("execution", "assessment", "coverage"))
    summary = report.get("summary") or {}
    lines = [f"DNS Probe {report.get('engine_version') or ''}".rstrip(),
             _clip(summary.get("headline") or "No assessment available"), "",
             f"Execution: {_terminal(execution.get('status', 'unknown'))} | Assessment: {_terminal(assessment.get('status', 'unknown'))}",
             f"Elapsed: {_milliseconds(report.get('duration_ms'))} ms | Exit: {execution.get('exit_code', '-')} | Stop: {_terminal(execution.get('stop_reason') or '-')}",
             f"Coverage: {coverage.get('completed', 0)}/{coverage.get('planned', 0)} completed; "
             f"{coverage.get('inconclusive', 0)} inconclusive; {coverage.get('skipped', 0)} skipped; {coverage.get('error', 0)} errors"]
    if not coverage.get("sufficient_for_assessment"):
        lines.append("Insufficient evidence for a complete assessment.")
    grouped = defaultdict(list)
    for observation in report.get("observations") or []:
        grouped[observation.get("path_id") or "unknown"].append(observation)
    if grouped:
        lines += ["", "Observed probes (all attempts; replies do not imply DNS success)"]
        rows=[]
        for path, observations in list(grouped.items())[:8]:
            counts = Counter(o.get("outcome") for o in observations)
            protocols = "/".join(sorted({o.get("transport") or "?" for o in observations}))
            families = "/".join(sorted({o.get("address_family") or "?" for o in observations}))
            rows.append([path, protocols, families, counts['response'], counts['error']+counts['timeout'], counts['cancelled']])
        lines += _table(["Path", "Protocol", "Family", "Replies", "Failed", "Cancelled"], rows, [26, 12, 12, 8, 8, 10])
        if len(grouped)>8: lines.append(f"{len(grouped)-8} additional paths omitted.")
        lines += _answer_view(report.get('observations') or [])
    statistics = report.get("statistics") or {}
    if statistics:
        lines += ["", "Repeat samples (cache state unknown; latency in ms)"]
        rows=[]
        for path, stats in list(statistics.items())[:8]:
            stats = stats or {}
            rows.append([path, stats.get('success_count', '-'), stats.get('failure_count', '-'), stats.get('cancelled_count', '-'),
                         _milliseconds(stats.get('p50_ms')), _milliseconds(stats.get('p95_ms'))])
        lines += _table(["Path", "Replies", "Failed", "Cancelled", "p50", "p95"], rows, [26, 8, 8, 10, 10, 10])
        lines.append("p95 needs 20 successful samples; '-' means unavailable.")
    findings = report.get("findings") or []
    if findings:
        lines += ["", "Findings"]
        for finding in sorted(findings,key=lambda f:{'error':0,'warning':1,'info':2}.get(f.get('severity'),3))[:6]:
            lines.append(_clip(f"[{finding.get('severity', 'info')}] {finding.get('id', '')} {finding.get('code', '')}"))
            lines.append(_clip("  " + str(finding.get('message', ''))))
        if len(findings)>6: lines.append(f"{len(findings)-6} additional findings omitted; use JSON/full evidence.")
    errors = report.get("errors") or []
    if errors:
        lines += ["", "Errors"]
        lines += [_clip(f"{e.get('code', '')}: {e.get('message', '')}") for e in errors[:4]]
    incomplete = [c for c in report.get("checks") or [] if c.get('status') in ('skipped','inconclusive','error')]
    if incomplete:
        lines += ["", "Not verified"]
        for check in incomplete[:6]:
            lines.append(_clip(f"{check.get('test_id', '?')} [{check.get('path_id', '?')}]: {check.get('reason_code') or check.get('status')}"))
        if len(incomplete)>6: lines.append(f"{len(incomplete)-6} additional incomplete checks omitted.")
    next_actions = report.get("next_actions") or []
    if next_actions:
        lines += ["", "Next steps (command previews; execute the JSON argv array)"]
        for action in next_actions[:2]:
            lines.append(_clip(action.get('reason_code') or action.get('id') or "Further diagnosis"))
            lines.append(_clip("  " + " ".join(str(arg) for arg in action.get('argv') or [])))
    omitted = report.get('omitted') or {}
    if report.get('truncated') or any(omitted.values()):
        lines += ["", _clip("Omitted from summary: " + ", ".join(f"{key}={value}" for key,value in omitted.items() if value))]
    artifacts=report.get('artifacts') or {}
    for key in ('report_path','evidence_path'):
        if artifacts.get(key): lines.append(_clip(f"{key}: {artifacts[key]}"))
    if summary.get('recommended_resolver_id'):
        lines.append(_clip("Observed candidate: " + summary['recommended_resolver_id']))
    lines = [_clip(line) for line in lines]
    if len(lines)>99:
        lines=lines[:99]+["Additional details omitted; use --detail full --json."]
    return "\n".join(lines)


def _atomic_write(path: Path, data: bytes):
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def save_artifacts(report: dict, directory) -> dict:
    """Write evidence first, then publish a matching report in a new run directory.

    report_sha256 is returned to the caller, never embedded in the bytes it hashes.
    A failed write raises, so no caller can claim the artifact set is complete.
    """
    base = Path(directory).expanduser().resolve()
    base.mkdir(parents=True, exist_ok=True)
    safe_id = re.sub(r"[^A-Za-z0-9_.-]", "_", str(report.get("run_id", "run")))[:100].strip(".") or "run"
    run_dir = base / safe_id
    while True:
        try:
            run_dir.mkdir(mode=0o700)
            break
        except FileExistsError:
            run_dir = base / f"{safe_id}-{uuid.uuid4().hex[:8]}"
    evidence_path = run_dir / "evidence.ndjson"
    report_path = run_dir / "report.json"
    evidence = "".join(encode(o) + "\n" for o in report.get("observations", [])).encode("utf-8")
    artifacts = {"report_path": str(report_path), "evidence_path": str(evidence_path),
                 "evidence_sha256": hashlib.sha256(evidence).hexdigest()}
    full = copy.deepcopy(report)
    full["artifacts"] = artifacts.copy()
    report_bytes = (encode(full) + "\n").encode("utf-8")
    if max(len(report_bytes), len(evidence)) > 64 * 1024 * 1024:
        raise OutputLimitError("Full artifact exceeds 64 MiB; reduce targets or max_attempts")
    _atomic_write(evidence_path, evidence)
    _atomic_write(report_path, report_bytes)
    artifacts["report_sha256"] = hashlib.sha256(report_bytes).hexdigest()
    return artifacts


def explain_report(report: dict, finding_id: str) -> dict:
    finding = next((f for f in report.get("findings", []) if f.get("id") == finding_id), None)
    if finding is None:
        raise ValueError(f"Finding not found: {finding_id}")
    ids = set(finding.get("evidence_ids", []))
    evidence = [o for o in report.get("observations", []) if o.get("id") in ids]
    known = {o.get("id") for o in evidence}
    return {"schema_version": report.get("schema_version", "1.0"), "run_id": report.get("run_id"),
            "finding": finding, "evidence": evidence, "missing_evidence_ids": sorted(ids - known),
            "checks": [c for c in report.get("checks", []) if ids.intersection(c.get("evidence_ids", []))]}


def compare_reports(before: dict, after: dict) -> dict:
    """Compare only frozen conditions; changed conditions never imply regression."""
    reasons = []
    for key in ("schema_version", "engine_version", "catalog_version", "ruleset_version", "profile_version", "implementation_fingerprint", "environment", "assessment"):
        left, right = before.get(key), after.get(key)
        if key == "assessment":
            left, right = (left or {}).get("scope"), (right or {}).get("scope")
        if left != right:
            reasons.append({"field": key, "reason_code": "CONDITIONS_CHANGED"})
    before_config = {k: v for k, v in before.get("effective_config", {}).items() if k != "output"}
    after_config = {k: v for k, v in after.get("effective_config", {}).items() if k != "output"}
    for key in sorted(before_config.keys() | after_config.keys()):
        if before_config.get(key) != after_config.get(key):
            reasons.append({"field": "effective_config." + key, "reason_code": "CONDITIONS_CHANGED"})
    for key in ("mode", "duration_ms", "interval_ms", "max_runs", "capacity_test"):
        if before.get("series", {}).get(key) != after.get("series", {}).get(key):
            reasons.append({"field": "series." + key, "reason_code": "CONDITIONS_CHANGED"})
    for report, label in ((before, "before"), (after, "after")):
        if not report.get("implementation_fingerprint"):
            reasons.append({"field": label + ".implementation_fingerprint", "reason_code": "MISSING_IMPLEMENTATION_FINGERPRINT"})
        if not str(report.get("schema_version", "")).startswith("1."):
            reasons.append({"field": label, "reason_code": "UNVERSIONED_OR_UNSUPPORTED"})
        if report.get("execution", {}).get("status") != "completed" or not report.get("coverage", {}).get("sufficient_for_assessment"):
            reasons.append({"field": label, "reason_code": "INCOMPLETE_EVIDENCE"})
        if "observations" not in report:
            reasons.append({"field": label, "reason_code": "FULL_REPORT_REQUIRED"})
    old = {f.get("code") for f in before.get("findings", [])}
    new = {f.get("code") for f in after.get("findings", [])}
    return {"schema_version": "1.0", "before_run_id": before.get("run_id"), "after_run_id": after.get("run_id"),
            "comparable": not reasons, "incompatibilities": reasons,
            "assessment_before": before.get("assessment"), "assessment_after": after.get("assessment"),
            "new_finding_codes": sorted(new - old), "resolved_finding_codes": sorted(old - new),
            "performance_regression": None,
            "performance_reason": "CONDITIONS_CHANGED" if reasons else "PAIRED_STATISTICAL_EVIDENCE_REQUIRED",
            "duration_delta_ms": after.get("duration_ms", 0) - before.get("duration_ms", 0)}
