"""DNS Probe CLI: familiar DNS shorthand with bounded, JSON-first diagnostics."""
from __future__ import annotations

import argparse
import asyncio
import copy
from datetime import datetime, timezone
import importlib.resources
import hashlib
import json
import math
import os
from pathlib import Path
import queue
import re
import stat
import sys
import threading
import time
import uuid

from . import __version__
from .config import RECORD_TYPES, normalize_request
from .report import OutputLimitError, compare_reports, encode, escape_json_controls, explain_report, render_text, save_artifacts, summarize

MAX_INPUT_BYTES = 1024 * 1024
MAX_OUTPUT_BYTES = 64 * 1024 * 1024
COMMANDS = {"run", "plan", "capabilities", "schema", "explain", "compare", "observe", "bench"}


class InputError(ValueError):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise InputError(message)

    def parse_args(self, args=None, namespace=None):
        argv = list(sys.argv[1:] if args is None else args)
        request_parsers = getattr(self, "request_parsers", {})
        if argv and argv[0] in request_parsers:
            # Intermixed parsing belongs to the selected child: argparse cannot
            # combine parse_intermixed_args() with a subparser positional itself.
            result = request_parsers[argv[0]].parse_intermixed_args(argv[1:], namespace)
            result.command = argv[0]
            return result
        return super().parse_args(argv, namespace)


def duration_ms(value):
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)(ms|s|m|h)?", value)
    if not match:
        raise argparse.ArgumentTypeError("Duration must be a positive number followed by ms, s, m or h")
    milliseconds = float(match[1]) * {"ms": 1, "s": 1000, "m": 60000, "h": 3600000, None: 1000}[match[2]]
    if not math.isfinite(milliseconds) or not 1 <= milliseconds <= 3600000:
        raise argparse.ArgumentTypeError("Duration must be between 1 ms and 1 hour")
    return int(milliseconds)


def _output_options(parser):
    output = parser.add_argument_group("output")
    output.add_argument("--agent", action="store_true", default=None, help="Compatibility alias for the default JSON summary; never prompts")
    formats = output.add_mutually_exclusive_group()
    formats.add_argument("--format", choices=("text", "json", "ndjson"), default=None,
                         help="Output format (default: json); text is the human-readable view")
    formats.add_argument("--json", dest="format", action="store_const", const="json", help="Alias for --format json")
    formats.add_argument("--jsonl", dest="format", action="store_const", const="ndjson", help="Alias for --format ndjson; one JSON object per line")
    formats.add_argument("--human", dest="format", action="store_const", const="text", help="Alias for --format text; readable diagnostic tables")
    output.add_argument("--pretty", action="store_true", default=None, help="Indent JSON by two spaces; incompatible with text/NDJSON")
    output.add_argument("--detail", choices=("summary", "full"), default=None,
                        help="Run JSON defaults to summary; text and offline results default to full")


def _request_options(parser):
    _output_options(parser)
    inputs = parser.add_argument_group("request input")
    inputs.add_argument("query", nargs="*", metavar="NAME|TYPE|@RESOLVER",
                        help="Names, uppercase RR types after a name, and @resolver; options may be intermixed")
    inputs.add_argument("--config", help="Explicit base JSON configuration; no implicit project configuration")
    group = inputs.add_mutually_exclusive_group()
    group.add_argument("--request-file")
    group.add_argument("--request-json", help="Literal JSON, or - to read stdin")
    parser = parser.add_argument_group("diagnostic options")
    parser.add_argument("--profile", choices=("quick", "standard", "deep"), help="quick: 5s, standard: 15s (default), deep: 60s")
    parser.add_argument("--workload", choices=("general", "hong-kong", "mainland", "custom"))
    parser.add_argument("--budget", type=duration_ms, help="Wall-clock budget, e.g. 5s or 500ms")
    parser.add_argument("-d", "--domain", action="append", help="Target name or HTTP(S) URL; repeatable")
    parser.add_argument("-t", "--type", dest="types", action="append", help="DNS RR type; repeatable")
    parser.add_argument("-r", "--resolver", action="append", help="Explicit system, IP, udp://, tcp://, tls://, https:// or quic:// endpoint")
    parser.add_argument("--tests", help="auto, all, or comma-separated stable test IDs")
    parser.add_argument("--network-scope", choices=("system", "private", "public", "all"))
    parser.add_argument("--public-comparison", action="store_true", default=None)
    parser.add_argument("--fail-on", choices=("warning", "error", "never"))
    parser.add_argument("--artifact-dir", help="Save full report and evidence in a new run subdirectory")
    parser.add_argument("--max-attempts", type=int)
    parser.add_argument("--concurrency", type=int)
    parser.add_argument("--per-endpoint", type=int)
    parser.add_argument("--rate", type=int, help="Maximum global DNS attempts/second")
    parser.add_argument("--endpoint-rate", type=int)
    parser.add_argument("--connect", action="store_true", default=None, help="Explicitly opt into APP.CONNECT")
    parser.add_argument("--ecs", help="Explicit ECS prefix (CIDR); never inferred from local network")
    parser.add_argument("--interface", help="Explicit source interface name")
    parser.add_argument("--force-family", choices=("auto", "ipv4", "ipv6"))


def build_parser():
    parser = Parser(prog="dnsprobe", description="DNS Probe — bounded DNS diagnostics. JSON by default; no command means run.",
                    formatter_class=argparse.RawDescriptionHelpFormatter,
                    epilog="Examples:\n  dnsprobe example.com A AAAA @1.1.1.1 --human\n  dnsprobe example.com --profile quick\n  dnsprobe plan example.com --pretty\n  dnsprobe -d example.com -t A -r 1.1.1.1\n  dnsprobe --request-json - --jsonl\n\nUppercase known types after a name apply to all targets; lowercase names stay names.\nNamed targets/resolvers/types precede shorthand entries when combined.\nUse an explicit run command for a name such as plan: dnsprobe run plan.\nUse -d A when an uppercase RR type is a literal host name.\n\nExit codes: 0 pass, 1 findings, 2 invalid input, 3 incomplete, 4 tool error, 130 interrupted.")
    parser.add_argument("--version", action="version", version=f"dnsprobe {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    parser.request_parsers = {}
    for command in ("run", "plan", "observe", "bench"):
        child = sub.add_parser(command, help={"run": "Run a bounded diagnostic", "plan": "Show selected work without network access", "observe": "Explicit bounded time series", "bench": "Explicit bounded resolver benchmark"}[command])
        parser.request_parsers[command] = child
        _request_options(child)
        if command in {"observe", "bench"}:
            child.add_argument("--duration", type=duration_ms, help="Required total duration; at most one hour")
            child.add_argument("--interval", type=duration_ms, help="Observe sampling interval (required for observe)")
            child.add_argument("--max-runs", type=int, default=None, help="Hard sample-run cap, 1–1000 (default 100)")
    child = sub.add_parser("capabilities", help="Installed test catalog and platform support, offline")
    _output_options(child)
    child = sub.add_parser("schema", help="Print the packaged JSON Schema, offline")
    _output_options(child)
    child.add_argument("--kind", choices=("request", "report", "event"), default="report")
    child = sub.add_parser("explain", help="Read a finding and its evidence from a local full report")
    _output_options(child)
    child.add_argument("--report", required=True)
    child.add_argument("--finding", required=True)
    child = sub.add_parser("compare", help="Compare two local full reports, offline")
    _output_options(child)
    child.add_argument("before")
    child.add_argument("after")
    return parser


def _json_loads(text):
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise InputError(f"Duplicate JSON key: {key}")
            result[key] = value
        return result
    try:
        value = json.loads(text, object_pairs_hook=unique_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(InputError("JSON non-finite numbers are forbidden")))
    except json.JSONDecodeError as exc:
        raise InputError(f"Invalid JSON at line {exc.lineno}, column {exc.colno}") from exc
    if not isinstance(value, dict):
        raise InputError("JSON request/report must be an object")
    return value


def _read_file(path, max_bytes=MAX_INPUT_BYTES):
    target = Path(path).expanduser()
    try:
        info = target.stat()
        if not stat.S_ISREG(info.st_mode):
            raise InputError("Input path must be a regular file")
        if info.st_size > max_bytes:
            raise InputError(f"Input file exceeds {max_bytes} bytes")
        with target.open("r", encoding="utf-8") as handle:
            text = handle.read(max_bytes + 1)
        if len(text.encode("utf-8")) > max_bytes:
            raise InputError(f"Input file exceeds {max_bytes} bytes")
        return _json_loads(text)
    except (OSError, UnicodeError) as exc:
        raise InputError(f"Cannot read JSON file: {type(exc).__name__}") from exc


def _read_report(path):
    value = _read_file(path, MAX_OUTPUT_BYTES)
    import jsonschema
    resource = importlib.resources.files("dnsprobe").joinpath("schemas", "report.schema.json")
    schema = json.loads(resource.read_text(encoding="utf-8"))
    error = next(jsonschema.Draft202012Validator(schema).iter_errors(value), None)
    if error is not None:
        location = ".".join(str(part) for part in error.path) or "report"
        raise InputError(f"Invalid report schema at {location}: {error.validator} constraint failed")
    return value


def _read_stdin(deadline):
    if sys.stdin.isatty():
        raise InputError("--request-json - requires piped JSON; interactive prompting is disabled")
    chunks, length = [], 0
    try:
        fd = sys.stdin.fileno()
    except (AttributeError, OSError):
        text = sys.stdin.read(MAX_INPUT_BYTES + 1)
        if len(text.encode()) > MAX_INPUT_BYTES:
            raise InputError("JSON input exceeds 1 MiB")
        return _json_loads(text)
    # Windows select() cannot wait on a pipe. Low-level reads in a daemon worker
    # keep the same deadline contract on every platform without a buffered stdin
    # lock that could block interpreter shutdown when the producer never closes.
    incoming = queue.Queue()
    def read_pipe():
        remaining_bytes = MAX_INPUT_BYTES + 1
        try:
            while remaining_bytes:
                chunk = os.read(fd, min(65536, remaining_bytes))
                incoming.put(chunk)
                if not chunk:
                    return
                remaining_bytes -= len(chunk)
        except OSError as exc:
            incoming.put(exc)
    threading.Thread(target=read_pipe, name="dnsprobe-stdin", daemon=True).start()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise InputError("Deadline expired while reading JSON input")
        try:
            chunk = incoming.get(timeout=remaining)
        except queue.Empty as exc:
            raise InputError("Deadline expired while reading JSON input") from exc
        if isinstance(chunk, OSError):
            raise InputError("Cannot read JSON input") from chunk
        if not chunk:
            break
        chunks.append(chunk)
        length += len(chunk)
        if length > MAX_INPUT_BYTES:
            raise InputError("JSON input exceeds 1 MiB")
    try:
        return _json_loads(b"".join(chunks).decode("utf-8"))
    except UnicodeError as exc:
        raise InputError("JSON input must be UTF-8") from exc


def _merge(left, right):
    result = copy.deepcopy(left)
    for key, value in right.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def prepare_request(args, started):
    raw = _read_file(args.config) if args.config else {}
    # JSON arriving on stdin cannot supply its budget until it has been read;
    # use explicit CLI options, then an already-loaded valid base-config budget.
    config_budget = raw.get("budget_ms")
    if type(config_budget) is not int or not 1 <= config_budget <= 3600000:
        config_budget = None  # Final merged validation still rejects invalid values.
    config_profile = raw.get("profile") if isinstance(raw.get("profile"), str) else None
    initial_budget = args.budget or config_budget or {"quick": 5000, "deep": 60000}.get(args.profile or config_profile, 15000)
    if args.request_file:
        raw = _merge(raw, _read_file(args.request_file))
    if args.request_json:
        data = _read_stdin(started + initial_budget / 1000) if args.request_json == "-" else _json_loads(args.request_json)
        if len(args.request_json.encode("utf-8")) > MAX_INPUT_BYTES:
            raise InputError("JSON input exceeds 1 MiB")
        raw = _merge(raw, data)
    domains, types, resolvers = list(args.domain or []), [value.upper() for value in args.types or []], list(args.resolver or [])
    for token in args.query:
        if token.startswith("@"):
            if len(token) == 1:
                raise InputError("@resolver requires a nonempty resolver endpoint")
            resolvers.append(token[1:])
        elif domains and token in RECORD_TYPES:
            types.append(token)
        else:
            domains.append(token)
    explicit = {}
    for key in ("profile", "workload", "network_scope", "public_comparison", "fail_on", "connect", "ecs", "force_family", "interface"):
        if getattr(args, key, None) is not None:
            explicit[key] = getattr(args, key)
    if args.budget is not None:
        explicit["budget_ms"] = args.budget
    if domains:
        explicit["targets"] = [{"name": domain, **({"types": types} if types else {})} for domain in domains]
    elif types:
        if not raw.get("targets"):
            raise InputError("--type requires targets from --domain or JSON")
        explicit["targets"] = [{**target, "types": types} for target in raw["targets"]]
    if resolvers:
        explicit["resolvers"] = [{"endpoint": endpoint} for endpoint in resolvers]
    if args.tests is not None:
        explicit["tests"] = args.tests if args.tests in {"auto", "all"} else args.tests.split(",")
    limits = {key: getattr(args, key) for key in ("max_attempts", "concurrency", "per_endpoint", "rate", "endpoint_rate") if getattr(args, key) is not None}
    if limits:
        explicit["limits"] = limits
    output = {key: getattr(args, key) for key in ("format", "detail", "agent", "artifact_dir", "pretty") if getattr(args, key) is not None}
    if output:
        explicit["output"] = output
    merged = _merge(raw, explicit)
    args.explicit_rate = "rate" in merged.get("limits", {})
    return normalize_request(merged)


def error_report(code, message, exit_code=2):
    message = str(message)[:2048]
    return {"schema_version": "1.0", "engine_version": __version__, "catalog_version": "1", "ruleset_version": "1", "profile_version": "1",
            "run_id": "error-" + uuid.uuid4().hex[:12], "started_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), "duration_ms": 0,
            "execution": {"status": "cancelled" if exit_code == 130 else "error", "stop_reason": code, "exit_code": exit_code},
            "assessment": {"status": "unknown", "scope": "none"},
            "coverage": {"planned": 0, "completed": 0, "inconclusive": 0, "skipped": 0, "error": 0, "sufficient_for_assessment": False, "required_unresolved": [], "not_selected": []},
            "summary": {"headline": message, "recommended_resolver_id": None}, "findings": [], "next_actions": [], "artifacts": {},
            "errors": [{"code": code, "message": message}]}


def _print(value, format="json", *, pretty=False):
    if format == "text":
        rendered = render_text(value)
    elif pretty:
        rendered = escape_json_controls(json.dumps(value, ensure_ascii=False, allow_nan=False, indent=2))
    else:
        rendered = encode(value)
    if len(rendered.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise OutputLimitError("Full output exceeds 64 MiB; reduce targets or max_attempts")
    print(rendered, flush=True)


class EventWriter:
    def __init__(self):
        self.seq = 0
        self.run_id = None
        self.finished = False

    def __call__(self, event):
        if event.get("event") == "run_finished":
            return
        self.write(event)

    def write(self, event):
        if self.finished:
            return
        value = dict(event)
        self.run_id = self.run_id or value.get("run_id") or "cli-" + uuid.uuid4().hex[:12]
        self.seq += 1
        value.update(schema_version="1.0", run_id=self.run_id, seq=self.seq)
        if value.get("event") == "finding":
            value["provisional"] = True
        _print(value)
        self.finished = value.get("event") == "run_finished"

    def finish(self, report, detail="summary"):
        report = {**report, "run_id": self.run_id or report["run_id"]}
        self.write({"event": "run_finished", "report": report if detail == "full" else summarize(report),
                    "exit_code": report["execution"]["exit_code"], "run_id": report["run_id"]})


async def run_series(request, args, started):
    """Explicit finite observation, retaining every target observation and timestamp."""
    from .engine import run, Scheduler, sample_statistics
    if not args.duration or not request["resolvers"] or not request["targets"]:
        raise InputError(f"{args.command} requires explicit --duration, resolver(s), and domain target(s)")
    if not 1 <= args.max_runs <= 1000:
        raise InputError("--max-runs must be between 1 and 1000")
    if args.command == "observe" and not args.interval:
        raise InputError("observe requires --interval")
    if args.command == "bench" and not args.explicit_rate:
        raise InputError("bench requires an explicit --rate")
    interval = (args.interval or max(100, int(1000 / request["limits"]["rate"]))) / 1000
    duration = args.duration / 1000
    deadline = started + duration
    shared_scheduler = Scheduler(deadline, request["limits"])
    samples, all_observations, all_checks, all_findings, all_errors = [], [], [], [], []
    expected_runs = min(args.max_runs, max(1, math.ceil(duration / interval)))
    last_report = None
    interrupted = False
    resource_stop = None
    for index in range(expected_runs):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        if shared_scheduler.stop_reason:
            resource_stop = shared_scheduler.stop_reason
            break
        config = copy.deepcopy(request)
        config["budget_ms"] = min(config["budget_ms"], max(1, int(remaining * 1000)))
        if args.command == "bench":
            # Bench is fixed diagnostic sampling, not resolver capacity estimation.
            config["tests"] = ["DNS.BASIC", "PERF.SAMPLE"]
        try:
            report = await run(config, deadline=min(deadline, time.monotonic() + config["budget_ms"] / 1000), scheduler=shared_scheduler)
        except asyncio.CancelledError:
            interrupted = True
            break
        last_report = report
        prefix = f"sample-{index + 1}:"
        def prefixed(value):
            value = copy.deepcopy(value)
            for key in ("id", "check_id"):
                if value.get(key):
                    value[key] = prefix + value[key]
            for key in ("evidence_ids",):
                if key in value:
                    value[key] = [prefix + identifier for identifier in value[key]]
            for snippet in value.get("evidence_summary", []):
                if snippet.get("id"):
                    snippet["id"] = prefix + snippet["id"]
                if snippet.get("check_id"):
                    snippet["check_id"] = prefix + snippet["check_id"]
            value["sample_index"] = index
            value["sample_started_at"] = report["started_at"]
            return value
        all_observations.extend(prefixed(o) for o in report.get("observations", []))
        all_checks.extend(prefixed(c) for c in report.get("checks", []))
        all_findings.extend(prefixed(f) for f in report.get("findings", []))
        all_errors.extend(report.get("errors", []))
        samples.append({"index": index, "started_at": report["started_at"], "duration_ms": report["duration_ms"],
                        "assessment": report["assessment"], "execution": report["execution"], "coverage": report["coverage"]})
        if report["execution"]["status"] == "cancelled":
            interrupted = True
            break
        wait = min(deadline, started + (index + 1) * interval) - time.monotonic()
        if wait > 0 and index + 1 < expected_runs:
            try:
                await asyncio.sleep(wait)
            except asyncio.CancelledError:
                interrupted = True
                break
    if last_report is None:
        result = error_report("INTERRUPTED" if interrupted else "DEADLINE_EXHAUSTED", "No complete sample run", 130 if interrupted else 3)
        result["execution"]["status"] = "cancelled" if interrupted else "partial"
        return result
    result = copy.deepcopy(last_report)
    result["run_id"] = args.command + "-" + uuid.uuid4().hex[:12]
    result["started_at"] = samples[0]["started_at"]
    result["duration_ms"] = (time.monotonic() - started) * 1000
    result.update(observations=all_observations, checks=all_checks, findings=all_findings, errors=all_errors)
    target_stats = {}
    for observation in all_observations:
        key = (observation.get("target_id"), observation.get("path_id"))
        stats = target_stats.setdefault(key, {"target_id": key[0], "path_id": key[1], "response_count": 0,
                                             "failure_count": 0, "cancelled_count": 0})
        outcome = observation.get("outcome")
        count = "response_count" if outcome == "response" else "cancelled_count" if outcome == "cancelled" else "failure_count"
        stats[count] += 1
    result["series"] = {"target_statistics": list(target_stats.values()), "mode": args.command, "duration_ms": args.duration, "interval_ms": round(interval * 1000), "samples": samples,
                        "sample_count": len(samples), "max_runs": args.max_runs, "capacity_test": False}
    coverage = {key: sum(sample["coverage"].get(key, 0) for sample in samples) for key in ("planned", "completed", "inconclusive", "skipped", "error")}
    coverage["required_unresolved"] = [f"sample-{s['index'] + 1}:{identifier}" for s in samples for identifier in s["coverage"].get("required_unresolved", [])]
    coverage["not_selected"] = last_report["coverage"].get("not_selected", [])
    coverage["sufficient_for_assessment"] = all(s["coverage"].get("sufficient_for_assessment") for s in samples)
    result["coverage"] = coverage
    states = {s["assessment"]["status"] for s in samples}
    result["assessment"]["status"] = next((state for state in ("fail", "unknown", "warn", "pass") if state in states), "unknown")
    fatal = any(s["execution"]["exit_code"] == 4 for s in samples)
    status = "cancelled" if interrupted else "error" if fatal else "partial" if resource_stop or any(s["execution"]["status"] in {"partial", "error"} for s in samples) else "completed"
    exit_code = 130 if interrupted else 4 if fatal else 3 if status == "partial" or not coverage["sufficient_for_assessment"] else max(s["execution"]["exit_code"] for s in samples)
    result["execution"] = {"status": status, "stop_reason": "interrupted" if interrupted else resource_stop or ("max_runs" if len(samples) == args.max_runs else "duration"), "exit_code": exit_code}
    result["summary"] = {"headline": f"{args.command}: {len(samples)} sample runs; assessment {result['assessment']['status']}", "recommended_resolver_id": None}
    result["next_actions"] = []
    result["effective_config"] = request
    result["config_hash"] = hashlib.sha256(json.dumps(request, sort_keys=True, default=str).encode()).hexdigest()
    result.pop("plan", None)  # A single last-sample plan would refer to stale unprefixed check IDs.
    result["statistics"] = {path: sample_statistics([o for o in all_observations
                            if o.get("path_id") == path and o.get("sample_kind") == "repeat_observed"])
                            for path in dict.fromkeys(o.get("path_id") for o in all_observations)}
    return result


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    # Resolve machine errors before argparse can write human-only stderr output.
    requested_format = next((arg.split("=", 1)[1] for arg in argv if arg.startswith("--format=")), None)
    if "--format" in argv:
        following = argv[argv.index("--format") + 1:]
        requested_format = following[0] if following else None
    if "--jsonl" in argv:
        requested_format = "ndjson"
    elif "--json" in argv:
        requested_format = "json"
    elif "--human" in argv:
        requested_format = "text"
    format = requested_format if requested_format in {"text", "ndjson"} else "json"
    pretty = "--pretty" in argv and format == "json"
    writer = EventWriter() if format == "ndjson" else None
    args = None
    try:
        if not argv or argv[0] not in COMMANDS | {"-h", "--help", "--version"}:
            argv.insert(0, "run")
        args = build_parser().parse_args(argv)
        started = time.monotonic()
        if args.command in {"run", "plan", "observe", "bench"}:
            request = prepare_request(args, started)
            output = request.get("output", {})
            format = output.get("format") or "json"
            detail = output.get("detail") or ("full" if format == "text" else "summary")
            pretty = output.get("pretty", False)
        else:
            format = args.format or "json"
            detail = args.detail or "full"
            pretty = bool(args.pretty)
            output = {}
        if pretty and format != "json":
            raise InputError("--pretty requires JSON output; it cannot be combined with text or NDJSON")
        writer = EventWriter() if format == "ndjson" else None
        if args.command == "schema":
            resource = importlib.resources.files("dnsprobe").joinpath("schemas", args.kind + ".schema.json")
            value = json.loads(resource.read_text(encoding="utf-8"))
        elif args.command == "capabilities":
            from .engine import TESTS
            value = {"schema_version": "1.0", "engine_version": __version__, "tests": TESTS,
                     "commands": sorted(COMMANDS), "profiles": {"quick": 5000, "standard": 15000, "deep": 60000},
                     "limits": {"max_targets": 100, "max_resolvers": 8, "summary_bytes": 8192},
                     "output_contract": {"default_format": "json", "default_detail": "summary", "summary_max_bytes": 8192,
                                         "pretty_expands_summary": True, "formats": ["json", "ndjson", "text"],
                                         "events": ["run_started", "plan_ready", "observation", "finding", "run_finished"],
                                         "offline_results": "full structured objects; NDJSON is one object per line",
                                         "terminal_detection": False},
                     "supported_transports": ["system", "udp", "tcp", "tls", "https", "quic"],
                     "fixture_policy": "Explicit fixtures with expiry; no owned test zone is automatically deployed",
                     "platform_support": {"macos": "implemented; native resolver helper + scutil discovery", "linux": "implemented; native resolver helper + resolv.conf discovery", "windows": "experimental; platform validation required"}}
        elif args.command == "plan":
            from .engine import plan
            value = plan(request)
        elif args.command == "explain":
            value = explain_report(_read_report(args.report), args.finding)
        elif args.command == "compare":
            value = compare_reports(_read_report(args.before), _read_report(args.after))
        elif args.command in {"observe", "bench"}:
            session = request.get("session", {})
            args.duration = args.duration if args.duration is not None else session.get("duration_ms")
            args.interval = args.interval if args.interval is not None else session.get("interval_ms")
            args.max_runs = args.max_runs if args.max_runs is not None else session.get("max_runs", 100)
            request["session"] = {"duration_ms": args.duration, "max_runs": args.max_runs}
            if args.interval is not None:
                request["session"]["interval_ms"] = args.interval
            # Input checks happen before invoking the engine or importing transports.
            if not args.duration or not request["resolvers"] or not request["targets"] or (args.command == "observe" and not args.interval) or (args.command == "bench" and not args.explicit_rate):
                raise InputError(f"{args.command} requires --duration, explicit targets/resolvers, and " + ("--interval" if args.command == "observe" else "--rate"))
            if writer:
                writer.write({"event": "run_started", "mode": args.command})
            value = asyncio.run(run_series(request, args, started))
        else:
            from .engine import run
            value = asyncio.run(run(request, event_sink=writer, deadline=started + request["budget_ms"] / 1000))
        if args.command in {"run", "observe", "bench"}:
            if writer and writer.run_id:
                value["run_id"] = writer.run_id
            if output.get("artifact_dir"):
                try:
                    value["artifacts"] = save_artifacts(value, output["artifact_dir"])
                except OSError as exc:
                    value["errors"].append({"code": "ARTIFACT_WRITE_FAILED", "message": f"Cannot save artifacts: {type(exc).__name__}"})
                    value["execution"] = {"status": "error", "stop_reason": "artifact_write_failed", "exit_code": 4}
            if writer:
                writer.finish(value, detail)
            else:
                _print(summarize(value) if detail == "summary" else value, format, pretty=pretty)
            return value["execution"]["exit_code"]
        _print(value, format, pretty=pretty)
        return 0
    except BrokenPipeError:
        # Prevent a second broken-pipe traceback during interpreter stream shutdown.
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass
        return 0
    except (InputError, ValueError, OSError) as exc:
        code = "OUTPUT_LIMIT_EXCEEDED" if isinstance(exc, OutputLimitError) else "INPUT_INVALID"
        artifacts = value.get("artifacts", {}) if isinstance(exc, OutputLimitError) and "value" in locals() else {}
        value = error_report(code, str(exc), 4 if isinstance(exc, OutputLimitError) else 2)
        value["artifacts"] = artifacts
        if writer:
            writer.finish(value, "full")
        else:
            _print(value, format, pretty=pretty and format == "json")
        return value["execution"]["exit_code"]
    except KeyboardInterrupt:
        value = error_report("INTERRUPTED", "Run interrupted by user", 130)
        if writer:
            writer.finish(value, "full")
        else:
            _print(value, format, pretty=pretty and format == "json")
        return 130
    except Exception as exc:
        value = error_report("INTERNAL_ERROR", f"Internal failure: {type(exc).__name__}", 4)
        if writer:
            writer.finish(value, "full")
        else:
            _print(value, format, pretty=pretty and format == "json")
        return 4
