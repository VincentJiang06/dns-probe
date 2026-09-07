"""Strict, deterministic request validation without discovery or network access."""
from __future__ import annotations

import copy
import ipaddress
import re
from urllib.parse import urlsplit

SCHEMA_VERSION = "1.0"
PROFILES = {"quick": (5000, 80), "standard": (15000, 240), "deep": (60000, 900)}
TEST_IDS = frozenset("ENV.SYSTEM RESOLVE.SYSTEM DNS.BASIC DNS.NEGATIVE DNS.TCP DNS.TRUNCATION DNS.EDNS DNS.DNSSEC_BEHAVIOR DNS.DNSSEC_VALIDATE DNS.CACHE DNS.CONSISTENCY DNS.IDENTITY DNS.ECS ENV.PROXY_PATH DNS.RECORDS DNS.CNAME DNS.DELEGATION DNS.DNS64 TRANSPORT.DOT TRANSPORT.DOH TRANSPORT.DOQ PERF.SAMPLE APP.CONNECT IDENTITY.OBSERVE".split())
RECORD_TYPES = frozenset("A AAAA CNAME MX TXT NS SOA CAA SRV PTR HTTPS SVCB DS DNSKEY RRSIG NSEC NSEC3 TLSA NAPTR DNAME ANY".split())
RCODES = frozenset("NOERROR FORMERR SERVFAIL NXDOMAIN NOTIMP REFUSED YXDOMAIN YXRRSET NXRRSET NOTAUTH NOTZONE BADVERS BADCOOKIE".split())
LIMIT_DEFAULTS = {"max_attempts": 240, "concurrency": 24, "per_endpoint": 4, "rate": 40, "endpoint_rate": 10}
LIMIT_CAPS = {"max_attempts": 100000, "concurrency": 256, "per_endpoint": 32, "rate": 1000, "endpoint_rate": 1000}
FIELDS = frozenset("schema_version profile workload budget_ms targets resolvers tests network_scope public_comparison limits expectations fail_on fixtures trust_anchors connect ecs records cname_max_depth delegation_roots force_family interface output session".split())


def _object(value, fields, where):
    if not isinstance(value, dict):
        raise ValueError(f"{where} must be an object")
    unknown = value.keys() - fields
    if unknown:
        raise ValueError(f"Unknown {where} field(s): {', '.join(sorted(unknown))}")


def _string(value, where, limit=1024):
    if not isinstance(value, str) or not value or len(value) > limit or any(ord(c) < 32 for c in value):
        raise ValueError(f"{where} must be nonempty text of at most {limit} characters")
    return value


def _integer(value, where, minimum=1, maximum=100000):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{where} must be an integer between {minimum} and {maximum}")
    return value


def _bool(value, where):
    if type(value) is not bool:
        raise ValueError(f"{where} must be boolean")
    return value


def _enum(value, values, where):
    if not isinstance(value, str) or value not in values:
        raise ValueError(f"{where} must be one of {', '.join(sorted(values))}")
    return value


def _list(value, where, maximum=100, minimum=0):
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise ValueError(f"{where} must contain {minimum} to {maximum} items")
    return value


def normalize_name(value: str) -> str:
    value = _string(value, "target name", 2048)
    if "://" in value:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Target URL must be HTTP(S), without credentials")
        value = parsed.hostname
    if value == ".":
        return "."
    if value.endswith(".."):
        raise ValueError("DNS name contains an empty label")
    value = value.removesuffix(".")
    try:
        name = value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Invalid internationalized target name") from exc
    if len(name) > 253 or any(not re.fullmatch(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?", label) for label in name.split(".")):
        raise ValueError("Invalid DNS name or label length")
    return name


def normalize_endpoint(value: str) -> str:
    value = _string(value, "resolver endpoint", 2048)
    if value == "system":
        return value
    if "://" not in value:
        try:
            ip = ipaddress.ip_address(value)
            return f"udp://[{ip}]:53" if ip.version == 6 else f"udp://{ip}:53"
        except ValueError:
            value = "udp://" + value
    try:
        parsed = urlsplit(value)
        scheme = {"dot": "tls", "doh": "https", "doq": "quic"}.get(parsed.scheme, parsed.scheme)
        if scheme not in {"udp", "tcp", "tls", "https", "quic"}:
            raise ValueError("Unsupported resolver endpoint scheme")
        if not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise ValueError("Resolver endpoint requires a host and cannot contain credentials or fragments")
        port = parsed.port if parsed.port is not None else (443 if scheme == "https" else 853 if scheme in {"tls", "quic"} else 53)
        if not 1 <= port <= 65535:
            raise ValueError("Invalid resolver port")
        try:
            host_ip = ipaddress.ip_address(parsed.hostname)
            host = f"[{host_ip}]" if host_ip.version == 6 else str(host_ip)
        except ValueError:
            if scheme in {"udp", "tcp"}:
                raise ValueError("UDP and TCP resolver endpoints require a literal IP address")
            host = normalize_name(parsed.hostname)
        if scheme != "https" and (parsed.path not in {"", "/"} or parsed.query):
            raise ValueError("Only HTTPS resolver endpoints accept a path/query")
        if scheme == "https":
            suffix = parsed.path or "/dns-query"
            if parsed.query:
                suffix += "?" + parsed.query
            return f"https://{host}" + (f":{port}" if port != 443 else "") + suffix
        return f"{scheme}://{host}:{port}"
    except ValueError as exc:
        # Do not echo original input: it may contain credentials.
        raise ValueError(str(exc)) from exc


def _types(value, where="types"):
    return list(dict.fromkeys(_enum(t, RECORD_TYPES, where) for t in _list(value, where, 32, 1)))


def normalize_request(raw: dict) -> dict:
    """Return a deep independent canonical request; unknown fields are errors."""
    _object(raw, FIELDS, "request")
    source = copy.deepcopy(raw)
    version = source.get("schema_version", SCHEMA_VERSION)
    if not isinstance(version, str) or not re.fullmatch(r"1\.\d+", version):
        raise ValueError("Unsupported schema_version; supported major is 1")
    profile = _enum(source.get("profile", "standard"), PROFILES, "profile")
    result = {
        "schema_version": version, "profile": profile,
        "workload": _enum(source.get("workload", "general"), {"general", "hong-kong", "mainland", "custom"}, "workload"),
        "budget_ms": _integer(source.get("budget_ms", PROFILES[profile][0]), "budget_ms", 1, 600000),
        "targets": [], "resolvers": [],
        "tests": source.get("tests", "auto"),
        "network_scope": _enum(source.get("network_scope", "public"), {"system", "public", "private", "all"}, "network_scope"),
        "public_comparison": _bool(source.get("public_comparison", False), "public_comparison"),
        "limits": {**LIMIT_DEFAULTS, "max_attempts": PROFILES[profile][1]},
        "expectations": [],
        "fail_on": _enum(source.get("fail_on", "error"), {"error", "warning", "never"}, "fail_on"),
    }
    if isinstance(result["tests"], str):
        _enum(result["tests"], {"auto", "all"}, "tests")
    else:
        result["tests"] = list(dict.fromkeys(_enum(t, TEST_IDS, "test ID") for t in _list(result["tests"], "tests", 64)))
    limits = source.get("limits", {})
    _object(limits, LIMIT_DEFAULTS.keys(), "limits")
    for key, value in limits.items():
        result["limits"][key] = _integer(value, f"limits.{key}", 1, LIMIT_CAPS[key])
    for target in _list(source.get("targets", []), "targets"):
        _object(target, {"name", "types", "allow_public", "app"}, "target")
        item = {"name": normalize_name(target.get("name")), "types": _types(target.get("types", ["A", "AAAA"])),
                "allow_public": _bool(target.get("allow_public", False), "target.allow_public")}
        if "app" in target:
            app = target["app"]
            _object(app, {"port", "tls", "server_name", "ca_file"}, "target.app")
            item["app"] = {"port": _integer(app.get("port", 443), "app.port", 1, 65535), "tls": _bool(app.get("tls", True), "app.tls")}
            if "server_name" in app:
                item["app"]["server_name"] = normalize_name(app["server_name"])
            if "ca_file" in app:
                item["app"]["ca_file"] = _string(app["ca_file"], "app.ca_file", 4096)
        result["targets"].append(item)
    ids = set()
    for index, resolver in enumerate(_list(source.get("resolvers", []), "resolvers", 8)):
        _object(resolver, {"id", "endpoint", "bootstrap_ips", "ca_file"}, "resolver")
        endpoint = normalize_endpoint(resolver.get("endpoint"))
        identifier = _string(resolver.get("id", "system" if endpoint == "system" else f"resolver-{index + 1}"), "resolver.id", 100)
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", identifier) or identifier in ids:
            raise ValueError("Resolver IDs must be unique and use letters, numbers, dot, dash or underscore")
        ids.add(identifier)
        ips = []
        for ip in _list(resolver.get("bootstrap_ips", []), "bootstrap_ips", 8):
            try:
                ips.append(str(ipaddress.ip_address(ip)))
            except ValueError as exc:
                raise ValueError("bootstrap_ips must contain IP literals") from exc
        item = {"id": identifier, "endpoint": endpoint, "bootstrap_ips": ips}
        if "ca_file" in resolver:
            item["ca_file"] = _string(resolver["ca_file"], "resolver.ca_file", 4096)
        result["resolvers"].append(item)
    for expectation in _list(source.get("expectations", []), "expectations", 500):
        _object(expectation, {"target", "type", "rcode", "min_answers", "max_answers", "answers", "resolver_id", "required", "ad"}, "expectation")
        item = {"target": normalize_name(expectation.get("target")), "type": _enum(expectation.get("type", "A"), RECORD_TYPES, "expectation.type")}
        for key in ("rcode", "min_answers", "max_answers", "answers", "resolver_id", "required", "ad"):
            if key not in expectation:
                continue
            val = expectation[key]
            if key == "rcode":
                val = _enum(val, RCODES, "expectation.rcode")
            elif key in {"min_answers", "max_answers"}:
                val = _integer(val, f"expectation.{key}", 0, 10000)
            elif key in {"required", "ad"}:
                val = _bool(val, f"expectation.{key}")
            elif key == "answers":
                val = [_string(a, "expectation answer", 4096) for a in _list(val, "expectation.answers", 100)]
            else:
                val = _string(val, "expectation.resolver_id", 100)
            item[key] = val
        if item.get("max_answers", 10000) < item.get("min_answers", 0):
            raise ValueError("expectation.max_answers cannot be below min_answers")
        result["expectations"].append(item)
    expectation_keys=set()
    for expectation in result['expectations']:
        target=next((t for t in result['targets'] if t['name']==expectation['target']),None)
        if target is None or expectation['type'] not in target['types']:
            raise ValueError('Each expectation must match an explicit target and one of its requested types')
        if result['resolvers'] and expectation.get('resolver_id') and expectation['resolver_id'] not in ids:
            raise ValueError('expectation.resolver_id must match an explicit resolver ID')
        key=(expectation['target'],expectation['type'],expectation.get('resolver_id'))
        if key in expectation_keys:
            raise ValueError('Duplicate expectation for the same target, type and resolver')
        expectation_keys.add(key)
    if "fixtures" in source:
        from datetime import datetime
        fixtures = []
        for fixture in _list(source["fixtures"], "fixtures", 100):
            _object(fixture, {"id", "name", "type", "rcode", "answers", "expires_at", "kind"}, "fixture")
            item = {"id": _string(fixture.get("id"), "fixture.id", 100), "name": normalize_name(fixture.get("name")),
                    "type": _enum(fixture.get("type", "A"), RECORD_TYPES, "fixture.type"),
                    "rcode": _enum(fixture.get("rcode", "NOERROR"), RCODES, "fixture.rcode"),
                    "kind": _string(fixture.get("kind"), "fixture.kind", 100),
                    "expires_at": _string(fixture.get("expires_at"), "fixture.expires_at", 100)}
            try:
                if datetime.fromisoformat(item["expires_at"].replace("Z", "+00:00")).tzinfo is None:
                    raise ValueError("timezone missing")
            except ValueError as exc:
                raise ValueError("fixture.expires_at must be an ISO 8601 timestamp with timezone") from exc
            if "answers" in fixture:
                item["answers"] = [_string(a, "fixture answer", 4096) for a in _list(fixture["answers"], "fixture.answers", 100)]
            fixtures.append(item)
        if len({f["id"] for f in fixtures}) != len(fixtures):
            raise ValueError("Fixture IDs must be unique")
        result["fixtures"] = fixtures
    if "trust_anchors" in source:
        result["trust_anchors"] = []
        for anchor in _list(source["trust_anchors"], "trust_anchors", 32):
            _object(anchor, {"name", "type", "value"}, "trust_anchor")
            result["trust_anchors"].append({"name": normalize_name(anchor.get("name")),
                                           "type": _enum(anchor.get("type"), {"DS", "DNSKEY"}, "trust_anchor.type"),
                                           "value": _string(anchor.get("value"), "trust_anchor.value", 8192)})
    if "connect" in source:
        result["connect"] = _bool(source["connect"], "connect")
    if "ecs" in source:
        try:
            result["ecs"] = str(ipaddress.ip_network(_string(source["ecs"], "ecs", 100), strict=False))
        except ValueError as exc:
            raise ValueError("ecs must be an IPv4 or IPv6 CIDR prefix") from exc
    if "records" in source:
        result["records"] = _types(source["records"], "records")
    if "cname_max_depth" in source:
        result["cname_max_depth"] = _integer(source["cname_max_depth"], "cname_max_depth", 1, 64)
    if "delegation_roots" in source:
        try:
            result["delegation_roots"] = [str(ipaddress.ip_address(ip)) for ip in _list(source["delegation_roots"], "delegation_roots", 13, 1)]
        except ValueError as exc:
            raise ValueError("delegation_roots must be IP literals") from exc
    if "force_family" in source:
        result["force_family"] = _enum(source["force_family"], {"ipv4", "ipv6", "auto"}, "force_family")
    if "interface" in source:
        result["interface"] = _string(source["interface"], "interface", 100)
    if "session" in source:
        session = source["session"]
        _object(session, {"duration_ms", "interval_ms", "max_runs"}, "session")
        result["session"] = {key: _integer(value, "session." + key, 1, 1000 if key == "max_runs" else 3600000)
                             for key, value in session.items()}
    if "output" in source:
        output = source["output"]
        _object(output, {"format", "detail", "artifact_dir", "agent", "pretty"}, "output")
        result["output"] = {}
        for key, val in output.items():
            if key == "format":
                val = _enum(val, {"text", "json", "ndjson"}, "output.format")
            elif key == "detail":
                val = _enum(val, {"summary", "full"}, "output.detail")
            elif key in {"agent", "pretty"}:
                val = _bool(val, "output." + key)
            else:
                val = _string(val, "output.artifact_dir", 4096)
            result["output"][key] = val
        if output.get("pretty") and output.get("format", "json") != "json":
            raise ValueError("output.pretty requires output.format json")
    return result
