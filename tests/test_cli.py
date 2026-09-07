"""Contract tests: real validation, reporting, and offline process boundaries."""
import importlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


def module(name):
    assert importlib.util.find_spec(name), f"Missing implementation: {name}"
    return importlib.import_module(name)


def example_report():
    return {
        "schema_version": "1.0", "engine_version": "1.0.0", "catalog_version": "1", "implementation_fingerprint": "fixture-source-sha256",
        "ruleset_version": "1", "profile_version": "1", "run_id": "test-run",
        "started_at": "2026-09-07T00:00:00Z", "duration_ms": 10,
        "execution": {"status": "completed", "stop_reason": None, "exit_code": 0},
        "assessment": {"status": "pass", "scope": "explicit_resolvers"},
        "coverage": {"planned": 1, "completed": 1, "inconclusive": 0, "skipped": 0, "error": 0,
                     "sufficient_for_assessment": True, "required_unresolved": [], "not_selected": []},
        "summary": {"headline": "Tests passed", "recommended_resolver_id": None},
        "findings": [], "next_actions": [], "artifacts": {}, "errors": [],
        "checks": [{"id": "c1", "test_id": "DNS.BASIC", "status": "pass", "evidence_ids": ["o1"]}],
        "observations": [{"id": "o1", "path_id": "local", "target_id": "example.com", "outcome": "response", "timing": {"total_ms": 2}}],
        "effective_config": {"profile": "standard", "targets": [{"name": "example.com"}], "limits": {"rate": 40}},
        "environment": {"platform": "test", "system_resolvers": []},
    }


@pytest.mark.parametrize("raw,expected", [
    ({}, ("standard", 15000)),
    ({"profile": "quick"}, ("quick", 5000)),
    ({"profile": "deep", "budget_ms": 250}, ("deep", 250)),
    ({"targets": [{"name": "https://EXAMPLE.com/path"}], "resolvers": [{"endpoint": "127.0.0.1"}]}, ("standard", 15000)),
    ({"output": {"pretty": True}}, ("standard", 15000)),
])
def test_request_defaults_and_normalization(raw, expected):
    normalize = module("dnsprobe.config").normalize_request
    value = normalize(raw)
    assert (value["profile"], value["budget_ms"]) == expected
    assert value["schema_version"] == "1.0"
    if raw.get("targets"):
        assert value["targets"] == [{"name": "example.com", "types": ["A", "AAAA"], "allow_public": False}]
        assert value["resolvers"][0]["endpoint"] == "udp://127.0.0.1:53"
    if raw.get("output"):
        assert value["output"] == raw["output"]
        import jsonschema
        schema_path = Path(__file__).resolve().parents[1] / "src/dnsprobe/schemas/request.schema.json"
        jsonschema.validate(raw, json.loads(schema_path.read_text()))
    assert normalize(value) == value


@pytest.mark.parametrize("raw", [
    {"typo": True}, {"schema_version": "2.0"}, {"budget_ms": True}, {"budget_ms": 0},
    {"limits": {"rate": 0}}, {"limits": {"concurrency": 10000}}, {"tests": ["DNS.TYPO"]},
    {"targets": [{"name": "abc", "unexpected": 1}]}, {"targets": [{"name": "a" * 64 + ".com"}]},
    {"targets": [{"name": "bad name.com"}]}, {"targets": [{"name": "example.com", "types": ["TYPO"]}]},
    {"targets": [{"name": "example.com", "types": ["mx"]}]},
    {"resolvers": [{"endpoint": "https://user:password@example.com/dns-query"}]},
    {"resolvers": [{"endpoint": "udp://example.com"}]},
    {"resolvers": [{"endpoint": "https://example.com/dns-query#secret"}]},
    {"resolvers": [{"id": "same", "endpoint": "127.0.0.1"}, {"id": "same", "endpoint": "127.0.0.2"}]},
    {"targets": [{"name": f"{i}.example.com"} for i in range(101)]},
    {"expectations": [{"target": "example.com", "type": "A", "min_answers": -1}]},
    {"output": {"pretty": "yes"}}, {"output": {"pretty": True, "format": "ndjson"}},
    {"output": {"pretty": True, "format": "text"}},
])
def test_request_rejects_invalid_inputs(raw):
    with pytest.raises(ValueError):
        module("dnsprobe.config").normalize_request(raw)


def test_report_summary_budget_artifacts_explain_and_comparison(tmp_path):
    reports = module("dnsprobe.report")
    report = example_report()
    report["findings"] = [{"id": f"f{i}", "code": "EXAMPLE", "severity": "warning", "message": "evidence " * 100,
                           "confidence": "low", "rule_id": "example/v1", "evidence_ids": ["o1"], "alternatives": []}
                          for i in range(20)]
    summary = reports.summarize(report)
    assert len(json.dumps(summary, ensure_ascii=False).encode()) <= 8192
    assert summary["truncated"] is True
    assert summary["omitted"]["findings"] >= 15
    assert summary["findings"][0]["evidence_summary"][0]["id"] == "o1"
    assert "observations" not in summary
    artifacts = reports.save_artifacts(report, tmp_path)
    assert Path(artifacts["report_path"]).exists()
    assert Path(artifacts["evidence_path"]).exists()
    saved = json.loads(Path(artifacts["report_path"]).read_text())
    assert saved["artifacts"]["evidence_path"] == artifacts["evidence_path"]
    assert artifacts["report_sha256"] and artifacts["evidence_sha256"]
    assert reports.save_artifacts(report, tmp_path)["report_path"] != artifacts["report_path"]
    explained = reports.explain_report(report, "f0")
    assert explained["evidence"][0]["id"] == "o1"
    changed = json.loads(json.dumps(report))
    changed["effective_config"]["profile"] = "deep"
    comparison = reports.compare_reports(report, changed)
    assert comparison["comparable"] is False
    assert comparison["performance_regression"] is None
    assert reports.compare_reports(report, report)["comparable"] is True


def call_cli(*args, input=None):
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}
    return subprocess.run([sys.executable, "-m", "dnsprobe", *args], input=input, text=True, capture_output=True, env=env, timeout=5)


@pytest.mark.parametrize("args,input", [
    (["run", "--budget", "nonsense"], None),
    (["run", "--bogus"], None),
    (["run", "--agent", "--request-json", "-"], '{"unexpected":1}'),
    (["run", "--agent", "--request-json", "-"], '{"profile":"quick","profile":"deep"}'),
    (["observe", "--agent"], None),
    (["bench", "--agent", "--resolver", "127.0.0.1"], None),
    (["run", "--json", "--bogus"], None),
    (["run", "--json", "--jsonl"], None),
    (["run", "--pretty", "--format", "ndjson"], None),
    (["run", "example.com", "@"], None),
    (["plan", "example.com", "--human", "--json"], None),
    (["plan", "example.com", "--bogus", "other.test"], None),
])
def test_cli_machine_errors_are_one_json_result(args, input):
    module("dnsprobe.cli")
    result = call_cli(*args, input=input)
    assert result.returncode == 2, result.stderr
    value = json.loads(result.stdout)
    if value.get("event") == "run_finished":
        value = value["report"]
    assert value["execution"]["status"] == "error"
    assert value["execution"]["exit_code"] == 2
    assert value["errors"][0]["code"]
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize("flags,pretty", [([], False), (["--json"], False), (["--jsonl"], False),
                                          (["--pretty"], True), (["--json", "--pretty"], True)])
def test_packaged_schemas_and_offline_cli(flags, pretty):
    module("dnsprobe.cli")
    for kind in ("request", "report", "event"):
        result = call_cli("schema", "--kind", kind, *flags)
        assert result.returncode == 0, result.stderr
        schema = json.loads(result.stdout)
        assert schema["$schema"].endswith("2020-12/schema")
        assert (len(result.stdout.splitlines()) > 1) is pretty
    result = call_cli("plan", *flags, "--domain", "example.com")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["checks"]
    assert (len(result.stdout.splitlines()) > 1) is pretty
    assert "\x1b" not in result.stdout
    result = call_cli("capabilities", *flags)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["commands"]
    assert (len(result.stdout.splitlines()) > 1) is pretty


@pytest.mark.parametrize('command,tokens,names,types,resolvers', [
    ('plan', ['example.com', 'A', 'AAAA', '@1.1.1.1'], ['example.com'], ['A', 'AAAA'], ['udp://1.1.1.1:53']),
    ('plan', ['@1.1.1.1', 'example.com', '--profile', 'quick', 'A', 'other.test', '@8.8.8.8'], ['example.com', 'other.test'], ['A'], ['udp://1.1.1.1:53', 'udp://8.8.8.8:53']),
    ('plan', ['a', 'aaaa', 'example.com'], ['a', 'aaaa', 'example.com'], ['A', 'AAAA'], []),
    ('plan', ['A', 'example.com', 'TXT'], ['a', 'example.com'], ['TXT'], []),
    ('plan', ['example.com', 'UNKNOWN'], ['example.com', 'unknown'], ['A', 'AAAA'], []),
    ('plan', ['example.com', '-d', 'named.test', 'A', '-t', 'AAAA', '@1.1.1.1', '-r', '8.8.8.8'], ['named.test', 'example.com'], ['AAAA', 'A'], ['udp://8.8.8.8:53', 'udp://1.1.1.1:53']),
    ('plan', ['-d', 'example.com', 'A'], ['example.com'], ['A'], []),
    ('plan', ['example.com', '-t', 'mx', '-r', '127.0.0.1'], ['example.com'], ['MX'], ['udp://127.0.0.1:53']),
    ('plan', ['--type', 'aaaa', '--request-json', '{"targets":[{"name":"configured.test"}]}'], ['configured.test'], ['AAAA'], []),
    ('plan', ['example.com', '--request-json', '{"targets":[{"name":"old.test"}]}'], ['example.com'], ['A', 'AAAA'], []),
    ('run', ['plan', 'A', '@127.0.0.1'], ['plan'], ['A'], ['udp://127.0.0.1:53']),
    ('observe', ['example.com', '--duration', '500ms', '@127.0.0.1', '--interval', '100ms', 'A'], ['example.com'], ['A'], ['udp://127.0.0.1:53']),
    ('bench', ['example.com', '--duration', '500ms', 'A', '@127.0.0.1', '--rate', '5'], ['example.com'], ['A'], ['udp://127.0.0.1:53']),
])
def test_request_shorthand_and_mixed_option_order(command, tokens, names, types, resolvers):
    import time
    cli = module('dnsprobe.cli')
    args = cli.build_parser().parse_args([command, *tokens])
    request = cli.prepare_request(args, time.monotonic())
    assert [target['name'] for target in request['targets']] == names
    assert all(target['types'] == types for target in request['targets'])
    assert [resolver['endpoint'] for resolver in request['resolvers']] == resolvers
    if command == 'plan':
        result = call_cli(command, *tokens)
        assert result.returncode == 0, result.stdout
        assert [target['name'] for target in json.loads(result.stdout)['targets']] == names


@pytest.mark.asyncio
async def test_live_cli_json_ndjson_artifacts_and_series(tmp_path):
    import asyncio
    import dns.message
    import dns.rrset
    import jsonschema

    received_queries = []
    class LocalResolver(asyncio.DatagramProtocol):
        def connection_made(self, transport):
            self.transport = transport
        def datagram_received(self, data, address):
            query = dns.message.from_wire(data)
            received_queries.append(query)
            if query.question[0].name.to_text() == 'blackhole.test.':
                return
            response = dns.message.make_response(query)
            response.answer.append(dns.rrset.from_text(query.question[0].name, 30, 'IN', 'A', '192.0.2.10'))
            self.transport.sendto(response.to_wire(), address)

    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(LocalResolver, local_addr=('127.0.0.1', 0))
    endpoint = f"udp://127.0.0.1:{transport.get_extra_info('sockname')[1]}"
    request = {"profile":"quick", "budget_ms":1000, "targets":[{"name":"cli.test","types":["A"]}],
               "resolvers":[{"endpoint":endpoint}], "tests":["DNS.BASIC"], "network_scope":"system"}
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}
    async def invoke(*args):
        proc = await asyncio.create_subprocess_exec(sys.executable, '-m', 'dnsprobe', *args,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env)
        stdout, stderr = await asyncio.wait_for(proc.communicate(), 5)
        return proc.returncode, stdout.decode(), stderr.decode()
    try:
        code, stdout, stderr = await invoke('cli.test', 'A', '@' + endpoint, '--request-json', json.dumps(request), '--artifact-dir', str(tmp_path))
        assert code == 0, (stdout, stderr)
        summary = json.loads(stdout)
        assert 'observations' not in summary, 'default CLI must return a compact summary'
        assert len(stdout.splitlines()) == 1
        assert '\x1b' not in stdout
        full = json.loads(Path(summary['artifacts']['report_path']).read_text())
        schema_dir = Path(__file__).resolve().parents[1] / 'src/dnsprobe/schemas'
        for value in (summary, full):
            jsonschema.validate(value, json.loads((schema_dir/'report.schema.json').read_text()))
        code, stdout, stderr = await invoke('run', '--jsonl', '--request-json', json.dumps(request))
        assert code == 0, (stdout, stderr)
        events = [json.loads(line) for line in stdout.splitlines()]
        assert events[0]['event'] == 'run_started'
        assert [e['seq'] for e in events] == list(range(1, len(events)+1))
        assert len({e['run_id'] for e in events}) == 1
        assert [e['event'] for e in events].count('run_finished') == 1
        for event in events:
            jsonschema.validate(event, json.loads((schema_dir/'event.schema.json').read_text()))
        code, stdout, stderr = await invoke('observe', 'cli.test', '--agent', '--detail', 'full', '--duration', '500ms',
                                            'A', '@' + endpoint, '--interval', '100ms', '--max-runs', '3', '--request-json', json.dumps(request))
        assert code == 0, (stdout, stderr)
        series = json.loads(stdout)
        assert series['series']['sample_count'] == 3
        assert len(series['observations']) == 3
        assert len({o['id'] for o in series['observations']}) == 3
        assert all(o['sample_started_at'].endswith('Z') for o in series['observations'])
        assert series['series']['target_statistics'][0]['response_count'] == 3
        import hashlib
        assert series['config_hash'] == hashlib.sha256(json.dumps(series['effective_config'], sort_keys=True, default=str).encode()).hexdigest()
        request['limits'] = {'max_attempts': 2}
        previous_queries = len(received_queries)
        code, stdout, stderr = await invoke('observe', '--agent', '--detail', 'full', '--duration', '500ms',
                                            '--interval', '100ms', '--max-runs', '5', '--request-json', json.dumps(request))
        series = json.loads(stdout)
        assert code == 3, (stdout, stderr)
        assert len(received_queries) - previous_queries <= 2, 'series must share a global DNS attempt cap'
        assert series['cost']['dns_attempts'] <= 2
        assert sum(o.get('outcome') == 'response' for o in series['observations']) <= 2
        # Characterize real process cancellation: one complete terminal event, exit 130.
        import signal
        request['budget_ms'] = 10000
        request['targets'] = [{'name':'blackhole.test','types':['A']}]
        request.pop('limits', None)
        process = await asyncio.create_subprocess_exec(sys.executable, '-m', 'dnsprobe', 'run', '--format', 'ndjson',
                            '--request-json', json.dumps(request), stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE, env=env)
        prefix = []
        while True:
            line = await asyncio.wait_for(process.stdout.readline(), 3)
            assert line, 'process ended before plan_ready'
            prefix.append(json.loads(line))
            if prefix[-1]['event'] == 'plan_ready':
                break
        if os.name == 'nt':
            process.terminate()
            await process.communicate()
            return  # Windows console CTRL events require a separate console process group.
        process.send_signal(signal.SIGINT)
        stdout, stderr = await asyncio.wait_for(process.communicate(), 3)
        interrupted = prefix + [json.loads(line) for line in stdout.splitlines()]
        assert process.returncode == 130, stderr.decode()
        assert [event['event'] for event in interrupted].count('run_finished') == 1
        assert interrupted[-1]['report']['execution']['status'] == 'cancelled'
    finally:
        transport.close()


@pytest.mark.parametrize('raw', [{"targets":[{"name":".."}]}, {"targets":[{"name":"example.com.."}]},
                                  {"resolvers":[{"endpoint":"udp://127.0.0.1:0"}]}])
def test_normalization_rejects_empty_labels_and_port_zero(raw):
    with pytest.raises(ValueError):
        module('dnsprobe.config').normalize_request(raw)


@pytest.mark.parametrize('args', [
    ['run', '--format=json', '--nonsense'],
    ['run', '--format=ndjson', '--nonsense'],
])
def test_cli_equals_format_errors(args):
    result = call_cli(*args)
    assert result.returncode == 2
    value = json.loads(result.stdout)
    if 'ndjson' in args[1]:
        assert value['event'] == 'run_finished'
        assert value['report']['run_id'] == value['run_id']
    else:
        assert value['execution']['exit_code'] == 2


@pytest.mark.parametrize('flags', [['--format', 'text'], ['--format=text'], ['--human']])
def test_explicit_text_errors_and_json_control_escaping(flags):
    result = call_cli('run', *flags, '--bogus')
    assert result.returncode == 2
    assert 'unrecognized arguments' in result.stdout
    assert not result.stdout.startswith('{')
    hostile_key = 'bad\x1b\x85\x9b\u2028\u2029\u202e\ud800key'
    for output_flags in ([], ['--pretty']):
        escaped = call_cli('run', *output_flags, '--request-json', json.dumps({hostile_key: True}))
        assert escaped.returncode == 2
        assert not any(char in escaped.stdout for char in '\x1b\x85\x9b\u2028\u2029\u202e\ud800')
        error = json.loads(escaped.stdout)['errors'][0]
        assert error['code'] == 'INPUT_INVALID'
        assert hostile_key in error['message'], 'JSON escaping must preserve the original diagnostic'


@pytest.mark.parametrize('mode', ['native', 'windows', 'config'])
def test_stdin_deadline_with_writer_still_open(mode, tmp_path):
    """Use a real pipe; only the unavailable OS selection is substituted on POSIX."""
    import time
    code = """
import json, os, time, types
from dnsprobe import cli
if WINDOWS_BRANCH:
    cli.os = types.SimpleNamespace(name='nt', read=os.read)
try:
    cli._read_stdin(time.monotonic() + 0.1)
except cli.InputError as exc:
    print(json.dumps({'error': str(exc)}), flush=True)
    raise SystemExit(2)
""".replace('WINDOWS_BRANCH', repr(mode == 'windows'))
    command = [sys.executable, '-c', code]
    if mode == 'config':
        config = tmp_path / 'config.json'
        config.write_text('{"budget_ms":100}')
        command = [sys.executable, '-m', 'dnsprobe', '--config', str(config), '--request-json', '-']
    env = {**os.environ, 'PYTHONPATH': str(Path(__file__).resolve().parents[1] / 'src')}
    started = time.monotonic()
    process = subprocess.Popen(command, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    try:
        process.stdin.write('{')
        process.stdin.flush()  # Keep the writer open: EOF must not be required to observe the deadline.
        process.wait(timeout=2)
        assert process.returncode == 2
        result = json.loads(process.stdout.read())
        assert 'Deadline expired' in (result['errors'][0]['message'] if mode == 'config' else result['error'])
        assert time.monotonic() - started < 2
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()


def test_event_writer_final_identity(capsys):
    EventWriter = module('dnsprobe.cli').EventWriter
    writer = EventWriter()
    writer.write({'event':'run_started', 'run_id':'series-root'})
    report = example_report()
    writer.finish(report, 'full')
    values = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert values[-1]['report']['run_id'] == values[0]['run_id']


def test_json_can_express_bounded_observation_options():
    config = module('dnsprobe.config')
    raw = {'session': {'duration_ms': 500, 'interval_ms': 100, 'max_runs': 3}}
    assert config.normalize_request(raw)['session'] == raw['session']
    with pytest.raises(ValueError):
        config.normalize_request({'session': {'duration_ms': 0}})
    with pytest.raises(ValueError):
        config.normalize_request({'session': {'unbounded': True}})


@pytest.mark.asyncio
@pytest.mark.parametrize('sample_code,expected_status', [(4, 'error'), (130, 'cancelled')])
async def test_series_preserves_fatal_and_interrupted_exit_priority(monkeypatch, sample_code, expected_status):
    from argparse import Namespace
    import time
    from dnsprobe import cli, engine
    async def injected_failure(request, **kwargs):
        return cli.error_report('INJECTED_DEPENDENCY_FAILURE', 'Fixture dependency failure', sample_code)
    monkeypatch.setattr(engine, 'run', injected_failure)
    request = module('dnsprobe.config').normalize_request({'targets':[{'name':'series.test'}], 'resolvers':[{'endpoint':'127.0.0.1'}]})
    args = Namespace(duration=100, interval=10, max_runs=1, command='observe', explicit_rate=False)
    result = await cli.run_series(request, args, time.monotonic())
    assert result['execution']['status'] == expected_status
    assert result['execution']['exit_code'] == sample_code


def test_full_output_limit_never_writes_partial_json(monkeypatch, capsys):
    cli = module('dnsprobe.cli')
    monkeypatch.setattr(cli, 'MAX_OUTPUT_BYTES', 100, raising=False)
    with pytest.raises(module('dnsprobe.report').OutputLimitError):
        cli._print({'message':'x' * 1000})
    assert capsys.readouterr().out == ''


@pytest.mark.parametrize('command', ['explain', 'compare'])
def test_offline_report_schema_errors_are_input_errors(tmp_path, command):
    path = tmp_path / 'bad-report.json'
    path.write_text('{"findings":"not-an-array"}')
    args = ['--report', str(path), '--finding', 'f1'] if command == 'explain' else [str(path), str(path)]
    result = call_cli(command, '--format', 'json', *args)
    assert result.returncode == 2
    assert json.loads(result.stdout)['errors'][0]['code'] == 'INPUT_INVALID'
