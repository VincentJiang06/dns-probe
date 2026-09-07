"""Independent integration regressions; transport is an offline recording fake."""
from copy import deepcopy
import asyncio
import time
from argparse import Namespace

import pytest

from dnsprobe import discovery, engine, transport
from dnsprobe.report import compare_reports


@pytest.fixture
def recorded_transport(monkeypatch):
    calls = []

    async def discover():
        return {'system_resolvers': [], 'private_domains': ['corp']}

    async def exchange(self, endpoint, name, qtype, timeout_ms, options=None):
        calls.append((endpoint['id'], name, qtype, options or {}))
        return {'outcome': 'response', 'rcode': 'NOERROR', 'flags': ['QR'],
                'answers': [{'name': name, 'type': qtype, 'ttl': 60,
                             'values': ['198.18.0.1' if endpoint['id'] == 'synthetic' else '192.0.2.1']}],
                'timing': {'total_ms': 1 if endpoint['id'] == 'synthetic' else 10}}

    monkeypatch.setattr(discovery, 'discover', discover)
    monkeypatch.setattr(transport.Transport, 'exchange', exchange)
    return calls


def request(**updates):
    return {'profile': 'quick', 'budget_ms': 1000,
            'targets': [{'name': 'a.example', 'types': ['A']}],
            'resolvers': [{'id': 'local', 'endpoint': 'udp://127.0.0.1:5300'}],
            'tests': ['DNS.BASIC'], 'network_scope': 'system',
            'limits': {'rate': 1000, 'endpoint_rate': 1000}, **updates}


@pytest.mark.parametrize('test_id', ['PERF.SAMPLE', 'DNS.EDNS'])
async def test_successful_explicit_diagnostic_is_required(recorded_transport, test_id):
    report = await engine.run(request(tests=[test_id]))
    assert report['execution']['exit_code'] == 0, report['coverage']
    assert any(c['required'] and c['test_id'] == test_id for c in report['checks'])


async def test_all_observation_check_references_resolve(recorded_transport):
    report = await engine.run(request(tests=['DNS.BASIC', 'PERF.SAMPLE', 'DNS.EDNS']))
    check_ids = {c['id'] for c in report['checks']}
    assert all(o['check_id'] in check_ids for o in report['observations']), report['observations']


async def test_private_fixture_not_sent_to_automatic_public_resolvers(recorded_transport):
    fixture = {'id': 'secret', 'name': 'signed.secret.corp', 'kind': 'signed',
               'type': 'A', 'rcode': 'NOERROR', 'expires_at': '2099-01-01T00:00:00Z'}
    await engine.run(request(resolvers=[], network_scope='public', public_comparison=True,
                             tests=['DNS.DNSSEC_BEHAVIOR'], fixtures=[fixture]))
    leaked = [c for c in recorded_transport if c[0].startswith('public-') and c[1].endswith('.corp')]
    assert not leaked, leaked


async def test_synthetic_identity_unverified_path_never_recommended(recorded_transport):
    report = await engine.run(request(profile='deep', tests=['DNS.BASIC', 'PERF.SAMPLE'],
        targets=[{'name': n, 'types': ['A']} for n in ('a.example', 'b.example')],
        resolvers=[{'id': p, 'endpoint': f'udp://127.0.0.1:{5300+i}'} for i, p in enumerate(('synthetic', 'normal'))]))
    assert report['execution']['exit_code'] == 0
    assert any(f['code'] == 'SYNTHETIC_ANSWER_OBSERVED' for f in report['findings'])
    assert report['summary']['recommended_resolver_id'] is None, report['summary']


@pytest.mark.parametrize('changed', ['implementation_fingerprint', 'ecs', 'trust_anchors', 'delegation_roots', 'cname_max_depth', 'connect'])
async def test_compare_rejects_changed_implementation_or_diagnostic_policy(recorded_transport, changed):
    before = await engine.run(request())
    before['implementation_fingerprint'] = 'a' * 64
    after = deepcopy(before)
    if changed == 'implementation_fingerprint':
        after[changed] = 'b' * 64
    else:
        after['effective_config'][changed] = 'changed-condition'
    assert not compare_reports(before, after)['comparable'], changed


async def test_compare_requires_implementation_fingerprint(recorded_transport):
    before = await engine.run(request())
    before.pop('implementation_fingerprint', None)
    assert not compare_reports(before, deepcopy(before))['comparable']


@pytest.mark.parametrize('rcode,kind', [('NXDOMAIN', 'nxdomain'), ('NOERROR', 'nodata')])
async def test_explicit_controlled_negative_fixture_is_actually_tested(recorded_transport, monkeypatch, rcode, kind):
    async def negative(self, endpoint, name, qtype, timeout_ms, options=None):
        recorded_transport.append((endpoint['id'], name, qtype, options or {}))
        return {'outcome': 'response', 'rcode': rcode, 'answers': [], 'flags': ['QR'],
                'timing': {'total_ms': 1}}
    monkeypatch.setattr(transport.Transport, 'exchange', negative)
    fixture = {'id': 'negative', 'name': 'controlled.corp', 'kind': kind,
               'type': 'A', 'rcode': rcode, 'expires_at': '2099-01-01T00:00:00Z'}
    report = await engine.run(request(tests=['DNS.NEGATIVE'], fixtures=[fixture]))
    assert any(c[1] == fixture['name'] for c in recorded_transport), report['checks']
    assert report['execution']['exit_code'] == 0, report['coverage']


@pytest.mark.parametrize('owner,expected_status', [('a.example', 'pass'), ('unrelated.example', 'fail')])
def test_answer_expectation_uses_reachable_owner(owner, expected_status):
    observation = {'outcome': 'response', 'rcode': 'NOERROR', 'path_id': 'local',
                   'answers': [{'name': owner, 'type': 'A', 'values': ['192.0.2.1']}]}
    req = {'expectations': [{'target': 'a.example', 'type': 'A', 'min_answers': 1,
                             'answers': ['192.0.2.1']}]}
    status, _ = engine._semantic(observation, 'A', 'a.example', req)
    assert status == expected_status


async def test_tests_all_does_not_hide_observed_cname_failure(recorded_transport, monkeypatch):
    async def loop(self, endpoint, name, qtype, timeout_ms, options=None):
        return {'outcome': 'response', 'rcode': 'NOERROR', 'flags': ['QR'],
                'answers': [{'name': name, 'type': 'CNAME', 'ttl': 60, 'values': [name]}],
                'timing': {'total_ms': 1}}
    monkeypatch.setattr(transport.Transport, 'exchange', loop)
    report = await engine.run(request(tests='all'))
    assert any(c['test_id'] == 'DNS.CNAME' and c['status'] == 'fail' for c in report['checks'])
    assert report['assessment']['status'] != 'pass', report['assessment']
    assert report['execution']['exit_code'] != 0


async def test_deep_auto_never_runs_tests_it_reports_as_not_selected(recorded_transport):
    report = await engine.run(request(profile='deep', tests='auto'))
    selected_checks = {c['test_id'] for c in report['checks']}
    assert not selected_checks.intersection(report['coverage']['not_selected'])


async def test_internal_transport_exception_is_tool_error(recorded_transport, monkeypatch):
    async def broken(self, *args, **kwargs):
        raise RuntimeError('injected implementation bug')
    monkeypatch.setattr(transport.Transport, 'exchange', broken)
    report = await engine.run(request())
    assert report['execution']['exit_code'] == 4, report['execution']
    assert report['errors'], 'Internal errors must not masquerade as DNS path findings'


async def test_cancelled_cname_auxiliary_observation_references_coverage(recorded_transport, monkeypatch):
    async def alias_then_block(self, endpoint, name, qtype, timeout_ms, options=None):
        if name.rstrip('.') == 'a.example':
            return {'outcome': 'response', 'rcode': 'NOERROR', 'flags': ['QR'],
                    'answers': [{'name': name, 'type': 'CNAME', 'values': ['b.example.']}],
                    'timing': {'total_ms': 1}}
        await asyncio.sleep(10)
    monkeypatch.setattr(transport.Transport, 'exchange', alias_then_block)
    report = await engine.run(request(tests=['DNS.CNAME'], budget_ms=40))
    assert report['execution']['exit_code'] == 3
    assert any(o['qname'].rstrip('.') == 'b.example' for o in report['observations'])
    checks = {c['id']: c for c in report['checks']}
    for observation in report['observations']:
        assert observation['check_id'] in checks, observation
        assert observation['id'] in checks[observation['check_id']]['evidence_ids']


async def test_system_scope_auto_does_not_generate_public_dns64_control(recorded_transport):
    await engine.run(request(profile='deep', tests='auto', network_scope='system'))
    assert not any(c[1] == 'ipv4only.arpa' for c in recorded_transport), recorded_transport


@pytest.mark.parametrize('test_id', ['PERF.SAMPLE', 'DNS.CACHE'])
async def test_all_servfail_samples_cannot_produce_healthy_assessment(recorded_transport, monkeypatch, test_id):
    async def refused(self, *args, **kwargs):
        return {'outcome': 'response', 'rcode': 'SERVFAIL', 'flags': ['QR'],
                'answers': [], 'timing': {'total_ms': 1}}
    monkeypatch.setattr(transport.Transport, 'exchange', refused)
    report = await engine.run(request(tests=[test_id]))
    assert report['assessment']['status'] != 'pass', report['checks']
    assert report['execution']['exit_code'] != 0


async def test_recommendation_requires_reliable_samples_for_each_target(recorded_transport, monkeypatch):
    seen = {}
    async def asymmetric(self, endpoint, name, qtype, timeout_ms, options=None):
        key = (endpoint['id'], name)
        seen[key] = seen.get(key, 0) + 1
        if endpoint['id'] == 'fast' and name == 'c.example' and seen[key] > 1:
            return {'outcome': 'timeout', 'rcode': None, 'answers': [], 'timing': {'total_ms': 800}}
        return {'outcome': 'response', 'rcode': 'NOERROR', 'flags': ['QR'],
                'answers': [{'name': name, 'type': qtype, 'values': ['192.0.2.1']}],
                'timing': {'total_ms': 1 if endpoint['id'] == 'fast' else 10}}
    monkeypatch.setattr(transport.Transport, 'exchange', asymmetric)
    report = await engine.run(request(profile='deep', tests=['DNS.BASIC', 'PERF.SAMPLE'],
        targets=[{'name': n, 'types': ['A']} for n in ('a.example', 'b.example', 'c.example')],
        resolvers=[{'id': p, 'endpoint': f'udp://127.0.0.1:{5300+i}'} for i, p in enumerate(('fast', 'reliable'))]))
    assert report['statistics']['fast']['response_rate'] >= .95
    assert report['summary']['recommended_resolver_id'] != 'fast', report['summary']


async def test_compare_series_rejects_changed_observation_schedule(recorded_transport):
    from dnsprobe.cli import run_series
    from dnsprobe.config import normalize_request
    req = normalize_request(request())
    first = await run_series(req, Namespace(command='observe', duration=100, interval=10,
                             max_runs=1, explicit_rate=False), time.monotonic())
    second = await run_series(req, Namespace(command='observe', duration=1000, interval=50,
                              max_runs=1, explicit_rate=False), time.monotonic())
    assert first['series']['interval_ms'] != second['series']['interval_ms']
    assert not compare_reports(first, second)['comparable']


async def test_series_preserves_shared_attempt_stop_reason(recorded_transport):
    from dnsprobe.cli import run_series
    from dnsprobe.config import normalize_request
    req = normalize_request(request(limits={'max_attempts': 1}))
    report = await run_series(req, Namespace(command='observe', duration=200, interval=10,
                              max_runs=3, explicit_rate=False), time.monotonic())
    assert report['execution']['exit_code'] == 3
    assert report['cost']['dns_attempts'] == 1
    assert report['execution']['stop_reason'] == 'max_attempts', report['execution']


@pytest.mark.parametrize('qtype,with_wire', [
    ('A', False), ('AAAA', False), ('MX', False), ('TXT', False),
    ('A', True), ('AAAA', True), ('MX', True), ('TXT', True),
    ('MX', 'discovered'), ('TXT', 'discovered'),
])
async def test_native_record_type_applicability_preserves_wire_queries(recorded_transport, monkeypatch, qtype, with_wire):
    resolvers = [{'id': 'native', 'endpoint': 'system'}]
    if with_wire:
        resolvers.append({'id': 'wire', 'endpoint': 'udp://127.0.0.1:5300'})
    req = request(targets=[{'name': 'a.example', 'types': [qtype]}], resolvers=resolvers,
                  tests=['DNS.BASIC', 'PERF.SAMPLE', 'DNS.CACHE'])
    environment = {'system_resolvers': [], 'private_domains': []}
    if with_wire == 'discovered':
        environment['system_resolvers'] = [{'id': 'wire', 'endpoint': 'udp://127.0.0.1:5300'}]
        async def discovered():
            return environment
        monkeypatch.setattr(discovery, 'discover', discovered)
        req.update(resolvers=[], tests='auto')
    native_id = 'system' if with_wire == 'discovered' else 'native'
    supported = qtype in ('A', 'AAAA')
    plan = engine.plan(req, environment)
    native_plan = [c for c in plan['checks'] if c['path_id'] == native_id and c.get('qtype') == qtype]
    assert len(native_plan) == 1
    if not supported:
        assert native_plan[0]['status'] == 'skipped'
        assert native_plan[0]['reason_code'] == 'SYSTEM_RRTYPE_UNSUPPORTED'
    report = await engine.run(req)
    native_observations = [o for o in report['observations'] if o['path_id'] == native_id]
    assert not any(f['code'] == 'DNS_PATH_FAILURE' for f in report['findings'])
    assert not report['errors']
    if supported:
        assert native_observations and all(o['qtype'] == qtype for o in native_observations)
        assert report['assessment']['status'] == 'pass'
        assert report['execution']['exit_code'] == 0, report['coverage']
    else:
        assert native_observations == [], 'Unsupported types must not start native attempts or repeats'
        assert report['cost']['auxiliary_calls'] == 0
        native_checks = [c for c in report['checks'] if c['path_id'] == native_id and c['target_id'] == 'a.example']
        assert all(c['status'] in ('skipped', 'inconclusive') and
                   c['reason_code'] == 'SYSTEM_RRTYPE_UNSUPPORTED' for c in native_checks)
        assert report['assessment']['status'] == ('pass' if with_wire == 'discovered' else 'unknown')
        assert report['execution']['exit_code'] == (0 if with_wire == 'discovered' else 3)
        if with_wire == 'discovered':
            assert not any(c['required'] for c in native_checks)
        direct = await discovery.system_lookup('localhost', qtype, 100)
        assert direct['error']['code'] == 'SYSTEM_RRTYPE_UNSUPPORTED'
    if with_wire:
        wire_observations = [o for o in report['observations'] if o['path_id'] == 'wire']
        assert wire_observations and all(o['qtype'] == qtype for o in wire_observations)
        assert all(c['status'] == 'pass' for c in report['checks'] if c['path_id'] == 'wire')


@pytest.mark.parametrize('scope', ['private','public'])
async def test_private_target_never_sent_to_default_authority_root(recorded_transport, scope):
    await engine.run(request(network_scope=scope, public_comparison=True, tests=['DNS.DELEGATION'],
                             targets=[{'name':'secret.corp','types':['A']}]))
    assert not any(c[0].startswith('authority-') for c in recorded_transport)


async def test_shared_evidence_limit_prevents_new_network_attempt(recorded_transport):
    import time
    req=engine._normal(request())
    scheduler=engine.Scheduler(time.monotonic()+1,req['limits'])
    scheduler.evidence_bytes=16*1024*1024
    report=await engine.run(req,scheduler=scheduler)
    assert not recorded_transport
    assert report['execution']['exit_code']==3
    assert report['execution']['stop_reason']=='max_evidence_bytes'


async def test_connect_flag_actually_attempts_default_tls_endpoint(recorded_transport, monkeypatch):
    calls=[]
    async def unavailable(address,port,**kwargs):
        calls.append((address,port,kwargs))
        raise ConnectionRefusedError('local fake: no network call')
    monkeypatch.setattr(asyncio,'open_connection',unavailable)
    report=await engine.run(request(connect=True,tests='auto'))
    assert calls, report['checks']
    assert calls[0][1]==443 and calls[0][2]['server_hostname']=='a.example'


async def test_explicit_connect_warning_is_in_requested_assessment(recorded_transport,monkeypatch):
    async def unavailable(*args,**kwargs): raise ConnectionRefusedError('offline fixture')
    monkeypatch.setattr(asyncio,'open_connection',unavailable)
    report=await engine.run(request(connect=True,tests='auto',fail_on='warning'))
    assert report['assessment']['status']=='warn'
    assert report['execution']['exit_code']==1


@pytest.mark.parametrize('expectation', [
    {'target':'typo.example','type':'A'},
    {'target':'a.example','type':'AAAA'},
    {'target':'a.example','type':'A','resolver_id':'typo'},
])
def test_unmatched_expectation_never_silently_discarded(expectation):
    with pytest.raises(ValueError):
        engine._normal(request(expectations=[expectation]))
