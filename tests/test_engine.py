import asyncio
import time

import dns.message
import dns.rcode
import dns.rrset
import pytest

from dnsprobe import engine


class Resolver(asyncio.DatagramProtocol):
    def __init__(self, mode):
        self.mode = mode
        self.requests = []

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        q = dns.message.from_wire(data)
        self.requests.append(q)
        if self.mode == "blackhole":
            return
        r = dns.message.make_response(q)
        if self.mode == "nxdomain":
            r.set_rcode(dns.rcode.NXDOMAIN)
        else:
            r.answer.append(dns.rrset.from_text(q.question[0].name, 60, "IN", "A", "192.0.2.10"))
        self.transport.sendto(r.to_wire(), addr)


@pytest.fixture
async def resolver_factory():
    transports = []

    async def make(mode="ok"):
        t, p = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: Resolver(mode), local_addr=("127.0.0.1", 0)
        )
        transports.append(t)
        return {"id": "local", "endpoint": f"udp://127.0.0.1:{t.get_extra_info('sockname')[1]}"}, p

    yield make
    for t in transports:
        t.close()


def request(endpoint, **changes):
    base = {"schema_version": "1.0", "profile": "quick", "budget_ms": 1000,
            "targets": [{"name": "example.com", "types": ["A"]}],
            "resolvers": [endpoint], "tests": ["DNS.BASIC"],
            "network_scope": "system", "public_comparison": False,
            "expectations": [], "limits": {"max_attempts": 20}}
    return base | changes


@pytest.mark.parametrize("mode,expectations,status,code", [
    ("ok", [], "pass", 0),
    ("nxdomain", [], "fail", 1),
    ("nxdomain", [{"target": "example.com", "type": "A", "rcode": "NXDOMAIN"}], "pass", 0),
    ("ok", [{"target": "example.com", "type": "A", "max_answers": 0}], "fail", 1),
    ("ok", [{"target": "example.com", "type": "A", "ad": True}], "fail", 1),
])
async def test_run_semantic_contract(resolver_factory, mode, expectations, status, code):
    endpoint, _ = await resolver_factory(mode)
    report = await engine.run(request(endpoint, expectations=expectations))
    assert report["assessment"]["status"] == status
    assert report["execution"]["exit_code"] == code
    assert report["coverage"]["required_unresolved"] == []
    assert report["observations"]
    assert report["execution"]["status"] == "completed"


async def test_deadline_returns_partial_without_pending_tasks(resolver_factory):
    endpoint, _ = await resolver_factory("blackhole")
    started = time.monotonic()
    report = await engine.run(request(endpoint, budget_ms=120))
    assert time.monotonic() - started < 0.5
    assert report["execution"]["status"] == "partial"
    assert report["execution"]["exit_code"] == 3
    assert report["assessment"]["status"] == "unknown"
    c = report["coverage"]
    assert c["planned"] == c["completed"] + c["inconclusive"] + c["skipped"] + c["error"]


async def test_attempt_budget_counts_all_queries(resolver_factory):
    endpoint, protocol = await resolver_factory()
    targets = [{"name": f"n{i}.example.com", "types": ["A"]} for i in range(10)]
    report = await engine.run(request(endpoint, targets=targets, limits={"max_attempts": 3}))
    assert len(protocol.requests) <= 3
    assert report["execution"]["exit_code"] == 3
    assert report["coverage"]["skipped"] > 0


def test_planner_never_leaks_private_targets_to_automatic_public_paths():
    req = request({"id": "system", "endpoint": "system"}, targets=[{"name": "secret.corp", "types": ["A"]}],
                  resolvers=[], network_scope="public", public_comparison=True)
    p = engine.plan(req, {"system_resolvers": [], "private_domains": ["corp"]})
    for check in p["checks"]:
        if check["target_id"] == "secret.corp" and check["path_id"].startswith("public-"):
            assert check["status"] == "skipped" and check["reason_code"] == "POLICY_EXCLUDED"


@pytest.mark.parametrize("n,p95,p99", [(3, False, False), (20, True, False), (100, True, True)])
def test_statistics_preserve_failure_and_quantile_limits(n,p95,p99):
    obs = [{"outcome": "response", "timing": {"total_ms": float(i+1)}} for i in range(n)]
    obs += [{"outcome": "timeout", "timing": {"total_ms": 800}}, {"outcome": "cancelled"}]
    s = engine.sample_statistics(obs)
    assert s["success_count"] == n
    assert s["failure_count"] == 1
    assert s["cancelled_count"] == 1
    assert (s["p95_ms"] is not None) == p95
    assert (s["p99_ms"] is not None) == p99
    assert s["response_rate"] == pytest.approx(n/(n+1))


async def test_cancelled_advanced_checks_retain_target_coverage(resolver_factory):
    endpoint, _ = await resolver_factory("blackhole")
    report = await engine.run(request(endpoint, tests=["DNS.CNAME"], budget_ms=100))
    checks = [c for c in report['checks'] if c['test_id']=='DNS.CNAME']
    assert checks and checks[0]['target_id']=='example.com'
    assert checks[0]['required']
    # A rounded transport timeout can finish just before global cancellation.
    assert checks[0]['status'] in ('skipped','inconclusive')
    assert report['execution']['exit_code']==3


@pytest.mark.parametrize('scheme,test_id', [('tls','TRANSPORT.DOT'),('https','TRANSPORT.DOH'),('quic','TRANSPORT.DOQ')])
async def test_explicit_transport_test_actually_queries(monkeypatch,scheme,test_id):
    from dnsprobe import transport,discovery
    async def discover(): return {'system_resolvers':[],'private_domains':[]}
    async def exchange(self,endpoint,name,qtype,timeout_ms,options=None):
        return {'outcome':'response','rcode':'NOERROR','flags':['QR'],
                'answers':[{'name':name,'type':'A','ttl':60,'values':['192.0.2.1']}],
                'timing':{'total_ms':1}}
    monkeypatch.setattr(discovery,'discover',discover)
    monkeypatch.setattr(transport.Transport,'exchange',exchange)
    ep={'id':'encrypted','endpoint':f'{scheme}://resolver.example'+('/dns-query' if scheme=='https' else ':853'),
        'bootstrap_ips':['192.0.2.53']}
    report=await engine.run(request(ep,tests=[test_id]))
    assert report['observations'], 'an explicit protocol test must execute the protocol'
    assert report['execution']['exit_code']==0


async def test_full_report_events_and_no_unresolved_evidence(resolver_factory):
    endpoint,_=await resolver_factory()
    events=[]
    r=await engine.run(request(endpoint),events.append)
    assert [e['event'] for e in events].count('run_finished')==1
    assert events[0]['event']=='run_started' and events[-1]['event']=='run_finished'
    assert [e['seq'] for e in events]==list(range(1,len(events)+1))
    assert all(o['check_id'] for o in r['observations'])
