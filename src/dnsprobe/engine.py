"""Bounded scheduling, evidence-based assessment and deterministic planning.

Only the scheduler may start network work. Diagnosis consumes observations and
never resolves names itself. A timeout is a measurement; cancellation is not.
"""
from __future__ import annotations

import asyncio
from collections import Counter, defaultdict
from contextlib import asynccontextmanager
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
import statistics
import time
from pathlib import Path
from urllib.parse import urlsplit
import uuid

from . import __version__

_DESCRIPTIONS = {
    'ENV.SYSTEM': 'System DNS configuration and interface scope',
    'ENV.PROXY_PATH': 'Synthetic address and proxy path observations',
    'RESOLVE.SYSTEM': 'Native operating-system address lookup',
    'DNS.BASIC': 'DNS response semantics for requested record types',
    'DNS.NEGATIVE': 'Known negative responses and configured fixtures',
    'DNS.TCP': 'TCP DNS path', 'DNS.TRUNCATION': 'Observed UDP truncation recovery',
    'DNS.EDNS': 'EDNS response and extended errors',
    'DNS.DNSSEC_BEHAVIOR': 'Resolver DNSSEC behavior using configured fixtures',
    'DNS.DNSSEC_VALIDATE': 'Local DNSSEC validation against configured trust anchors',
    'DNS.CACHE': 'First and repeated query observations, cache state unknown',
    'DNS.CONSISTENCY': 'Normalized answer-set differences, without truth by majority',
    'DNS.IDENTITY': 'NSID and id.server self-reported identity',
    'DNS.ECS': 'Explicit ECS observations', 'DNS.RECORDS': 'Use-case record inventory',
    'DNS.CNAME': 'CNAME chain and loop checks', 'DNS.DELEGATION': 'Iterative delegation trace',
    'DNS.DNS64': 'DNS64 synthesis observations',
    'TRANSPORT.DOT': 'Authenticated DNS over TLS',
    'TRANSPORT.DOH': 'Authenticated DNS over HTTPS',
    'TRANSPORT.DOQ': 'Authenticated DNS over QUIC',
    'PERF.SAMPLE': 'Bounded latency samples with visible failures',
    'APP.CONNECT': 'Explicit TCP/TLS connection to resolved addresses',
    'IDENTITY.OBSERVE': 'Authority-side observations require an external observer',
}
TESTS = {k: {'id': k, 'description': v, 'version': '1',
             'available': k != 'IDENTITY.OBSERVE'} for k, v in _DESCRIPTIONS.items()}
QUICK = {'ENV.SYSTEM', 'ENV.PROXY_PATH', 'RESOLVE.SYSTEM', 'DNS.BASIC', 'PERF.SAMPLE'}
STANDARD = QUICK | {'DNS.NEGATIVE', 'DNS.TCP', 'DNS.TRUNCATION', 'DNS.EDNS',
                    'DNS.DNSSEC_BEHAVIOR', 'DNS.CACHE', 'DNS.CONSISTENCY',
                    'TRANSPORT.DOT', 'TRANSPORT.DOH'}
ADVANCED = {'DNS.IDENTITY','DNS.ECS','DNS.RECORDS','DNS.CNAME','DNS.DELEGATION',
            'DNS.DNS64','DNS.DNSSEC_BEHAVIOR','DNS.DNSSEC_VALIDATE','APP.CONNECT'}
PUBLIC = [
    {'id':'public-cloudflare', 'endpoint':'udp://1.1.1.1:53', 'operator_id':'cloudflare', 'source':'catalog'},
    {'id':'public-google', 'endpoint':'https://dns.google/dns-query', 'bootstrap_ips':['8.8.8.8'],
     'operator_id':'google', 'source':'catalog'},
]
WORKLOADS = {
    'general': ['example.com'],
    'hong-kong': ['www.hk01.com','www.mtr.com.hk','www.cloudflare.com','www.wikipedia.org','www.qq.com','www.taobao.com'],
    'mainland': ['www.qq.com','www.baidu.com','www.taobao.com','www.apple.com'],
}


def _normal(request):
    from .config import normalize_request
    return normalize_request(request)


def selected_tests(request):
    tests = request.get('tests', 'auto')
    if isinstance(tests, list):
        return set(tests)
    if tests == 'all':
        return set(TESTS) - (set() if request.get('connect') else {'APP.CONNECT'})
    if request.get('profile') == 'deep':
        return set(TESTS) - {'APP.CONNECT','IDENTITY.OBSERVE','DNS.ECS','DNS.DNSSEC_VALIDATE'} | (
            {'DNS.ECS'} if request.get('ecs') else set()) | ({'DNS.DNSSEC_VALIDATE'} if request.get('trust_anchors') else set()) | (
            {'APP.CONNECT'} if request.get('connect') else set())
    return (QUICK if request.get('profile') == 'quick' else STANDARD) | ({'APP.CONNECT'} if request.get('connect') else set())


def _key_name(name):
    return name.rstrip('.').lower()


def _native_type_supported(path, qtype):
    return path['endpoint'] != 'system' or qtype in ('A', 'AAAA')


def _private(name, environment):
    name = _key_name(name)
    return '.' not in name or name.endswith('.local') or any(
        name == _key_name(d).lstrip('~') or name.endswith('.' + _key_name(d).lstrip('~'))
        for d in environment.get('private_domains', []) if d and d not in ('.','~.')
    )


def _allowed(target, path, request, environment):
    if path.get('source') == 'catalog':
        if request['network_scope'] in ('system','private'):
            return False
        if target.get('_control'):
            return True
        if _private(target['name'], environment):
            return bool(target.get('allow_public'))
        return bool(request.get('public_comparison') or target.get('allow_public'))
    # Scoped system resolvers are queried only for matching suffixes.
    domains = path.get('domains', path.get('routing_domains', []))
    if domains and '.' not in domains and '~.' not in domains:
        return any(_key_name(target['name']) == _key_name(d).lstrip('~') or
                   _key_name(target['name']).endswith('.'+_key_name(d).lstrip('~')) for d in domains)
    return True


def plan(request, environment=None):
    request = _normal(request)
    environment = environment or {'system_resolvers': [], 'private_domains': []}
    selected = selected_tests(request)
    explicit = bool(request['resolvers'])
    paths = deepcopy(request['resolvers']) if explicit else [{'id':'system','endpoint':'system','source':'system'}]
    if not explicit:
        for i, p in enumerate(environment.get('system_resolvers', [])):
            p = {'endpoint':f'udp://{p}:53'} if isinstance(p, str) else deepcopy(p)
            p.setdefault('id', f'system-dns-{i+1}')
            p.setdefault('source','system_config')
            paths.append(p)
        if request['network_scope'] not in ('system','private'):
            paths.extend(deepcopy(PUBLIC))
    unique, seen = [], set()
    for p in paths:
        k = (p['endpoint'],p.get('interface_scope'),tuple(p.get('routing_domains',p.get('domains',[]))))
        if k not in seen:
            seen.add(k); unique.append(p)
    paths = unique[:8]
    for p in paths:
        p.setdefault('source','explicit' if explicit else 'system_config')
        p.setdefault('bootstrap_ips',[])
    targets = deepcopy(request['targets'])
    if not targets and request['network_scope'] not in ('system','private'):
        targets = [{'name':n,'types':['A','AAAA'],'_control':True} for n in WORKLOADS.get(request.get('workload','general'),['example.com'])]
    if 'APP.CONNECT' in selected:
        for target in targets: target.setdefault('app',{'port':443,'tls':True})
    # System-only is deliberately non-exfiltrating: no public control names.
    checks = []
    for target in targets:
        configured_wire_ids={p['id'] for p in paths if p['endpoint']!='system'
                             and p.get('source')!='catalog' and _allowed(target,p,request,environment)}
        for path in paths:
            kind = 'RESOLVE.SYSTEM' if path['endpoint']=='system' else 'DNS.BASIC'
            proto_test={'tls':'TRANSPORT.DOT','https':'TRANSPORT.DOH','quic':'TRANSPORT.DOQ'}.get(urlsplit(path['endpoint']).scheme)
            if kind not in selected and 'DNS.BASIC' not in selected and proto_test not in selected:
                continue
            for qt in target.get('types',['A','AAAA']):
                allowed = _allowed(target,path,request,environment)
                supported = _native_type_supported(path,qt)
                required = explicit or path['endpoint']=='system'
                if not explicit and request['tests']=='auto' and qt not in ('A','AAAA') and configured_wire_ids:
                    required = path['id'] in configured_wire_ids
                check_kind=kind if kind in selected else 'DNS.BASIC' if 'DNS.BASIC' in selected else proto_test
                cid = f'{check_kind}:{path["id"]}:{target["name"]}:{qt}'
                checks.append({'id':cid,'test_id':check_kind,'target_id':target['name'], 'path_id':path['id'],
                    'qtype':qt,'status':'pending' if allowed and supported else 'skipped','required':required and allowed,
                    'evidence_ids':[], 'reason_code':'POLICY_EXCLUDED' if not allowed else
                    'SYSTEM_RRTYPE_UNSUPPORTED' if not supported else None})
    for target in targets:
        for path in paths:
            allowed=_allowed(target,path,request,environment)
            for tid in sorted(selected & ADVANCED):
                checks.append({'id':f'{tid}:{path["id"]}:{target["name"]}:','test_id':tid,
                    'target_id':target['name'],'path_id':path['id'],'status':'pending' if allowed else 'skipped',
                    'required':allowed and (request['tests']!='auto' or tid=='APP.CONNECT' and request.get('connect',False)),'evidence_ids':[],
                    'reason_code':None if allowed else 'POLICY_EXCLUDED'})
    return {'profile':request['profile'],'workload':request.get('workload','general'),
            'tests':sorted(selected),'paths':paths,'targets':targets,'checks':checks,
            'limits':request['limits'],'budget_ms':request['budget_ms'],
            'estimated_attempts_upper_bound':min(request['limits']['max_attempts'],len(checks)*6+len(paths)*10),
            'omitted_paths':unique[8:],'network_access':False,
            'warnings':['Control queries disabled: supply targets for system-only diagnostics'] if not targets else []}


def sample_statistics(observations):
    success = [o for o in observations if o.get('outcome')=='response']
    failed = [o for o in observations if o.get('outcome') in ('timeout','error')]
    cancelled = len(observations)-len(success)-len(failed)
    vals = sorted(float(o.get('timing',{}).get('total_ms',0)) for o in success)
    def quantile(q):
        if not vals: return None
        k = (len(vals)-1)*q; lo = math.floor(k); hi = math.ceil(k)
        return round(vals[lo]+(vals[hi]-vals[lo])*(k-lo),3)
    return {'success_count':len(success),'failure_count':len(failed),'cancelled_count':cancelled,
        'sample_count':len(success)+len(failed),
        'response_rate':len(success)/(len(success)+len(failed)) if success or failed else None,
        'p50_ms':quantile(.5),'p95_ms':quantile(.95) if len(vals)>=20 else None,
        'p99_ms':quantile(.99) if len(vals)>=100 else None,
        'max_ms':max(vals) if vals else None,
        'cache_state':'unknown', 'metric':'attempt_total',
        'rcodes':dict(Counter(o.get('rcode') or 'unobserved' for o in success))}


class BudgetExhausted(Exception):
    pass


class Scheduler:
    def __init__(self, deadline, limits):
        self.deadline = deadline
        self.limits = limits
        self.global_sem = asyncio.Semaphore(limits['concurrency'])
        self.endpoint_sem = defaultdict(lambda:asyncio.Semaphore(limits['per_endpoint']))
        self.tokens = {}
        self.attempts = 0
        self.auxiliary = 0
        self.evidence_bytes = 0
        self.stop_reason = None

    async def _rate(self, key, rate, capacity):
        while True:
            now = time.monotonic()
            last, count = self.tokens.get(key,(now,float(capacity)))
            count = min(float(capacity), count+(now-last)*rate)
            if count >= 1:
                self.tokens[key]=(now,count-1)
                return
            self.tokens[key]=(now,count)
            await asyncio.sleep(min((1-count)/rate,max(.001,self.deadline-now)))

    @asynccontextmanager
    async def slot(self, endpoint, kind='dns'):
        key = endpoint['id'] if isinstance(endpoint,dict) else str(endpoint)
        async with self.global_sem, self.endpoint_sem[key]:
            if self.evidence_bytes>=16*1024*1024:
                self.stop_reason='max_evidence_bytes'; raise BudgetExhausted(self.stop_reason)
            if time.monotonic() >= self.deadline:
                self.stop_reason='deadline'; raise BudgetExhausted('deadline')
            if kind=='dns' and self.attempts>=self.limits['max_attempts']:
                self.stop_reason='max_attempts'; raise BudgetExhausted('max_attempts')
            await self._rate('global', self.limits['rate'], self.limits['concurrency'])
            await self._rate(key,self.limits['endpoint_rate'],self.limits['per_endpoint'])
            if time.monotonic()>=self.deadline:
                self.stop_reason='deadline'; raise BudgetExhausted('deadline')
            # Recheck after rate waits: many waiting tasks share the last token.
            if kind=='dns':
                if self.attempts>=self.limits['max_attempts']:
                    self.stop_reason='max_attempts'; raise BudgetExhausted('max_attempts')
                self.attempts+=1
            else:
                self.auxiliary+=1
            yield


def reachable_values(obs, qt, target):
    reachable={_key_name(target)}
    for _ in range(64):
        following={_key_name(v) for rr in obs.get('answers',[]) if rr.get('type')=='CNAME'
                   and _key_name(rr.get('name',target)) in reachable for v in rr.get('values',[])}
        if following.issubset(reachable): break
        reachable.update(following)
    return [v for rr in obs.get('answers',[]) if rr.get('type')==qt
            and _key_name(rr.get('name',target)) in reachable for v in rr.get('values',[])]


def _semantic(obs, qt, target, request):
    if (obs.get('error') or {}).get('code')=='SYSTEM_RRTYPE_UNSUPPORTED':
        return 'skipped','SYSTEM_RRTYPE_UNSUPPORTED'
    if obs.get('outcome')=='cancelled': return 'skipped','BUDGET_EXHAUSTED'
    if obs.get('outcome')!='response': return 'fail',(obs.get('error') or {}).get('code','NO_RESPONSE')
    expected = next((e for e in request.get('expectations',[]) if _key_name(e['target'])==_key_name(target)
                     and e.get('type',qt)==qt and e.get('resolver_id',obs.get('path_id'))==obs.get('path_id')),None)
    desired = expected.get('rcode','NOERROR') if expected else 'NOERROR'
    actual = obs.get('rcode')
    if actual is not None and actual!=desired: return 'fail','RCODE_MISMATCH'
    if actual is None and desired!='NOERROR': return 'inconclusive','RCODE_UNOBSERVABLE'
    vals = reachable_values(obs,qt,target)
    if expected:
        if len(vals)<expected.get('min_answers',0): return 'fail','ANSWER_COUNT_MISMATCH'
        if len(vals)>expected.get('max_answers',10000): return 'fail','ANSWER_COUNT_MISMATCH'
        if expected.get('answers') and not set(expected['answers']).issubset(vals): return 'fail','ANSWER_MISMATCH'
        if 'ad' in expected:
            if obs.get('transport')=='system': return 'inconclusive','AD_UNOBSERVABLE'
            if ('AD' in (obs.get('flags') or []))!=expected['ad']: return 'fail','AD_EXPECTATION_MISMATCH'
    return 'pass',None


def _utc():
    return datetime.now(timezone.utc).isoformat().replace('+00:00','Z')


async def run(request, event_sink=None, *, deadline=None, scheduler=None):
    start = time.monotonic()
    request = _normal(request)
    deadline = min(deadline or float('inf'),start+request['budget_ms']/1000)
    scheduler = scheduler or Scheduler(deadline, request['limits'])
    deadline=min(deadline,scheduler.deadline)
    stop_reason=None
    run_id = str(uuid.uuid4())
    report = {'schema_version':'1.0','engine_version':__version__,'catalog_version':'2026-09-07',
              'ruleset_version':'1','profile_version':'1','run_id':run_id,'started_at':_utc(),
              'duration_ms':0,'execution':{},'assessment':{},'coverage':{},'summary':{},
              'findings':[],'next_actions':[],'artifacts':{'report_path':None,'evidence_path':None},
              'errors':[],'checks':[],'observations':[],'environment':{},'effective_config':request}
    fingerprint=hashlib.sha256()
    for source in sorted(Path(__file__).parent.glob('*.py')):
        fingerprint.update(source.name.encode()); fingerprint.update(source.read_bytes())
    report['implementation_fingerprint']=fingerprint.hexdigest()
    seq=0
    def emit(event, **data):
        nonlocal seq
        seq+=1
        if event_sink: event_sink({'schema_version':'1.0','run_id':run_id,'seq':seq,'event':event,**data})
    emit('run_started', started_at=report['started_at'])
    selected = selected_tests(request)
    plan_data = {'paths':[],'targets':[],'checks':[]}
    def add_check(test_id,target_id,path_id,status,evidence_ids,reason_code=None,required=False,**extra):
        existing = next((c for c in report['checks'] if c['test_id']==test_id and c['target_id']==target_id
                         and c['path_id']==path_id and c.get('qtype')==extra.get('qtype')),None)
        c = existing or {'id':f'{test_id}:{path_id}:{target_id}:{extra.get("qtype","")}',
                         'test_id':test_id,'target_id':target_id,'path_id':path_id}
        c.update(status=status,evidence_ids=evidence_ids,reason_code=reason_code,required=required or c.get('required',False),**extra)
        if not existing: report['checks'].append(c)
        for o in report['observations']:
            if o['id'] in evidence_ids and not o.get('check_id'): o['check_id']=c['id']
        return c
    def finding(code,message,obs,severity='warning',confidence='medium',**extra):
        f = {'id':f'f-{len(report["findings"])+1:03}', 'code':code,'message':message,
             'severity':severity,'confidence':confidence,'rule_id':code.lower()+'/1',
             'evidence_ids':[o['id'] for o in obs],
             'evidence_summary':[{k:o.get(k) for k in ('id','path_id','outcome','rcode')} for o in obs[:3]],
             'alternatives':[],**extra}
        report['findings'].append(f); emit('finding', finding=f, provisional=True)
        return f
    transport = None
    async def probe(endpoint,name,qtype,options=None,check_id=None):
        options=dict(options or {})
        for k in ('force_family','interface'):
            if request.get(k) is not None: options.setdefault(k,request[k])
        queued=time.monotonic()
        obs={'id':f'obs-{len(report["observations"])+1:05}', 'check_id':check_id,
             'path_id':endpoint['id'],'target_id':name,'qname':name,'qtype':qtype,
             'outcome':'cancelled','error':None,'timing':{},'attempt_index':options.pop('_attempt_index',0),
             'sample_kind':options.pop('_sample_kind','diagnostic')}
        report['observations'].append(obs)
        try:
            target=next((t for t in plan_data['targets'] if _key_name(t['name'])==_key_name(name)),{'name':name})
            if not _allowed(target,endpoint,request,report['environment']):
                obs['error']={'code':'POLICY_EXCLUDED','message':'Query excluded by name routing policy','stage':'planner'}
                return obs
            if not _native_type_supported(endpoint,qtype):
                obs['error']={'code':'SYSTEM_RRTYPE_UNSUPPORTED',
                              'message':'Native address lookup supports only A and AAAA','stage':'planner'}
                return obs
            async with scheduler.slot(endpoint,kind='system' if endpoint['endpoint']=='system' else 'dns'):
                remaining=max(1,int((deadline-time.monotonic())*1000))
                timeout=min(800 if endpoint['endpoint'].startswith('udp:') else 1500,remaining)
                result=await transport.exchange(endpoint,name,qtype,timeout,options)
                obs.update(result)
                obs.setdefault('timing',{})['queue_ms']=round((time.monotonic()-queued)*1000-obs.get('timing',{}).get('total_ms',0),3)
                obs['timeout_ms']=timeout
                obs['wire_attempts_observable']=endpoint['endpoint']!='system'
                # Hostname bootstrap is observable as an OS lookup, not guessed wire packets.
                if (obs.get('bootstrap') or {}).get('source')=='system': scheduler.auxiliary+=1
        except BudgetExhausted as exc:
            obs['error']={'code':'BUDGET_EXHAUSTED','message':str(exc),'stage':'scheduler'}
        except asyncio.CancelledError:
            obs['error']={'code':'CANCELLED','message':'Global run cancelled','stage':'scheduler'}
            raise
        except Exception as exc:
            obs.update(outcome='error',error={'code':'INTERNAL_PROBE_ERROR','message':str(exc)[:300],'stage':'engine'})
            report['errors'].append(dict(obs['error']))
        finally:
            scheduler.evidence_bytes+=len(json.dumps(obs,ensure_ascii=False,default=str).encode())
            emit('observation',observation=obs)
        return obs

    async def basic(c):
        path = next(p for p in plan_data['paths'] if p['id']==c['path_id'])
        target,qt=c['target_id'],c['qtype']
        obs=await probe(path,target,qt,{'edns_payload':1232},c['id'])
        chain=[obs]
        if obs.get('outcome') in ('timeout','error') and (obs.get('error') or {}).get('code') not in (
                'TLS_CERTIFICATE_ERROR','ENCRYPTED_BOOTSTRAP_FAILED','SYSTEM_INTERFACE_UNSUPPORTED',
                'INTERFACE_BIND_UNSUPPORTED','UNSUPPORTED','SYSTEM_RRTYPE_UNSUPPORTED','INTERNAL_PROBE_ERROR'):
            await asyncio.sleep(.05)
            obs=await probe(path,target,qt,{'edns_payload':1232,'_attempt_index':1},c['id']); chain.append(obs)
        if 'TC' in (obs.get('flags') or []) and path['endpoint'].startswith('udp://'):
            tcp=dict(path,endpoint=path['endpoint'].replace('udp://','tcp://',1))
            obs=await probe(tcp,target,qt,{'_attempt_index':len(chain)},c['id']); chain.append(obs)
            status,reason=_semantic(obs,qt,target,request)
            if 'DNS.TRUNCATION' in selected:
                add_check('DNS.TRUNCATION',target,path['id'],status,[o['id'] for o in chain],reason,
                          required=request['tests']!='auto')
        status,reason=_semantic(obs,qt,target,request)
        c.update(status=status,reason_code=reason,evidence_ids=[o['id'] for o in chain])
        expected=next((e for e in request.get('expectations',[]) if _key_name(e['target'])==_key_name(target)
                       and e.get('type',qt)==qt and e.get('resolver_id',path['id'])==path['id']),None)
        if expected and 'required' in expected: c['required']=expected['required']
        if status=='fail':
            finding('RESOLVER_EXPECTATION_MISMATCH' if obs.get('outcome')=='response' else 'DNS_PATH_FAILURE',
                    f'{target} {qt}: {reason}',chain,'error' if c['required'] else 'warning',
                    'high' if obs.get('outcome')=='response' else 'medium', affects_assessment=c['required'])
        for rr in obs.get('answers',[]):
            for value in rr.get('values',[]) if rr.get('type')=='A' else []:
                try: synthetic=ipaddress.ip_address(value) in ipaddress.ip_network('198.18.0.0/15')
                except ValueError: synthetic=False
                if synthetic:
                    finding('SYNTHETIC_ANSWER_OBSERVED','Synthetic address observed; upstream identity is unverified',[obs],
                            'info','medium',affects_assessment=False)
        return c

    async def extras(path,target):
        name=target['name']; baseline = [o for o in report['observations'] if o['path_id']==path['id'] and o['target_id']==name]
        if not _allowed(target,path,request,report['environment']): return
        if 'PERF.SAMPLE' in selected or 'DNS.CACHE' in selected:
            if not _native_type_supported(path,target.get('types',['A'])[0]):
                for tid in ('PERF.SAMPLE','DNS.CACHE'):
                    if tid in selected:
                        add_check(tid,name,path['id'],'skipped',[],'SYSTEM_RRTYPE_UNSUPPORTED',
                                  required=request['tests']!='auto')
                return
            count={'quick':3,'standard':5,'deep':20}[request['profile']]
            for i in range(count):
                o=await probe(path,name,target.get('types',['A'])[0],{'_sample_kind':'repeat_observed'})
                baseline.append(o)
                if o['outcome']=='cancelled': break
                if len(baseline)>=2 and all(o['outcome'] in ('timeout','error') for o in baseline[-2:]): break
            stats=sample_statistics(baseline)
            semantic_states=[_semantic(o,o['qtype'],name,request)[0] for o in baseline]
            healthy=semantic_states.count('pass')
            stats['semantic_success_count']=healthy
            if 'PERF.SAMPLE' in selected:
                perf_status='pass' if healthy and 'fail' not in semantic_states else 'warn' if healthy else 'fail' if 'fail' in semantic_states else 'inconclusive'
                add_check('PERF.SAMPLE',name,path['id'],perf_status,
                          [o['id'] for o in baseline],metrics=stats,required=request['tests']!='auto')
            if 'DNS.CACHE' in selected:
                add_check('DNS.CACHE',name,path['id'],'pass' if healthy>=2 else 'fail' if 'fail' in semantic_states else 'inconclusive',
                          [o['id'] for o in baseline],cache_state='unknown',required=request['tests']!='auto',connection_and_cache_independent=True)
        if path['endpoint']=='system': return
        if 'DNS.TCP' in selected and path['endpoint'].startswith('udp://'):
            tcp=dict(path,endpoint=path['endpoint'].replace('udp://','tcp://',1))
            o=await probe(tcp,name,'A')
            status,reason=_semantic(o,'A',name,request)
            add_check('DNS.TCP',name,path['id'],status,[o['id']],reason,
                      required=request['tests']!='auto')
        if 'DNS.EDNS' in selected:
            o=await probe(path,name,'A',{'edns_payload':1232})
            add_check('DNS.EDNS',name,path['id'],'pass' if o['outcome']=='response' else 'inconclusive',
                      [o['id']],None if o['outcome']=='response' else 'NO_RESPONSE',
                      required=request['tests']!='auto',details={'ede':o.get('ede',[]),'edns':o.get('edns_version')})
        if 'DNS.TRUNCATION' in selected and not any(c['test_id']=='DNS.TRUNCATION' and c['path_id']==path['id'] and c['target_id']==name for c in report['checks']):
            add_check('DNS.TRUNCATION',name,path['id'],'skipped',[],'TRUNCATION_NOT_OBSERVED')

    async def negatives(path):
        if 'DNS.NEGATIVE' not in selected: return
        fixtures=[f for f in request.get('fixtures',[]) if f.get('kind') in ('nxdomain','nodata')]
        if not fixtures:
            if request['network_scope'] in ('system','private'):
                add_check('DNS.NEGATIVE','control',path['id'],'skipped',[],'FIXTURE_UNAVAILABLE',required=request['tests']!='auto'); return
            fixtures=[{'name':f'{run_id[:12]}.dnsprobe.invalid','type':'A','rcode':'NXDOMAIN','kind':'nxdomain'}]
        for f in fixtures:
            name=f['name']; qt=f['type']; required=request['tests']!='auto'
            if f.get('expires_at') and datetime.fromisoformat(f['expires_at'].replace('Z','+00:00'))<=datetime.now(timezone.utc):
                add_check('DNS.NEGATIVE',name,path['id'],'skipped',[],'FIXTURE_EXPIRED',required=required); continue
            if not _allowed({'name':name},path,request,report['environment']):
                add_check('DNS.NEGATIVE',name,path['id'],'skipped',[],'POLICY_EXCLUDED'); continue
            o=await probe(path,name,qt)
            expected={'target':name,'type':qt,'rcode':f['rcode'],'max_answers':0}
            status,reason=_semantic(o,qt,name,dict(request,expectations=[expected]))
            if status=='fail' and not f.get('id') and o.get('rcode')=='NOERROR' and o.get('answers'):
                status='warn'
                finding('NEGATIVE_RESPONSE_SYNTHESIZED','Reserved .invalid name received an answer; policy or synthetic proxy may explain it',[o],affects_assessment=required)
            add_check('DNS.NEGATIVE',name,path['id'],status,[o['id']],reason,required=required,
                      expectation_source='configured_fixture' if f.get('id') else 'reserved_invalid_name')

    cancelled=False; fatal=False
    try:
        async with asyncio.timeout_at(asyncio.get_running_loop().time()+max(0,deadline-time.monotonic())):
            from .discovery import discover
            from .transport import Transport
            report['environment']=await discover()
            plan_data=plan(request,report['environment'])
            report['checks']=deepcopy(plan_data['checks'])
            report['plan']=plan_data
            emit('plan_ready',plan=plan_data)
            if 'ENV.SYSTEM' in selected:
                add_check('ENV.SYSTEM','environment','system','pass',[],details=report['environment'])
            if 'ENV.PROXY_PATH' in selected:
                add_check('ENV.PROXY_PATH','environment','system','pass',[],identity_verified=False,
                          details={'proxy_detection':'observations_only'})
            async with Transport() as transport:
                await asyncio.gather(*(basic(c) for c in report['checks'][:] if c['status']=='pending' and c.get('qtype')))
                # Optional diagnostics are lower priority than all target first results.
                jobs=[extras(p,t) for t in plan_data['targets'] for p in plan_data['paths']]
                jobs.extend(negatives(p) for p in plan_data['paths'])
                await asyncio.gather(*jobs)
                from .advanced import run_advanced
                for target in plan_data['targets']:
                    allowed=[p for p in plan_data['paths'] if _allowed(target,p,request,report['environment'])]
                    advanced_req=dict(request,targets=[target],_selected_tests=sorted(selected & ADVANCED),
                                      _private_target=_private(target['name'],report['environment']))
                    fs=await run_advanced(advanced_req,allowed,probe,add_check,network_slot=scheduler.slot)
                    for f in fs or []:
                        f.setdefault('id',f'f-{len(report["findings"])+1:03}')
                        f.setdefault('affects_assessment',request['tests']!='auto')
                        if not f.get('evidence_summary'):
                            f['evidence_summary']=[{k:o.get(k) for k in ('id','path_id','outcome','rcode')} for o in report['observations'] if o['id'] in f.get('evidence_ids',[])][:3]
                        report['findings'].append(f); emit('finding',finding=f,provisional=True)
    except BudgetExhausted as exc:
        scheduler.stop_reason=str(exc)
    except TimeoutError:
        stop_reason='deadline'
        if time.monotonic()>=scheduler.deadline: scheduler.stop_reason='deadline'
    except asyncio.CancelledError:
        cancelled=True
    except Exception as exc:
        fatal=True
        report['errors'].append({'code':'INTERNAL_ERROR','message':f'{type(exc).__name__}: {exc}'[:500]})
    stop_reason=stop_reason or scheduler.stop_reason
    for c in report['checks']:
        if c['status']=='pending': c.update(status='skipped',reason_code='CANCELLED' if cancelled else 'BUDGET_EXHAUSTED' if stop_reason else 'NOT_APPLICABLE')
    # Explicit test requests are never silently discarded by unavailable prerequisites.
    for test_id in selected:
        if not any(c['test_id']==test_id for c in report['checks']):
            add_check(test_id,'*','*','skipped',[],
                      'BUDGET_EXHAUSTED' if stop_reason else 'NOT_APPLICABLE',
                      required=request['tests']!='auto' and test_id not in ('ENV.SYSTEM','ENV.PROXY_PATH'))
    # Endpoint transports are observations, not claims that every resolver supports them.
    for path in plan_data['paths']:
        proto=urlsplit(path['endpoint']).scheme
        tid={'tls':'TRANSPORT.DOT','https':'TRANSPORT.DOH','quic':'TRANSPORT.DOQ'}.get(proto)
        if tid and tid in selected:
            obs=[o for o in report['observations'] if o['path_id']==path['id']]
            existing=next((c for c in report['checks'] if c['test_id']==tid and c['path_id']=='*'),None)
            if existing: report['checks'].remove(existing)
            status='pass' if any(o['outcome']=='response' for o in obs) else 'inconclusive'
            add_check(tid,'*',path['id'],status,[o['id'] for o in obs],required=request['tests']!='auto')
    if 'DNS.CONSISTENCY' in selected:
        by_target=defaultdict(list)
        for o in report['observations']:
            if o.get('outcome')=='response' and o.get('qtype')=='A': by_target[o['target_id']].append(o)
        for target,obs in by_target.items():
            sets={tuple(sorted(v for rr in o.get('answers',[]) if rr.get('type')=='A' for v in rr.get('values',[]))) for o in obs}
            if len(sets)>1:
                finding('ANSWER_SET_DIFFERENCE','Answer sets differ; CDN, policy, cache or routing may explain this',obs,'info','high',affects_assessment=False)
            add_check('DNS.CONSISTENCY',target,'*','pass' if len({o['path_id'] for o in obs})>1 else 'skipped',
                      [o['id'] for o in obs],None if len({o['path_id'] for o in obs})>1 else 'INSUFFICIENT_PATHS')
    fatal=fatal or bool(report['errors'])
    assessments = [c for c in report['checks'] if c.get('required')]
    unresolved=[c['id'] for c in assessments if c['status'] in ('skipped','error','inconclusive')]
    sufficient=bool(assessments) and not unresolved
    status='fail' if any(c['status']=='fail' for c in assessments) else 'unknown' if not sufficient else 'warn' if any(c['status']=='warn' for c in assessments) else 'pass'
    # A cancelled probe is still evidence and must reference a coverage node.
    check_ids={c['id'] for c in report['checks']}
    for o in report['observations']:
        if o.get('check_id') in check_ids:
            c=next(c for c in report['checks'] if c['id']==o['check_id'])
            if o['id'] not in c['evidence_ids']: c['evidence_ids'].append(o['id'])
        if o.get('check_id') not in check_ids:
            linked=next((c for c in report['checks'] if o['id'] in c['evidence_ids']),None)
            if linked is None:
                linked=next((c for c in report['checks'] if c['path_id']==o['path_id'] and c['target_id']==o['target_id']),None)
            if linked is not None:
                o['check_id']=linked['id']
                if o['id'] not in linked['evidence_ids']: linked['evidence_ids'].append(o['id'])
    execution='cancelled' if cancelled else 'error' if fatal else 'partial' if stop_reason else 'completed'
    fail_on=request.get('fail_on','error')
    threshold={'error'} if fail_on=='error' else {'error','warning'} if fail_on=='warning' else set()
    violations=any(f.get('severity') in threshold and f.get('affects_assessment',True) for f in report['findings'])
    if status=='fail' and fail_on!='never': violations=True
    if status=='warn' and fail_on=='warning': violations=True
    exit_code=130 if cancelled else 4 if fatal else 3 if not sufficient or execution=='partial' else 1 if violations else 0
    report['execution']={'status':execution,'stop_reason':stop_reason,'exit_code':exit_code}
    report['assessment']={'status':status,'scope':'requested_targets_on_current_network'}
    counts=Counter(c['status'] for c in report['checks'])
    report['coverage']={'planned':len(report['checks']),'completed':sum(counts[s] for s in ('pass','warn','fail')),
        'inconclusive':counts['inconclusive'],'skipped':counts['skipped'],'error':counts['error'],
        'sufficient_for_assessment':sufficient,'required_unresolved':unresolved,'not_selected':sorted(set(TESTS)-selected)}
    path_stats={p['id']:sample_statistics([o for o in report['observations'] if o['path_id']==p['id'] and o.get('sample_kind')=='repeat_observed']) for p in plan_data['paths']}
    report['statistics']=path_stats
    # A short diagnostic is deliberately allowed to return no winner.
    eligible=[]
    comparison_targets={(_key_name(t['name']),t['types'][0]) for t in plan_data['targets']}
    for p in plan_data['paths']:
        stats=path_stats[p['id']]
        checks=[c for c in report['checks'] if c['path_id']==p['id'] and c['test_id'] in ('DNS.BASIC','RESOLVE.SYSTEM')]
        synthetic=any(f['code']=='SYNTHETIC_ANSWER_OBSERVED' and any(o['path_id']==p['id'] and o['id'] in f['evidence_ids'] for o in report['observations']) for f in report['findings'])
        groups=defaultdict(list)
        for o in report['observations']:
            if o['path_id']==p['id'] and o.get('sample_kind')=='repeat_observed': groups[(_key_name(o['target_id']),o['qtype'])].append(o)
        fair=bool(comparison_targets) and set(groups)==comparison_targets
        medians=[]
        for (name,qt), samples in groups.items():
            metrics=sample_statistics(samples)
            semantically_good=sum(_semantic(o,qt,name,request)[0]=='pass' for o in samples)
            fair=fair and metrics['success_count']>=20 and metrics['response_rate']>=.95 and semantically_good>=.95*len(samples)
            medians.append(metrics['p50_ms'] or 0)
        if not synthetic and fair and checks and all(c['status']=='pass' for c in checks):
            eligible.append((statistics.mean(medians),p['id']))
    eligible.sort()
    recommended=eligible[0][1] if len(eligible)>=2 and eligible[1][0]>eligible[0][0]*1.2 and sufficient else None
    report['summary']={'headline':{'pass':'Required DNS checks passed','fail':'DNS expectations failed',
        'warn':'DNS checks completed with warnings','unknown':'Insufficient evidence for a complete assessment'}[status],
        'recommended_resolver_id':recommended,'recommendation_reason':'insufficient_comparable_samples' if recommended is None else 'observed_latency_among_eligible_paths'}
    if unresolved or status=='fail':
        followup=deepcopy(request)
        followup.pop('output',None); followup.pop('session',None)
        followup['budget_ms']=min(60000,max(request['budget_ms']*2,5000))
        argv=['dnsprobe','run','--agent','--request-json',json.dumps(followup,separators=(',',':'))]
        report['next_actions']=[{'id':'a-001','kind':'diagnostic','reason_code':'CONFIRM_OR_COMPLETE',
            'argv':argv,'mutates_system':False,'estimated_max_duration_ms':min(60000,max(request['budget_ms']*2,5000))+250}]
    report['cost']={'dns_attempts':scheduler.attempts,'auxiliary_calls':scheduler.auxiliary,
                    'system_wire_attempts_observable':False}
    report['duration_ms']=round((time.monotonic()-start)*1000,3)
    report['config_hash']=hashlib.sha256(json.dumps(request,sort_keys=True,default=str).encode()).hexdigest()
    emit('run_finished',report=report)
    return report
