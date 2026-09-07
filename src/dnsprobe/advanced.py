"""Bounded advanced DNS diagnostics. All DNS I/O uses the engine's probe.

DNSSEC validates signatures locally from explicitly configured DNSKEY/DS anchors.
Unsupported algorithms, opt-out proofs, missing signatures, and incomplete chains
remain inconclusive; an AD bit is never substituted for local validation.
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
import datetime as dt
import ipaddress
import ssl
import time

import dns.dnssec
import dns.exception
import dns.message
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset

ADVANCED_TESTS = {
    'DNS.RECORDS', 'DNS.CNAME', 'DNS.DELEGATION', 'DNS.DNS64',
    'DNS.IDENTITY', 'DNS.ECS', 'DNS.DNSSEC_BEHAVIOR', 'DNS.DNSSEC_VALIDATE', 'APP.CONNECT',
}


def _name(value):
    return dns.name.from_text(value).canonicalize().to_text()


def _values(obs, kind, section='answers', owner=None):
    return [v for rr in obs.get(section, []) if rr.get('type') == kind
            and (owner is None or _name(rr['name']) == _name(owner)) for v in rr.get('values', [])]


def _reachable_values(obs, kind, owner):
    """Accept terminal answers only on the queried name's unambiguous CNAME path."""
    current = _name(owner)
    seen = set()
    for _ in range(64):
        if current in seen:
            return []
        seen.add(current)
        aliases = {_name(v) for v in _values(obs, 'CNAME', owner=current)}
        if not aliases:
            return _values(obs, kind, owner=current)
        if len(aliases) != 1:
            return []
        current = next(iter(aliases))
    return []


def _ok(obs):
    return obs.get('outcome') == 'response'


def _wire(obs):
    value = obs.get('response_wire_b64')
    if not value:
        raise _Unverified('DNS_WIRE_UNAVAILABLE')
    try:
        return dns.message.from_wire(base64.b64decode(value, validate=True))
    except Exception as exc:
        raise _Unverified('DNS_WIRE_INVALID') from exc


def _finding(code, message, evidence, severity='info', alternatives=None):
    return dict(code=code, message=message, severity=severity,
                confidence='high' if severity == 'error' else 'medium',
                rule_id=code.lower().replace('_', '-')+'/v1',
                evidence_ids=evidence, evidence_summary=[], alternatives=alternatives or [])


class _Unverified(Exception):
    pass


class _Bogus(Exception):
    pass


def _rrset(message, owner, kind, sections=None):
    for rrset in sections if sections is not None else message.answer + message.authority:
        if rrset.name == dns.name.from_text(owner) and rrset.rdtype == dns.rdatatype.from_text(kind):
            return rrset
    return None


def _signatures(message, rrset):
    for candidate in message.answer + message.authority:
        if (candidate.name == rrset.name and candidate.rdtype == dns.rdatatype.RRSIG
                and candidate.covers == rrset.rdtype):
            return candidate
    raise _Unverified('RRSIG_UNAVAILABLE')


def _validate(rrset, sigs, keys):
    try:
        dns.dnssec.validate(rrset, sigs, keys)
    except dns.exception.UnsupportedAlgorithm as exc:
        raise _Unverified('DNSSEC_ALGORITHM_UNSUPPORTED') from exc
    except dns.dnssec.DeniedByPolicy as exc:
        raise _Unverified('DNSSEC_ALGORITHM_POLICY') from exc
    except dns.dnssec.ValidationFailure as exc:
        raise _Bogus('DNSSEC_SIGNATURE_INVALID') from exc


def _has_type(record, qtype):
    value = dns.rdatatype.from_text(qtype)
    window, offset = divmod(value, 256)
    for number, bits in record.windows:
        if number == window:
            byte, bit = divmod(offset, 8)
            return byte < len(bits) and bool(bits[byte] & (0x80 >> bit))
    return False


def _covers(owner, following, value):
    """Canonical DNS name or base32hex hash interval; endpoints excluded."""
    return owner < value < following if owner < following else value > owner or value < following


def _denial(message, name, qtype, signer):
    """Verify denial semantics after signatures are independently validated."""
    qname = dns.name.from_text(name).canonicalize()
    zone = dns.name.from_text(signer).canonicalize()
    if not qname.is_subdomain(zone):
        raise _Unverified('DENIAL_OUTSIDE_SIGNER_ZONE')
    nsecs = [(r.name.canonicalize(), item) for r in message.authority
             if r.rdtype == dns.rdatatype.NSEC for item in r]
    nsec3 = [(r.name, item) for r in message.authority
             if r.rdtype == dns.rdatatype.NSEC3 for item in r]
    nx = message.rcode() == dns.rcode.NXDOMAIN
    if nsecs:
        if any(not owner.is_subdomain(zone) or not item.next.is_subdomain(zone) for owner,item in nsecs):
            raise _Unverified('DENIAL_OUTSIDE_SIGNER_ZONE')
        if not nx:
            exact = [item for owner,item in nsecs if owner == qname]
            if exact and _has_type(exact[0],'NS') and not _has_type(exact[0],'SOA') and qtype != 'DS':
                raise _Unverified('DENIAL_BELOW_DELEGATION')
            if exact and not _has_type(exact[0],qtype) and not _has_type(exact[0],'CNAME'):
                return 'NSEC_NODATA'
            raise _Unverified('DENIAL_PROOF_INCOMPLETE')
        existing = {owner for owner,_ in nsecs} | {zone}
        ancestor = qname.parent()
        while ancestor not in existing and ancestor != zone:
            ancestor = ancestor.parent()
        if any(owner == ancestor and _has_type(item,'NS') and not _has_type(item,'SOA') for owner,item in nsecs):
            raise _Unverified('DENIAL_BELOW_DELEGATION')
        wildcard = dns.name.from_text('*', origin=ancestor)
        def covered(n):
            return any(_covers(owner, item.next.canonicalize(), n) for owner,item in nsecs)
        if covered(qname) and covered(wildcard):
            return 'NSEC_NXDOMAIN'
    if nsec3:
        first = nsec3[0][1]
        if any(item.flags & 1 for _,item in nsec3):
            raise _Unverified('NSEC3_OPTOUT_UNSUPPORTED')
        if first.algorithm != 1 or first.iterations > 150:
            raise _Unverified('NSEC3_PARAMETERS_UNSUPPORTED')
        if any((item.algorithm,item.iterations,item.salt) != (first.algorithm,first.iterations,first.salt)
               or owner.parent() != zone for owner,item in nsec3):
            raise _Unverified('NSEC3_PARAMETERS_INCONSISTENT')
        def hashed(n):
            return dns.dnssec.nsec3_hash(n,first.salt,first.iterations,first.algorithm).upper()
        records = {owner.labels[0].decode().upper(): item for owner,item in nsec3}
        hq = hashed(qname)
        if not nx:
            item=records.get(hq)
            if item and _has_type(item,'NS') and not _has_type(item,'SOA') and qtype != 'DS':
                raise _Unverified('DENIAL_BELOW_DELEGATION')
            if item and not _has_type(item,qtype) and not _has_type(item,'CNAME'):
                return 'NSEC3_NODATA'
            raise _Unverified('DENIAL_PROOF_INCOMPLETE')
        ancestor = qname.parent()
        next_closer = qname
        while ancestor.is_subdomain(zone):
            if hashed(ancestor) in records:
                break
            next_closer, ancestor = ancestor, ancestor.parent()
        if not ancestor.is_subdomain(zone):
            raise _Unverified('DENIAL_PROOF_INCOMPLETE')
        closest=records[hashed(ancestor)]
        if _has_type(closest,'NS') and not _has_type(closest,'SOA'):
            raise _Unverified('DENIAL_BELOW_DELEGATION')
        wildcard = dns.name.from_text('*',origin=ancestor)
        def covered_hash(n):
            h = hashed(n)
            return any(_covers(owner,base64.b32hexencode(item.next).decode().rstrip('='),h)
                       for owner,item in records.items())
        if covered_hash(next_closer) and covered_hash(wildcard):
            return 'NSEC3_NXDOMAIN'
    raise _Unverified('DENIAL_PROOF_INCOMPLETE')


class _Validator:
    def __init__(self, anchors, query):
        self.anchors = anchors
        self.query = query
        self.keys = {}
        self.visiting = set()

    async def trusted_keys(self, signer):
        signer = dns.name.from_text(signer).canonicalize()
        if signer in self.keys:
            return self.keys[signer]
        if signer in self.visiting or len(self.visiting) >= 32:
            raise _Unverified('DNSSEC_CHAIN_DEPTH_LIMIT')
        self.visiting.add(signer)
        try:
            message = _wire(await self.query(signer.to_text(),'DNSKEY',{'do':True,'cd':True}))
            keyset = _rrset(message, signer.to_text(),'DNSKEY')
            if not keyset:
                raise _Unverified('DNSKEY_UNAVAILABLE')
            anchors = [a for a in self.anchors if dns.name.from_text(a['name']).canonicalize()==signer]
            if anchors:
                trusted = dns.rrset.RRset(signer, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
                for key in keyset:
                    for anchor in anchors:
                        kind = anchor.get('type','DNSKEY')
                        data = dns.rdata.from_text('IN',kind,anchor['value'])
                        if (kind=='DNSKEY' and data==key) or (kind=='DS' and self.matches_ds(signer,key,data)):
                            trusted.add(key,keyset.ttl)
                if not trusted:
                    raise _Bogus('TRUST_ANCHOR_MISMATCH')
                _validate(keyset,_signatures(message,keyset),{signer:trusted})
            else:
                if signer == dns.name.root:
                    raise _Unverified('TRUST_ANCHOR_NO_CHAIN')
                dsmessage=_wire(await self.query(signer.to_text(),'DS',{'do':True,'cd':True}))
                dsset=_rrset(dsmessage,signer.to_text(),'DS')
                if not dsset:
                    raise _Unverified('INSECURE_OR_MISSING_DELEGATION')
                sigs=_signatures(dsmessage,dsset)
                parent=sigs[0].signer
                if parent == signer or not signer.is_subdomain(parent):
                    raise _Bogus('DNSSEC_INVALID_PARENT_SIGNER')
                parentkeys=await self.trusted_keys(parent.to_text())
                _validate(dsset,sigs,{parent:parentkeys})
                trusted=dns.rrset.RRset(signer,dns.rdataclass.IN,dns.rdatatype.DNSKEY)
                for key in keyset:
                    if any(self.matches_ds(signer,key,ds) for ds in dsset):
                        trusted.add(key,keyset.ttl)
                if not trusted:
                    raise _Bogus('DNSSEC_DS_MISMATCH')
                _validate(keyset,_signatures(message,keyset),{signer:trusted})
            self.keys[signer]=keyset
            return keyset
        finally:
            self.visiting.discard(signer)

    @staticmethod
    def matches_ds(signer,key,ds):
        try:
            return dns.dnssec.make_ds(signer,key,ds.digest_type,validating=True)==ds
        except (dns.exception.UnsupportedAlgorithm,dns.dnssec.DeniedByPolicy):
            return False

    async def validate(self, name, qtype):
        message=_wire(await self.query(name,qtype,{'do':True,'cd':True}))
        if message.rcode() not in (dns.rcode.NOERROR,dns.rcode.NXDOMAIN):
            raise _Unverified('DNSSEC_RESPONSE_UNAVAILABLE')
        sets=[r for r in message.answer if r.rdtype != dns.rdatatype.RRSIG]
        if not sets:
            sets=[r for r in message.authority if r.rdtype in (dns.rdatatype.SOA,dns.rdatatype.NSEC,dns.rdatatype.NSEC3)]
        if not sets:
            raise _Unverified('DNSSEC_PROOF_UNAVAILABLE')
        signers=set()
        for rrset in sets:
            sigs=_signatures(message,rrset)
            signer=sigs[0].signer
            if not rrset.name.is_subdomain(signer):
                raise _Bogus('DNSSEC_SIGNER_OUTSIDE_ZONE')
            keys=await self.trusted_keys(signer.to_text())
            _validate(rrset,sigs,{signer:keys})
            signers.add(signer)
            if any(sig.labels < len(rrset.name.labels)-1 for sig in sigs):
                raise _Unverified('WILDCARD_PROOF_NOT_VALIDATED')
        if not message.answer:
            if len(signers)!=1:
                raise _Unverified('DENIAL_SIGNERS_INCONSISTENT')
            return _denial(message,name,qtype,next(iter(signers)).to_text())
        # A signed CNAME alone does not validate its target's requested RRset.
        current=dns.name.from_text(name)
        seen=set()
        for _ in range(32):
            if current in seen:
                raise _Bogus('CNAME_LOOP')
            seen.add(current)
            if _rrset(message,current.to_text(),qtype,message.answer):
                return 'DNSSEC_CHAIN_VALIDATED'
            aliases=_rrset(message,current.to_text(),'CNAME',message.answer)
            if not aliases:
                raise _Unverified('DNSSEC_TERMINAL_RRSET_MISSING')
            current=aliases[0].target
        raise _Unverified('DNSSEC_CHAIN_DEPTH_LIMIT')


async def run_advanced(request, paths, probe, add_check, network_slot=None):
    findings=[]
    selection=request.get('tests','auto')
    if '_selected_tests' in request:
        selected=ADVANCED_TESTS.intersection(request['_selected_tests'])
    elif selection=='all':
        selected=ADVANCED_TESTS
    elif selection=='auto':
        selected=(ADVANCED_TESTS-{'APP.CONNECT'} if request.get('profile')=='deep' else {'DNS.DNSSEC_BEHAVIOR'} if request.get('profile','standard')=='standard' else set())
    else:
        selected=ADVANCED_TESTS.intersection(selection)
    if '_selected_tests' not in request and any(target.get('app') for target in request.get('targets',[])):
        selected=selected|{'APP.CONNECT'}
    targets=request.get('targets',[])

    async def run_one(test,path,target):
        endpoint=path.get('endpoint')
        if isinstance(endpoint,dict):
            endpoint={**endpoint,'id':path.get('id')}
        else:
            endpoint=path
        path_id=path.get('id',path.get('path_id','unknown'))
        name=target.get('name','example.com')
        target_id=target.get('id',name)
        evidence=[]
        required=(test in request['_required_tests'] if '_required_tests' in request else
                  selection=='all' or isinstance(selection,list) and test in selection)
        def finish(status,reason=None,**details):
            return add_check(test,target_id,path_id,status,evidence,reason,required=required,details=details)
        async def query(qname,qtype,options=None,ep=None):
            obs=await probe(ep or endpoint,qname,qtype,options=options,check_id=f'{test}:{path_id}:{target_id}:')
            if obs.get('id'): evidence.append(obs['id'])
            return obs
        if test != 'APP.CONNECT' and (endpoint.get('endpoint')=='system' or path.get('transport')=='system'):
            return finish('skipped','NOT_APPLICABLE')
        if test=='DNS.RECORDS':
            kinds=[t for t in target.get('types',[]) if t not in ('A','AAAA')]
            if not kinds: kinds=['MX','TXT','NS','SOA','CAA','HTTPS','SVCB']
            if name.endswith(('.in-addr.arpa','.ip6.arpa')): kinds=['PTR']
            if name.startswith('_') and '._' in name: kinds=['SRV','TXT']
            results={}
            for kind in kinds:
                obs=await query(name,kind)
                results[kind]={'outcome':obs.get('outcome'),'rcode':obs.get('rcode'),'values':_reachable_values(obs,kind,name)}
            return finish('pass' if all(x['outcome']=='response' and x['rcode']=='NOERROR' for x in results.values()) else 'inconclusive','RECORDS_OBSERVED',records=results)
        if test=='DNS.CNAME':
            current=_name(name); seen=set(); chain=[]
            maximum=request.get('cname_max_depth',16)
            for _ in range(maximum):
                if current in seen:
                    findings.append(_finding('CNAME_LOOP','A repeated name proves a CNAME loop on this path.',evidence.copy(),'error'))
                    return finish('fail','CNAME_LOOP',chain=chain)
                seen.add(current)
                obs=await query(current,'A')
                if not _ok(obs): return finish('inconclusive','CNAME_QUERY_FAILED',chain=chain)
                if obs.get('rcode')=='NXDOMAIN' and chain:
                    findings.append(_finding('CNAME_TARGET_NXDOMAIN','The observed alias target returned NXDOMAIN.',evidence.copy(),'warning',['transient_authoritative_change']))
                    return finish('warn','CNAME_TARGET_NXDOMAIN',chain=chain)
                if obs.get('rcode')!='NOERROR': return finish('inconclusive','CNAME_RESPONSE_UNAVAILABLE',chain=chain)
                aliases={_name(r['name']):_name(r['values'][0]) for r in obs.get('answers',[]) if r.get('type')=='CNAME' and r.get('values')}
                if current not in aliases:
                    if chain and not (_values(obs,'A',owner=current) or _values(obs,'AAAA',owner=current) or _values(obs,'SOA','authority')):
                        return finish('inconclusive','CNAME_TERMINAL_UNVERIFIED',chain=chain)
                    return finish('pass','CNAME_CHAIN_COMPLETE',chain=chain)
                while current in aliases:
                    following=aliases[current]; chain.append({'name':current,'target':following})
                    if following in seen:
                        findings.append(_finding('CNAME_LOOP','A repeated name proves a CNAME loop on this path.',evidence.copy(),'error'))
                        return finish('fail','CNAME_LOOP',chain=chain)
                    if len(chain)>=maximum: return finish('inconclusive','CNAME_DEPTH_LIMIT',chain=chain)
                    current=following
                    if current in aliases: seen.add(current)
                if _values(obs,'A',owner=current) or _values(obs,'AAAA',owner=current):
                    return finish('pass','CNAME_CHAIN_COMPLETE',chain=chain)
            return finish('inconclusive','CNAME_DEPTH_LIMIT',chain=chain)
        if test=='DNS.DNS64':
            if request.get('network_scope') in ('system','private'):
                return finish('skipped','POLICY_EXCLUDED')
            obs=await query('ipv4only.arpa','AAAA')
            prefixes=set()
            for value in _reachable_values(obs,'AAAA','ipv4only.arpa'):
                try: packed=ipaddress.IPv6Address(value).packed
                except ValueError: continue
                for length in (32,40,48,56,64,96):
                    prefix_bytes=length//8
                    embedded=packed[12:16] if length==96 else packed[prefix_bytes:8]+packed[9:9+(4-(8-prefix_bytes))]
                    if embedded in (b'\xc0\x00\x00\xaa',b'\xc0\x00\x00\xab') and (length==96 or packed[8]==0):
                        prefixes.add(str(ipaddress.IPv6Network((value,length),strict=False)))
            if prefixes:
                findings.append(_finding('DNS64_SYNTHESIS_OBSERVED','AAAA results embed the RFC 7050 IPv4 controls; DNS64 synthesis is plausible.',evidence.copy()))
                return finish('pass','DNS64_SYNTHESIS_OBSERVED',prefixes=sorted(prefixes))
            return finish('inconclusive','DNS64_NOT_OBSERVED',prefixes=[])
        if test in ('DNS.IDENTITY','DNS.ECS'):
            options={'nsid':True} if test=='DNS.IDENTITY' else {'ecs':request.get('ecs','0.0.0.0/0')}
            obs=await query(name,'A',options)
            kind='NSID' if test=='DNS.IDENTITY' else 'ECS'
            values=[o for o in obs.get('edns_options',[]) if str(o.get('type',o.get('name',''))).upper() in (kind,'3' if kind=='NSID' else '8')]
            return finish('pass' if values else 'inconclusive',kind+'_OBSERVED' if values else kind+'_NOT_OBSERVED',options=values,interpretation='self_report_only' if kind=='NSID' else 'echo_does_not_prove_upstream_forwarding')
        if test=='DNS.DNSSEC_BEHAVIOR':
            fixtures=[f for f in request.get('fixtures',[]) if f.get('kind') in ('signed','bogus','unsigned','dnssec_valid','dnssec_bogus','dnssec_unsigned')]
            if not fixtures: return finish('skipped','FIXTURE_UNAVAILABLE')
            results=[]
            for fixture in fixtures:
                try: expiry=dt.datetime.fromisoformat(fixture['expires_at'].replace('Z','+00:00'))
                except (KeyError,ValueError,TypeError): return finish('inconclusive','FIXTURE_EXPIRY_UNAVAILABLE')
                if expiry.tzinfo is None or expiry<=dt.datetime.now(dt.timezone.utc): return finish('inconclusive','FIXTURE_EXPIRED')
                fkind=fixture['kind']; qtype=fixture.get('type','A')
                normal=await query(fixture['name'],qtype,{'do':True,'cd':False})
                disabled=await query(fixture['name'],qtype,{'do':True,'cd':True})
                if not _ok(normal) or not _ok(disabled): return finish('inconclusive','FIXTURE_QUERY_FAILED')
                # This only observes configured expectations, never certifies fixture health remotely.
                expected=fixture.get('answers',[])
                control_values=_reachable_values(disabled,qtype,fixture['name'])
                control_ok=disabled.get('rcode')=='NOERROR' and bool(control_values) and (not expected or set(expected).issubset(control_values))
                if not control_ok: return finish('inconclusive','FIXTURE_UNHEALTHY')
                if fkind in ('bogus','dnssec_bogus'):
                    if normal.get('rcode')=='NOERROR' and _reachable_values(normal,qtype,fixture['name']):
                        findings.append(_finding('DNSSEC_BOGUS_ACCEPTED','The resolver accepted a configured bogus fixture with checking enabled.',evidence.copy(),'error',['fixture_state_changed','resolver_validation_disabled_by_policy']))
                        return finish('fail','DNSSEC_BOGUS_ACCEPTED',fixture_id=fixture.get('id'),expectation_source='configured_fixture')
                    if normal.get('rcode')!='SERVFAIL': return finish('inconclusive','DNSSEC_BEHAVIOR_AMBIGUOUS')
                else:
                    normal_values=_reachable_values(normal,qtype,fixture['name'])
                    if normal.get('rcode')!='NOERROR' or not normal_values or (expected and not set(expected).issubset(normal_values)):
                        return finish('inconclusive','DNSSEC_VALID_CONTROL_FAILED')
                results.append({'fixture_id':fixture.get('id'),'kind':fkind,'rcode':normal.get('rcode'),'ad':'AD' in normal.get('flags',[])})
            return finish('pass','DNSSEC_BEHAVIOR_OBSERVED',fixtures=results,local_validation=False)
        if test=='DNS.DNSSEC_VALIDATE':
            anchors=request.get('trust_anchors',[])
            if not anchors: return finish('skipped','TRUST_ANCHOR_UNAVAILABLE')
            validator=_Validator(anchors,query)
            try:
                validated=[]
                for qtype in target.get('types',['A','AAAA']):
                    validated.append({'type':qtype,'proof':await validator.validate(name,qtype)})
                return finish('pass','DNSSEC_CHAIN_VALIDATED',validated=validated,trust_anchor_source='request')
            except _Unverified as exc: return finish('inconclusive',str(exc))
            except _Bogus as exc:
                findings.append(_finding(str(exc),'Local DNSSEC validation failed against the configured trust anchor.',evidence.copy(),'error',['stale_trust_anchor','incorrect_local_clock']))
                return finish('fail',str(exc))
        if test=='DNS.DELEGATION':
            if request.get('network_scope') in ('system','private') or (request.get('_private_target') and not target.get('allow_public')):
                return finish('skipped','POLICY_EXCLUDED')
            if not target.get('allow_public') and path.get('source') not in ('explicit','user') and not request.get('public_comparison'):
                return finish('skipped','POLICY_EXCLUDED')
            roots=request.get('delegation_roots',['198.41.0.4'])
            server=roots[0]; previous=dns.name.root; chain=[]; seen=set()
            for depth in range(24):
                obs=await query(name,target.get('types',['A'])[0],{'rd':False},ep={'id':f'authority-{server}','endpoint':f'udp://[{server}]:53' if ':' in server else f'udp://{server}:53'})
                if not _ok(obs): return finish('inconclusive','AUTHORITY_UNREACHABLE',chain=chain)
                if 'AA' in obs.get('flags',[]): return finish('pass','DELEGATION_REACHED_AUTHORITY',chain=chain,rcode=obs.get('rcode'))
                referrals=[r for r in obs.get('authority',[]) if r.get('type')=='NS' and dns.name.from_text(name).is_subdomain(dns.name.from_text(r['name']))]
                if not referrals: return finish('inconclusive','DELEGATION_REFERRAL_MISSING',chain=chain)
                referral=max(referrals,key=lambda r:len(dns.name.from_text(r['name']).labels))
                zone=dns.name.from_text(referral['name'])
                if (zone.to_text(),server) in seen or not zone.is_subdomain(previous) or (depth and zone==previous):
                    return finish('inconclusive','DELEGATION_LOOP_OR_INVALID',chain=chain)
                seen.add((zone.to_text(),server)); previous=zone
                names=referral.get('values',[])
                glue=[]
                for ns in names:
                    if dns.name.from_text(ns).is_subdomain(zone):
                        glue.extend(_values(obs,'A','additional',ns)+_values(obs,'AAAA','additional',ns))
                if not glue and names:
                    resolved=await query(names[0],'A')
                    glue=_values(resolved,'A',owner=names[0])
                valid=[]
                for address in glue:
                    try: valid.append(str(ipaddress.ip_address(address)))
                    except ValueError: pass
                chain.append({'zone':zone.to_text(),'nameservers':names,'addresses':valid})
                if not valid: return finish('inconclusive','DELEGATION_ADDRESS_UNAVAILABLE',chain=chain)
                server=valid[0]
            return finish('inconclusive','DELEGATION_DEPTH_LIMIT',chain=chain)
        if test=='APP.CONNECT':
            app=target.get('app')
            if not app: return finish('skipped','APPLICATION_ENDPOINT_UNSPECIFIED')
            addresses=[]
            for kind in ('A','AAAA'):
                obs=await query(name,kind)
                if _ok(obs) and obs.get('rcode') in ('NOERROR',None): addresses.extend(_reachable_values(obs,kind,name))
            if not addresses: return finish('inconclusive','APPLICATION_DNS_UNAVAILABLE')
            connections=[]
            for address in addresses[:4]:
                try: ipaddress.ip_address(address)
                except ValueError: continue
                writer=None; started=time.monotonic()
                tls=app.get('tls',True); port=app.get('port',443 if tls else 80)
                try:
                    context=ssl.create_default_context(cafile=app.get('ca_file')) if tls else None
                    slot=network_slot(endpoint,kind='connect') if network_slot else contextlib.nullcontext()
                    async with slot:
                        async with asyncio.timeout(min(request.get('budget_ms',15000)/1000,3)):
                            _,writer=await asyncio.open_connection(address,port,ssl=context,server_hostname=app.get('server_name',name) if tls else None)
                    connections.append({'peer_ip':address,'port':port,'tls':tls,'status':'pass','duration_ms':round((time.monotonic()-started)*1000,3)})
                    return finish('pass','APPLICATION_CONNECTED',connections=connections)
                except ssl.SSLCertVerificationError:
                    connections.append({'peer_ip':address,'status':'fail','error_code':'TLS_CERTIFICATE_INVALID'})
                except (OSError,TimeoutError) as exc:
                    connections.append({'peer_ip':address,'status':'fail','error_code':'CONNECT_TIMEOUT' if isinstance(exc,TimeoutError) else 'CONNECT_FAILED'})
                finally:
                    if writer:
                        writer.close()
                        with contextlib.suppress(Exception): await asyncio.wait_for(writer.wait_closed(),.1)
            findings.append(_finding('DNS_OK_CONNECT_FAILED','DNS returned addresses but the explicit application connection attempts failed.',evidence.copy(),'warning',['application_service_down','path_filtering','tls_identity_failure']))
            return finish('warn','DNS_OK_CONNECT_FAILED',connections=connections)

    # Bounded task count, fair per-path interleaving; DNS concurrency remains engine-owned.
    jobs=[]
    for test in sorted(selected):
        for path in paths:
            scoped=targets[:1] if test in ('DNS.DNS64','DNS.DNSSEC_BEHAVIOR','DNS.IDENTITY','DNS.ECS') else targets
            for target in scoped:
                jobs.append((test,path,target))
    for test,path,target in jobs:
        await run_one(test,path,target)
    return findings
