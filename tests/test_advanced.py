import base64
import time
import pytest
import dns.dnssec
import dns.message
import dns.name
import dns.rrset
from cryptography.hazmat.primitives.asymmetric import ec
from dnsprobe.advanced import run_advanced

PATH = {'id': 'local', 'endpoint': 'udp://127.0.0.1:5300', 'source': 'explicit'}

def rr(name, kind, *values):
    return {'name': name, 'type': kind, 'ttl': 60, 'values': list(values)}

class Harness:
    def __init__(self, responses):
        self.responses = responses
        self.checks = []
        self.queries = []
    async def probe(self, endpoint, name, qtype, options=None, check_id=None):
        self.queries.append((name.rstrip('.'), qtype, options or {}))
        key = (name.rstrip('.'), qtype)
        val = self.responses(key, options or {}) if callable(self.responses) else self.responses.get(key, {})
        return {'id': f'o{len(self.queries)}', 'outcome': 'response', 'rcode': 'NOERROR', 'answers': [], 'authority': [], 'additional': [], 'flags': [], **val}
    def add(self, test_id, target_id, path_id, status, evidence_ids, reason_code=None, required=False, **extra):
        check = dict(id=f'c{len(self.checks)}', test_id=test_id, target_id=target_id,path_id=path_id,status=status,evidence_ids=evidence_ids,reason_code=reason_code,required=required,**extra)
        self.checks.append(check)
        return check
    async def run(self, test, **extra):
        return await run_advanced({'profile':'deep','tests':[test], 'targets':[{'name':'a.example','types':['A']}], **extra}, [PATH], self.probe, self.add)

@pytest.mark.asyncio
async def test_cname_detects_loop_inside_one_response():
    h=Harness({('a.example','A'):{'answers':[rr('a.example','CNAME','b.example.'),rr('b.example','CNAME','a.example.')]}})
    findings=await h.run('DNS.CNAME')
    assert h.checks[0]['status']=='fail'
    assert findings[0]['code']=='CNAME_LOOP'
    assert len(h.queries)==1

@pytest.mark.asyncio
async def test_cname_depth_is_unknown_not_loop():
    h=Harness(lambda key,opt: {'answers':[rr(key[0],'CNAME', 'b.'+key[0])]})
    findings=await h.run('DNS.CNAME',cname_max_depth=2)
    assert h.checks[0]['status']=='inconclusive'
    assert h.checks[0]['reason_code']=='CNAME_DEPTH_LIMIT'
    assert not any(f['code']=='CNAME_LOOP' for f in findings)

@pytest.mark.asyncio
async def test_absent_optional_records_are_not_failures():
    h=Harness({})
    await h.run('DNS.RECORDS')
    assert all(c['status']=='pass' for c in h.checks)
    assert {'MX','TXT','NS','SOA','CAA','HTTPS','SVCB'} <= {q[1] for q in h.queries}

@pytest.mark.asyncio
async def test_missing_dnssec_fixture_is_explicit_skipped():
    h=Harness({})
    await h.run('DNS.DNSSEC_BEHAVIOR')
    assert h.checks[0]['status']=='skipped'
    assert h.checks[0]['reason_code']=='FIXTURE_UNAVAILABLE'
    assert not h.queries

@pytest.mark.asyncio
async def test_expired_fixture_never_blames_resolver():
    h=Harness({})
    findings=await h.run('DNS.DNSSEC_BEHAVIOR',fixtures=[{'id':'b','kind':'bogus','name':'b.example','type':'A','expires_at':'2000-01-01T00:00:00Z'}])
    assert h.checks[0]['status']=='inconclusive'
    assert h.checks[0]['reason_code']=='FIXTURE_EXPIRED'
    assert not h.queries
    assert not any(f['severity']=='error' for f in findings)

@pytest.mark.asyncio
async def test_dns64_legitimate_synthesis_not_pollution():
    h=Harness({('ipv4only.arpa','AAAA'):{'answers':[rr('ipv4only.arpa','AAAA','64:ff9b::c000:aa','64:ff9b::c000:ab')]}})
    findings=await h.run('DNS.DNS64')
    assert h.checks[0]['status']=='pass'
    assert h.checks[0]['details']['prefixes']==['64:ff9b::/96']
    assert all(f['severity']=='info' for f in findings)

@pytest.mark.asyncio
async def test_no_nsid_is_unknown():
    h=Harness({})
    await h.run('DNS.IDENTITY')
    assert h.checks[0]['status']=='inconclusive'

@pytest.mark.asyncio
async def test_dnssec_without_anchor_never_claims_validation():
    h=Harness({})
    await h.run('DNS.DNSSEC_VALIDATE')
    assert h.checks[0]['status']=='skipped'
    assert h.checks[0]['reason_code']=='TRUST_ANCHOR_UNAVAILABLE'

def signed_fixture(tamper=False):
    key=ec.generate_private_key(ec.SECP256R1())
    public=dns.dnssec.make_dnskey(key.public_key(),13,flags=257)
    owner=dns.name.from_text('example.')
    keys=dns.rrset.from_rdata(owner,60,public)
    answer=dns.rrset.from_text('a.example.',60,'IN','A','192.0.2.1')
    def signed(rrset):
        signature=dns.dnssec.sign(rrset,key,owner,public,inception=int(time.time())-60,lifetime=3600)
        return dns.rrset.from_rdata(rrset.name,60,signature)
    sig=signed(answer)
    if tamper: answer=dns.rrset.from_text('a.example.',60,'IN','A','192.0.2.2')
    def wire(name,kind,sets):
        message=dns.message.make_response(dns.message.make_query(name,kind))
        message.answer.extend(sets)
        return {'response_wire_b64':base64.b64encode(message.to_wire()).decode()}
    return public,{('example','DNSKEY'):wire('example.','DNSKEY',[keys,signed(keys)]),('a.example','A'):wire('a.example.','A',[answer,sig])}

@pytest.mark.asyncio
@pytest.mark.parametrize('tamper,expected',[(False,'pass'),(True,'fail')])
async def test_real_cryptographic_dnssec_validation(tamper,expected):
    public,responses=signed_fixture(tamper)
    h=Harness(responses)
    await h.run('DNS.DNSSEC_VALIDATE',trust_anchors=[{'name':'example.','type':'DNSKEY','value':public.to_text()}])
    assert h.checks[0]['status']==expected
    assert {q[:2] for q in h.queries}=={('a.example','A'),('example','DNSKEY')}

@pytest.mark.asyncio
async def test_app_connect_explicit_numeric_result_local_socket():
    import asyncio
    server=await asyncio.start_server(lambda r,w:w.close(),'127.0.0.1',0)
    try:
        port=server.sockets[0].getsockname()[1]
        h=Harness({('a.example','A'):{'answers':[rr('a.example','A','127.0.0.1')]}})
        await h.run('APP.CONNECT',targets=[{'name':'a.example','types':['A'],'app':{'port':port,'tls':False}}])
        assert h.checks[0]['status']=='pass'
        assert h.checks[0]['details']['connections'][0]['peer_ip']=='127.0.0.1'
    finally:
        server.close()
        await server.wait_closed()

@pytest.mark.asyncio
async def test_cname_timeout_is_inconclusive():
    h=Harness({('a.example','A'):{'outcome':'timeout'}})
    findings=await h.run('DNS.CNAME')
    assert h.checks[0]['status']=='inconclusive'
    assert not findings

@pytest.mark.asyncio
async def test_delegation_system_scope_does_not_contact_roots():
    h=Harness({})
    await h.run('DNS.DELEGATION',network_scope='system')
    assert h.checks[0]['reason_code']=='POLICY_EXCLUDED'
    assert h.queries==[]

@pytest.mark.asyncio
async def test_delegation_rejects_unrelated_glue():
    def response(key,opt):
        if len(h.queries)==1:
            return {'authority':[rr('example.','NS','ns.example.')], 'additional':[rr('evil.example.','A','203.0.113.66')]}
        return {}
    h=Harness(response)
    await h.run('DNS.DELEGATION')
    assert h.checks[0]['reason_code']=='DELEGATION_ADDRESS_UNAVAILABLE'
    assert ('ns.example','A') in {q[:2] for q in h.queries}


def signed_denial(kind='NSEC',rcode='NXDOMAIN',tamper=False):
    key=ec.generate_private_key(ec.SECP256R1())
    public=dns.dnssec.make_dnskey(key.public_key(),13,flags=257)
    owner=dns.name.from_text('example.')
    keys=dns.rrset.from_rdata(owner,60,public)
    def signed(rrset):
        return dns.rrset.from_rdata(rrset.name,60,dns.dnssec.sign(rrset,key,owner,public,inception=int(time.time())-60,lifetime=3600))
    if kind=='NSEC':
        denial=dns.rrset.from_text('example.',60,'IN','NSEC','z.example. NS SOA RRSIG NSEC DNSKEY')
    else:
        hashed=dns.dnssec.nsec3_hash('example.',b'',0,1)
        denial=dns.rrset.from_text(hashed+'.example.',60,'IN','NSEC3',f'1 0 0 - {hashed} NS SOA RRSIG DNSKEY NSEC3PARAM')
    negative=dns.message.make_response(dns.message.make_query('a.example.','A'))
    negative.set_rcode(dns.rcode.from_text(rcode))
    signature=signed(denial)
    if tamper:
        denial=dns.rrset.from_text('example.',60,'IN','NSEC','b.example. NS SOA RRSIG NSEC DNSKEY')
    negative.authority.extend([denial,signature])
    keymessage=dns.message.make_response(dns.message.make_query('example.','DNSKEY'))
    keymessage.answer.extend([keys,signed(keys)])
    return public,{('example','DNSKEY'):{'response_wire_b64':base64.b64encode(keymessage.to_wire()).decode()},('a.example','A'):{'response_wire_b64':base64.b64encode(negative.to_wire()).decode()}}

@pytest.mark.asyncio
@pytest.mark.parametrize('kind',['NSEC','NSEC3'])
async def test_cryptographic_nxdomain_denial(kind):
    public,responses=signed_denial(kind)
    h=Harness(responses)
    await h.run('DNS.DNSSEC_VALIDATE',trust_anchors=[{'name':'example.','type':'DNSKEY','value':public.to_text()}])
    assert h.checks[0]['status']=='pass'
    assert h.checks[0]['details']['validated'][0]['proof']==kind+'_NXDOMAIN'

@pytest.mark.asyncio
async def test_tampered_denial_signature_fails():
    public,responses=signed_denial(tamper=True)
    h=Harness(responses)
    await h.run('DNS.DNSSEC_VALIDATE',trust_anchors=[{'name':'example.','type':'DNSKEY','value':public.to_text()}])
    assert h.checks[0]['status']=='fail'

@pytest.mark.asyncio
async def test_cryptographic_ds_chain():
    root_private=ec.generate_private_key(ec.SECP256R1())
    child_private=ec.generate_private_key(ec.SECP256R1())
    root_public=dns.dnssec.make_dnskey(root_private.public_key(),13,flags=257)
    child_public=dns.dnssec.make_dnskey(child_private.public_key(),13,flags=257)
    root=dns.name.from_text('.')
    child=dns.name.from_text('example.')
    rootkeys=dns.rrset.from_rdata(root,60,root_public)
    childkeys=dns.rrset.from_rdata(child,60,child_public)
    ds=dns.rrset.from_rdata(child,60,dns.dnssec.make_ds(child,child_public,'SHA256'))
    answer=dns.rrset.from_text('a.example.',60,'IN','A','192.0.2.1')
    def wire(name,kind,rrset,private,public,signer):
        response=dns.message.make_response(dns.message.make_query(name,kind))
        sig=dns.dnssec.sign(rrset,private,signer,public,inception=int(time.time())-60,lifetime=3600)
        response.answer.extend([rrset,dns.rrset.from_rdata(rrset.name,60,sig)])
        return {'response_wire_b64':base64.b64encode(response.to_wire()).decode()}
    responses={('','DNSKEY'):wire('.','DNSKEY',rootkeys,root_private,root_public,root),('example','DS'):wire('example.','DS',ds,root_private,root_public,root),('example','DNSKEY'):wire('example.','DNSKEY',childkeys,child_private,child_public,child),('a.example','A'):wire('a.example.','A',answer,child_private,child_public,child)}
    h=Harness(responses)
    await h.run('DNS.DNSSEC_VALIDATE',trust_anchors=[{'name':'.','type':'DS','value':dns.dnssec.make_ds(root,root_public,'SHA256').to_text()}])
    assert h.checks[0]['status']=='pass'
    assert len(h.queries)==4

@pytest.mark.asyncio
async def test_all_reports_app_precondition_skip():
    h=Harness({})
    await run_advanced({'tests':'all','profile':'deep','targets':[{'name':'a.example','types':['A']}],'network_scope':'system'},[PATH],h.probe,h.add)
    app=[c for c in h.checks if c['test_id']=='APP.CONNECT']
    assert len(app)==1 and app[0]['reason_code']=='APPLICATION_ENDPOINT_UNSPECIFIED'

@pytest.mark.asyncio
async def test_cname_nodata_terminal_without_soa_not_complete():
    h=Harness({('a.example','A'):{'answers':[rr('a.example','CNAME','b.example.')]}})
    await h.run('DNS.CNAME')
    assert h.checks[0]['status']=='inconclusive'
    assert h.checks[0]['reason_code']=='CNAME_TERMINAL_UNVERIFIED'

@pytest.mark.asyncio
async def test_application_tls_checks_hostname(tmp_path):
    import asyncio
    import datetime
    import ssl
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.x509.oid import NameOID
    private=ec.generate_private_key(ec.SECP256R1())
    subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'a.example')])
    now=datetime.datetime.now(datetime.timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(private.public_key()).serial_number(1000)
          .not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(days=1))
          .add_extension(x509.SubjectAlternativeName([x509.DNSName('a.example')]),critical=False)
          .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True).sign(private,hashes.SHA256()))
    certfile=tmp_path/'ca.pem'; keyfile=tmp_path/'key.pem'
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile,keyfile)
    server=await asyncio.start_server(lambda r,w:w.close(),'127.0.0.1',0,ssl=context)
    try:
        port=server.sockets[0].getsockname()[1]
        for hostname,expected in [('a.example','pass'),('wrong.example','warn')]:
            h=Harness({('a.example','A'):{'answers':[rr('a.example','A','127.0.0.1')]}})
            await h.run('APP.CONNECT',targets=[{'name':'a.example','types':['A'],'app':{'port':port,'tls':True,'server_name':hostname,'ca_file':str(certfile)}}])
            assert h.checks[0]['status']==expected
            if expected=='warn':
                assert h.checks[0]['details']['connections'][0]['error_code']=='TLS_CERTIFICATE_INVALID'
    finally:
        server.close()
        await server.wait_closed()

@pytest.mark.asyncio
async def test_application_works_on_native_system_path():
    h=Harness({})
    await run_advanced({'tests':['APP.CONNECT'],'targets':[{'name':'a.example','app':{'tls':False,'port':80}}]},[{'id':'system','endpoint':'system'}],h.probe,h.add)
    assert h.checks[0]['reason_code']=='APPLICATION_DNS_UNAVAILABLE'
    assert len(h.queries)==2

@pytest.mark.parametrize('kind',['NSEC','NSEC3'])
def test_dnssec_parent_delegation_cannot_prove_child_nodata(kind):
    from dnsprobe.advanced import _denial,_Unverified
    message=dns.message.make_response(dns.message.make_query('child.example.','A'))
    if kind=='NSEC':
        proof=dns.rrset.from_text('child.example.',60,'IN','NSEC','z.example. NS RRSIG NSEC')
    else:
        hashed=dns.dnssec.nsec3_hash('child.example.',b'',0,1)
        proof=dns.rrset.from_text(hashed+'.example.',60,'IN','NSEC3',f'1 0 0 - {hashed} NS')
    message.authority.append(proof)
    with pytest.raises(_Unverified,match='DELEGATION'):
        _denial(message,'child.example.','A','example.')

@pytest.mark.asyncio
async def test_engine_selected_override_is_exact_and_does_not_make_auto_required():
    h=Harness({})
    await run_advanced({'tests':'auto','profile':'deep','_selected_tests':['DNS.IDENTITY'],
                       'targets':[{'name':'a.example','app':{'port':80,'tls':False}}]},[PATH],h.probe,h.add)
    assert {c['test_id'] for c in h.checks}=={'DNS.IDENTITY'}
    assert not any(c['required'] for c in h.checks)

@pytest.mark.asyncio
async def test_all_explicit_cname_failure_is_required():
    h=Harness({('a.example','A'):{'answers':[rr('a.example','CNAME','a.example.')]}})
    await run_advanced({'tests':'all','_selected_tests':['DNS.CNAME'],'targets':[{'name':'a.example'}]},[PATH],h.probe,h.add)
    assert h.checks[0]['status']=='fail'
    assert h.checks[0]['required']

@pytest.mark.asyncio
async def test_app_connect_ignores_unrelated_answer_owner(monkeypatch):
    import asyncio
    calls=[]
    async def forbidden(*args,**kwargs):
        calls.append(args)
        raise AssertionError('An unrelated answer must not trigger connection')
    monkeypatch.setattr(asyncio,'open_connection',forbidden)
    h=Harness({('a.example','A'):{'answers':[rr('unrelated.example','A','127.0.0.1')]}})
    await h.run('APP.CONNECT',targets=[{'name':'a.example','app':{'port':80,'tls':False}}])
    assert not calls
    assert h.checks[0]['reason_code']=='APPLICATION_DNS_UNAVAILABLE'

@pytest.mark.asyncio
async def test_dns64_ignores_unrelated_answer_owner():
    h=Harness({('ipv4only.arpa','AAAA'):{'answers':[rr('unrelated.example','AAAA','64:ff9b::c000:aa')]}})
    findings=await h.run('DNS.DNS64')
    assert h.checks[0]['status']=='inconclusive'
    assert not findings


def test_reachable_answers_follow_alias_but_ignore_unrelated_records():
    from dnsprobe.advanced import _reachable_values
    obs={'answers':[rr('a.example','CNAME','b.example.'),rr('b.example','A','192.0.2.1'),rr('c.example','A','192.0.2.2')]}
    assert _reachable_values(obs,'A','a.example')==['192.0.2.1']

@pytest.mark.asyncio
async def test_signed_fixture_normal_response_requires_reachable_expected_answer():
    def response(key,opt):
        owner=key[0] if opt.get('cd') else 'unrelated.example'
        return {'answers':[rr(owner,'A','192.0.2.1')]}
    h=Harness(response)
    await h.run('DNS.DNSSEC_BEHAVIOR',fixtures=[{'id':'signed','name':'signed.example','kind':'signed','type':'A','answers':['192.0.2.1'],'expires_at':'2099-01-01T00:00:00Z'}])
    assert h.checks[0]['status']=='inconclusive'
    assert h.checks[0]['reason_code']=='DNSSEC_VALID_CONTROL_FAILED'
