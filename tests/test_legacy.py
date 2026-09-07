"""Legacy compatibility is explicit, bounded and does not invent old metrics."""
import json
from pathlib import Path
import subprocess
import sys

import pytest


def test_legacy_request_mapping(tmp_path):
    from dnsprobe.legacy import translate, CompatibilityError
    servers = tmp_path / 'servers.txt'
    servers.write_text('127.0.0.1 loopback local\n# comment\n::1 ipv6 local\n')
    request, options = translate('bench', ['--servers-file', str(servers), '-d', 'example.test', '--no-v6', '-c', '2', '--no-ping', '--json', str(tmp_path / 'out.json')])
    assert request['targets'] == [{'name': 'example.test', 'types': ['A'], 'allow_public': False}]
    assert [r['endpoint'] for r in request['resolvers']] == ['udp://127.0.0.1:53', 'udp://[::1]:53']
    assert request['limits']['concurrency'] == 2
    assert options['json_path'] == str(tmp_path / 'out.json')
    hk, _ = translate('hk', ['-s', '127.0.0.1', '--quick'])
    assert hk['workload'] == 'hong-kong' and hk['profile'] == 'quick'
    lab, _ = translate('lab', ['--profile', 'quick', '-s', '127.0.0.1'])
    assert lab['profile'] == 'deep' and lab['budget_ms'] == 60000
    for args, duration in [([],300000), (['--profile','marathon'],1800000), (['--duration','2','--interval','2','-s','127.0.0.1'],2000)]:
        observe, metadata = translate('lab',args)
        assert observe['session']['duration_ms'] == duration
        assert observe['session']['max_runs'] <= 1000
        assert metadata['session']['duration_ms'] == duration
        assert observe['targets'] and observe['resolvers']
    for mode, args in [('bench', ['-r', '20']), ('bench', ['--timeout', '3']), ('bench', ['--min-reliability','90']), ('bench',['--unknown'])]:
        with pytest.raises(CompatibilityError): translate(mode, args)


def test_legacy_envelope_and_atomic_json(tmp_path):
    from dnsprobe.legacy import envelope, save_json
    report = {'schema_version':'1.0', 'duration_ms':123, 'execution':{'status':'partial','exit_code':3},
              'coverage':{'sufficient_for_assessment':False}, 'assessment':{'status':'unknown'},
              'summary':{'recommended_resolver_id':None}, 'findings':[], 'observations':[]}
    full = envelope('bench', report, ['LEGACY_ADAPTER_V1'])
    assert full['ok'] is False and full['returncode'] == 3
    assert full['data'] == report
    assert full['recommend'] == {'primary':None,'backup':None}
    brief = envelope('bench', report, [], brief=True)
    assert 'data' not in brief
    assert brief['execution']['status'] == 'partial'
    assert brief['coverage']['sufficient_for_assessment'] is False
    output = tmp_path / 'legacy.json'; save_json(output, full)
    assert json.loads(output.read_text()) == full
    assert list(tmp_path.iterdir()) == [output]


def test_legacy_entrypoints_offline(tmp_path):
    root = Path(__file__).resolve().parents[1]
    for name in ('dnstk.py', 'dns_bench.py', 'dns_bench_hk.py', 'dns_lab.py'):
        result = subprocess.run([sys.executable, str(root / name), '--help'], capture_output=True, text=True, timeout=3)
        assert result.returncode == 0, result.stderr
        assert 'compatibility' in result.stdout.lower(), result.stdout
    result = subprocess.run([sys.executable, str(root/'dnstk.py'), 'agent','bench','--brief','--timeout','9'], capture_output=True, text=True, timeout=3)
    assert result.returncode == 2
    body = json.loads(result.stdout)
    assert body['ok'] is False
    assert body['error']['code'] == 'LEGACY_OPTION_UNSUPPORTED'
    assert not result.stderr

    target = tmp_path / 'sys.json'
    result = subprocess.run([sys.executable,str(root/'dnstk.py'),'agent','sys','--json',str(target)],capture_output=True,text=True,timeout=3)
    saved=json.loads(target.read_text()); body=json.loads(result.stdout)
    assert saved['schema_version']=='1.0'
    assert body['data']==saved
    assert body['returncode']==result.returncode
    assert saved['observations']==[]
    observed = subprocess.run([sys.executable,str(root/'dnstk.py'),'agent','lab','--duration','1','--interval','2','-s','system','-d','localhost','--no-audit','--brief'],capture_output=True,text=True,timeout=3)
    body=json.loads(observed.stdout)
    assert body['returncode']==observed.returncode
    assert body['compatibility']['adapter_version']=='1.0'
    assert 'data' not in body
    assert 'LEGACY_DURATION_PRESERVED_WITH_SHARED_RESOURCE_CAP' in body['warnings']
