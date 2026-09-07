"""Explicit v1 compatibility for the four historic script entrypoints.

The envelope keys remain stable; data is a versioned DNSProbe report, never an
invented reconstruction of historical scores, cache state or hijack judgments.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
from pathlib import Path
import stat
import sys
import tempfile
import time

from .config import normalize_request


class CompatibilityError(ValueError):
    def __init__(self, message, code='LEGACY_OPTION_UNSUPPORTED', argv=None):
        self.code, self.argv = code, argv or ['dnsprobe', 'run', '--agent']
        super().__init__(message)


class Parser(argparse.ArgumentParser):
    def error(self, message): raise CompatibilityError(message, 'LEGACY_OPTION_UNSUPPORTED')


def _parser(mode):
    parser = Parser(prog='dnstk ' + mode, description='DNSProbe v1 compatibility adapter; modern evidence and exit-code semantics.')
    parser.add_argument('-s', '--server', action='append', help='Explicit resolver IP or endpoint; repeatable')
    parser.add_argument('--servers-file', help='Regular UTF-8 file: one IP [name] [group] per line')
    parser.add_argument('-d', '--domain', action='append')
    parser.add_argument('--no-v6', action='store_true', help='Query A records only; does not select the transport family')
    parser.add_argument('-c', '--concurrency', type=int, default=8)
    parser.add_argument('--json', dest='json_path', help='Atomically write the modern full report to this exact path')
    parser.add_argument('--color', choices=('auto','never','always'), default='auto')
    parser.add_argument('-q','--quiet', action='store_true')
    parser.add_argument('--no-ping', action='store_true', help='Modern diagnostics already omit ICMP')
    parser.add_argument('--no-hijack', action='store_true', help='Omit DNS.NEGATIVE checks')
    parser.add_argument('--no-audit', action='store_true', help='Omit negative and DNSSEC behavior checks')
    parser.add_argument('--no-local', action='store_true', help='Requires explicit -s/--servers-file')
    parser.add_argument('--quick', action='store_true', help='5-second modern quick profile (HK mode)')
    parser.add_argument('--profile', choices=('quick','standard','marathon'))
    parser.add_argument('--budget', help='Explicit modern wall-clock budget, e.g. 5s')
    parser.add_argument('--brief', action='store_true', help='Agent envelope without data; status/coverage retained')
    parser.add_argument('--agent', action='store_true', help='Print the legacy machine envelope')
    # Parsed explicitly so unsupported semantic changes produce useful migration data.
    for names in (('-r','--rounds'),('-t','--timeout'),('--min-reliability',),('--top',),('--preset',),('--duration',),('--interval',)):
        parser.add_argument(*names, help='Historic option; requires explicit migration to modern run/observe/bench')
    for name in ('domestic','abroad','intl','cn'):
        parser.add_argument('--'+name, action='store_true', help='Historic candidate list; migrate using explicit modern --resolver')
    return parser


def _read_servers(path):
    target = Path(path).expanduser()
    try:
        info = target.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 65536:
            raise CompatibilityError('Server list must be a regular file of at most 64 KiB', 'LEGACY_INPUT_INVALID')
        with target.open(encoding='utf-8') as stream: text = stream.read(65537)
        if len(text.encode()) > 65536: raise CompatibilityError('Server list exceeds 64 KiB', 'LEGACY_INPUT_INVALID')
    except (OSError, UnicodeError) as exc:
        raise CompatibilityError('Cannot read legacy server file: ' + type(exc).__name__, 'LEGACY_INPUT_INVALID') from exc
    values = [line.split('#',1)[0].split()[0] for line in text.splitlines() if line.split('#',1)[0].split()]
    if not values: raise CompatibilityError('Server list is empty', 'LEGACY_INPUT_INVALID')
    return values


def translate(mode, argv):
    if mode not in ('bench','hk','lab','sys'): raise CompatibilityError('Unknown legacy mode', 'LEGACY_INPUT_INVALID')
    args = _parser(mode).parse_args(argv)
    for key in ('rounds','timeout','min_reliability','top','preset','domestic','abroad','intl','cn'):
        if getattr(args,key) is not None and getattr(args,key) is not False:
            raise CompatibilityError('--' + key.replace('_','-') + ' has no equivalent v1 semantics; use explicit dnsprobe run/observe/bench options')
    if args.color == 'always': raise CompatibilityError('Forced legacy ANSI colors are unavailable; use --color never or modern text output')
    if args.server and args.servers_file: raise CompatibilityError('Use -s or --servers-file, not both', 'LEGACY_INPUT_INVALID')
    servers = args.server or (_read_servers(args.servers_file) if args.servers_file else [])
    if args.no_local and not servers: raise CompatibilityError('--no-local requires explicit resolvers', 'LEGACY_INPUT_INVALID')
    warnings = ['LEGACY_ADAPTER_V1', 'DATA_IS_VERSIONED_DNSPROBE_REPORT', 'HISTORIC_SCORES_NOT_RECONSTRUCTED']
    session = None
    if mode == 'lab':
        legacy_profile = args.profile or 'standard'
        duration = {'quick':0,'standard':300,'marathon':1800}[legacy_profile]
        interval = 10 if legacy_profile == 'quick' else 15
        try:
            if args.duration is not None: duration = int(args.duration)
            if args.interval is not None: interval = int(args.interval)
        except ValueError as exc: raise CompatibilityError('Legacy duration/interval must be integer seconds','LEGACY_INPUT_INVALID') from exc
        if not 0 <= duration <= 3600 or not 1 <= interval <= 3600:
            raise CompatibilityError('Duration must be 0–3600 seconds and interval 1–3600 seconds','LEGACY_INPUT_INVALID')
        if interval < 2:
            interval = 2; warnings.append('LEGACY_INTERVAL_MINIMUM_2S')
        profile = 'deep'
        if duration:
            session = {'duration_ms':duration*1000,'interval_ms':interval*1000,
                       'max_runs':min(1000,max(1,math.ceil(duration/interval)))}
            warnings.extend(['LEGACY_DURATION_PRESERVED_WITH_SHARED_RESOURCE_CAP','LEGACY_BURST_NOT_EXECUTED'])
            if not servers:
                servers = ['system']; warnings.append('LEGACY_OBSERVE_DEFAULT_SYSTEM_PATH')
        else:
            if args.interval is not None: raise CompatibilityError('--interval requires a positive observation duration')
            warnings.append('LEGACY_LAB_QUICK_USES_DEEP_60S_NO_BURST')
    else:
        if args.duration is not None or args.interval is not None:
            raise CompatibilityError('--duration/--interval are legacy lab options; use dnsprobe observe or bench')
        if args.profile: raise CompatibilityError('--profile is a legacy lab option; use dnsprobe run --profile')
        profile = 'quick' if args.quick or mode in ('bench','sys') else 'standard'
    if args.quick and mode != 'hk': raise CompatibilityError('--quick is a legacy HK option; use dnsprobe run --profile quick')
    if not servers: warnings.append('CANDIDATES_USE_MODERN_DISCOVERY_NOT_HISTORIC_ALL_SERVERS')
    request = {'profile':profile, 'workload':'hong-kong' if mode=='hk' else 'general',
               'resolvers':[{'endpoint':server} for server in servers],
               'targets':[{'name':name, 'types':['A'] if args.no_v6 else ['A','AAAA']} for name in args.domain or []],
               'limits':{'concurrency':args.concurrency}}
    if args.no_v6 and not args.domain:
        from .engine import WORKLOADS
        request['targets'] = [{'name':name,'types':['A']} for name in WORKLOADS[request['workload']]]
        warnings.append('NO_V6_APPLIES_TO_ANSWER_RECORDS_ONLY')
    if session:
        request['session'] = session
        if not request['targets']: request['targets'] = [{'name':'example.com','types':['A'] if args.no_v6 else ['A','AAAA']}]
    if args.budget:
        from .cli import duration_ms
        try: request['budget_ms'] = duration_ms(args.budget)
        except argparse.ArgumentTypeError as exc: raise CompatibilityError(str(exc), 'LEGACY_INPUT_INVALID') from exc
    if mode == 'sys':
        request.update(tests=['ENV.SYSTEM','ENV.PROXY_PATH'],network_scope='system')
        if args.domain or servers: raise CompatibilityError('Legacy sys is read-only discovery; use dnsprobe run for target queries')
    if args.no_hijack or args.no_audit:
        from .engine import selected_tests
        request['tests'] = sorted(selected_tests(request) - ({'DNS.NEGATIVE','DNS.DNSSEC_BEHAVIOR'} if args.no_audit else {'DNS.NEGATIVE'}))
    try: normalized = normalize_request(request)
    except ValueError as exc: raise CompatibilityError(str(exc), 'LEGACY_INPUT_INVALID') from exc
    return normalized, {'json_path':args.json_path,'brief':args.brief,'agent':args.agent,'quiet':args.quiet,'warnings':warnings,'session':session}


def envelope(mode, report, warnings, brief=False):
    code = report['execution']['exit_code']
    value = {'ok':code == 0, 'mode':mode, 'elapsed_s':round(report.get('duration_ms',0)/1000,3),
             'warnings':list(warnings) + [f['code'] for f in report.get('findings',[]) if f.get('severity') in ('warning','error')],
             'recommend':{'primary':None,'backup':None}, 'returncode':code,
             'execution':report['execution'], 'assessment':report['assessment'], 'coverage':report['coverage'],
             'compatibility':{'adapter_version':'1.0','data_schema':'dnsprobe-report/1.0','historical_metrics_available':False}}
    if not brief: value['data'] = report
    return value


def save_json(path, value):
    path = Path(path).expanduser()
    encoded = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(',',':')) + '\n'
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(descriptor,'w',encoding='utf-8') as stream:
            stream.write(encoded); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary,path)
    finally:
        try: os.unlink(temporary)
        except FileNotFoundError: pass


def main(argv=None, mode=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    agent = '--agent' in argv or (bool(argv) and argv[0]=='agent')
    started = time.monotonic()
    try:
        if mode is None:
            if not argv or argv[0] in ('-h','--help'):
                print('DNSProbe v1 compatibility: dnstk [agent] bench|hk|lab|sys [options]\nUse dnsprobe run --agent for the stable modern interface.\nLegacy --rounds/--timeout/ranking options require explicit migration.')
                return 0
            if argv[0] == 'agent': agent=True; argv.pop(0)
            if not argv: raise CompatibilityError('Missing legacy mode', 'LEGACY_INPUT_INVALID')
            mode = argv.pop(0)
        request, options = translate(mode, argv)
        agent = agent or options['agent']
        print('Deprecated script entrypoint: use dnsprobe run/observe --agent; output uses DNSProbe v1 semantics.',file=sys.stderr)
        from .engine import run
        if options['session']:
            from .cli import run_series
            series_args = argparse.Namespace(command='observe',duration=options['session']['duration_ms'],
                interval=options['session']['interval_ms'],max_runs=options['session']['max_runs'],explicit_rate=False)
            report = asyncio.run(run_series(request,series_args,started))
        else:
            report = asyncio.run(run(request, deadline=started + request['budget_ms']/1000))
        if options['json_path']: save_json(options['json_path'],report)
        if agent:
            print(json.dumps(envelope(mode,report,options['warnings'],options['brief']),ensure_ascii=False,allow_nan=False,separators=(',',':')))
        else:
            from .report import render_text
            print('Compatibility: modern DNSProbe report; historical rankings and timing semantics are not reproduced.',file=sys.stderr)
            print(render_text(report))
        return report['execution']['exit_code']
    except CompatibilityError as exc:
        error = {'ok':False,'mode':mode,'returncode':2,'error':{'code':exc.code,'message':str(exc)},
                 'next_action':{'argv':exc.argv,'mutates_system':False}}
        if agent: print(json.dumps(error,ensure_ascii=False,separators=(',',':')))
        else: print(str(exc) + '\nUse dnsprobe run --help for the modern interface.',file=sys.stderr)
        return 2
    except BrokenPipeError:
        return 0
    except OSError as exc:
        error={'ok':False,'mode':mode,'returncode':4,'error':{'code':'LEGACY_IO_ERROR','message':type(exc).__name__}}
        print(json.dumps(error,separators=(',',':')),file=sys.stdout if agent else sys.stderr)
        return 4
    except KeyboardInterrupt:
        if agent: print(json.dumps({'ok':False,'mode':mode,'returncode':130,'error':{'code':'INTERRUPTED','message':'Interrupted'}}))
        return 130
