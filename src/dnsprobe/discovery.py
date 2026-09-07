"""Bounded, read-only platform discovery and cancellable native resolution.

Configuration is evidence, never a claim about the OS resolver's selected route.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import platform
import re
import socket
import sys
import time
from pathlib import Path


def _endpoint(address, source, interface=None, domains=None, **extra):
    address = str(address).strip()
    base = address.split('%')[0]
    try:
        ip = ipaddress.ip_address(base)
    except ValueError:
        return None
    if ip.version == 6 and ip.is_link_local and '%' not in address and interface:
        address += '%' + str(interface)
    host = f'[{address}]' if ip.version == 6 else address
    return {'id': f'system-dns-{address}-{interface or "default"}',
            'endpoint': f'udp://{host}:53', 'bootstrap_ips': [], 'source': source,
            'interface_scope': interface, 'routing_domains': domains or [],
            'scope_known': bool(domains or interface), **extra}


def _empty():
    return {'system_resolvers': [], 'private_domains': [], 'interfaces': [], 'warnings': []}


def _unique(result):
    seen = set()
    result['system_resolvers'] = [r for r in result['system_resolvers'] if not (
        (key := (r['endpoint'], r.get('interface_scope'), tuple(r.get('routing_domains', [])))) in seen
        or seen.add(key))]
    result['private_domains'] = sorted(set(result['private_domains']))
    return result


def parse_scutil_dns(text):
    result = _empty()
    for block in re.split(r'(?m)^resolver #\d+\s*$', text)[1:]:
        addresses = re.findall(r'nameserver\[\d+\]\s*:\s*(\S+)', block)
        domain = re.search(r'(?m)^\s*domain\s*:\s*(\S+)', block)
        search = re.findall(r'search domain\[\d+\]\s*:\s*(\S+)', block)
        iface = re.search(r'if_index\s*:\s*(\d+)\s*(?:\(([^)]+)\))?', block)
        interface = (iface.group(2) or iface.group(1)) if iface else None
        domains = [domain.group(1).rstrip('.')] if domain else []
        flags = re.search(r'(?m)^\s*flags\s*:\s*(.+)', block)
        result['private_domains'].extend(domains + search)
        for address in addresses:
            endpoint = _endpoint(address, 'scutil --dns', interface, domains,
                                 flags=flags.group(1).strip() if flags else None)
            if endpoint: result['system_resolvers'].append(endpoint)
    return _unique(result)


def parse_resolv_conf(text):
    result = _empty()
    for line in text.splitlines():
        parts = re.split(r'[;#]', line, maxsplit=1)[0].split()
        if not parts: continue
        if parts[0] == 'nameserver' and len(parts) > 1:
            endpoint = _endpoint(parts[1], 'resolv.conf')
            if endpoint: result['system_resolvers'].append(endpoint)
        elif parts[0] in ('search', 'domain'):
            result['private_domains'].extend(p.rstrip('.') for p in parts[1:])
    return _unique(result)


def _as_list(value):
    return value if isinstance(value, list) else ([value] if value else [])


def parse_windows_dns(data):
    result = _empty()
    for item in _as_list(data.get('servers')):
        interface = item.get('InterfaceAlias') or str(item.get('InterfaceIndex', ''))
        for address in _as_list(item.get('ServerAddresses')):
            endpoint = _endpoint(address, 'Get-DnsClientServerAddress', interface)
            if endpoint: result['system_resolvers'].append(endpoint)
    for item in _as_list(data.get('nrpt')):
        domains = [str(v).lstrip('.').rstrip('.') for v in _as_list(item.get('Namespace')) if v != '.']
        result['private_domains'].extend(domains)
        for value in _as_list(item.get('NameServers')):
            for address in re.split(r'[,;\s]+', value):
                endpoint = _endpoint(address, 'Get-DnsClientNrptPolicy', domains=domains)
                if endpoint: result['system_resolvers'].append(endpoint)
    for item in _as_list(data.get('clients')):
        domain = item.get('ConnectionSpecificSuffix')
        if domain: result['private_domains'].append(domain)
    return _unique(result)


def parse_resolvectl(text):
    """Parse version-stable status labels while retaining route-only domains."""
    result = _empty()
    blocks = re.split(r'(?m)^(?=Global\s*$|Link \d+ \()', text)
    for block in blocks:
        iface = re.search(r'^Link (\d+) \(([^)]+)\)', block)
        interface = iface.group(2) if iface else None
        match = re.search(r'(?m)^\s*DNS Servers:\s*(.*)((?:\n\s{12,}\S+[^:\n]*$)*)', block)
        domains_match = re.search(r'(?m)^\s*DNS Domain:\s*(.+)', block)
        domains = domains_match.group(1).split() if domains_match else []
        private = [d.lstrip('~').rstrip('.') for d in domains if d not in ('.', '~.')]
        result['private_domains'].extend(private)
        if match:
            for address in (match.group(1) + match.group(2)).split():
                endpoint = _endpoint(address, 'resolvectl status', interface, domains)
                if endpoint: result['system_resolvers'].append(endpoint)
    return _unique(result)


async def _command(argv, timeout=0.7):
    process = None
    try:
        async with asyncio.timeout(timeout):
            process = await asyncio.create_subprocess_exec(*argv, stdout=asyncio.subprocess.PIPE,
                                                           stderr=asyncio.subprocess.DEVNULL)
            output = bytearray()
            while chunk := await process.stdout.read(16384):
                output.extend(chunk)
                if len(output) > 262144: raise ValueError('command output limit')
            code = await process.wait()
            return output.decode('utf-8', 'replace') if code == 0 else None
    except (OSError, TimeoutError, ValueError):
        return None
    finally:
        if process is not None and process.returncode is None:
            try: process.kill()
            except ProcessLookupError: pass
            await process.wait()


async def discover():
    result = _empty()
    result.update(platform=platform.system(), resolver_selection='unobservable',
                  wire_attempts_observable=False, route_reachability='unverified')
    system = result['platform']
    if system == 'Darwin':
        raw = await _command(['/usr/sbin/scutil', '--dns'])
        if raw: result.update(parse_scutil_dns(raw))
        else: result['warnings'].append('SCUTIL_DNS_UNAVAILABLE')
    elif system == 'Windows':
        script = ("$ErrorActionPreference='Stop'; $s=@(Get-DnsClientServerAddress); "
                  "$n=@(Get-DnsClientNrptPolicy -Effective); $c=@(Get-DnsClient); "
                  "@{servers=$s;nrpt=$n;clients=$c}|ConvertTo-Json -Depth 6 -Compress")
        raw = await _command(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script], 1.0)
        if raw:
            try: result.update(parse_windows_dns(json.loads(raw)))
            except (ValueError, TypeError): result['warnings'].append('WINDOWS_DNS_PARSE_FAILED')
        else: result['warnings'].append('WINDOWS_DNS_DISCOVERY_UNAVAILABLE')
    else:
        raw = await _command(['resolvectl', 'status', '--no-pager'], .5)
        if raw: result.update(parse_resolvectl(raw))
        result['warnings'].append('RESOLVED_DBUS_NOT_QUERIED_STATUS_FALLBACK')
        try:
            nss = Path('/etc/nsswitch.conf').read_text()[:65536]
            result['nss_hosts'] = next((l.partition(':')[2].strip() for l in nss.splitlines() if l.startswith('hosts:')), None)
        except OSError: result['nss_hosts'] = None
    if not result['system_resolvers'] and system != 'Windows':
        try:
            fallback = parse_resolv_conf(Path('/etc/resolv.conf').read_text()[:65536])
            result['system_resolvers'] = fallback['system_resolvers']
            result['private_domains'].extend(fallback['private_domains'])
            result['warnings'].append('RESOLV_CONF_FALLBACK_SCOPE_INCOMPLETE')
        except OSError: result['warnings'].append('SYSTEM_DNS_CONFIGURATION_UNAVAILABLE')
    try:
        result['interfaces'] = [{'index': index, 'name': name,
                                 'tunnel_hint': name.startswith(('utun', 'tun', 'tap', 'wg', 'ppp'))}
                                for index, name in socket.if_nameindex()]
    except OSError: result['warnings'].append('INTERFACES_UNAVAILABLE')
    try:
        addresses = interface_addresses()
        for entry in result['interfaces']: entry['addresses'] = addresses.get(entry['name'], [])
    except (ImportError, OSError): result['warnings'].append('INTERFACE_ADDRESSES_UNAVAILABLE')
    result['proxy'] = {'mode': 'direct', 'environment_proxy_configured': any(
        os.environ.get(key) for key in ('HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy', 'ALL_PROXY', 'all_proxy')),
        'environment_proxy_used': False}
    result['container_hint'] = Path('/.dockerenv').exists()
    result['wsl_hint'] = 'microsoft' in platform.release().lower()
    return _unique(result)


# One isolated process per operation: no blocked thread can keep the parent alive.
_LOOKUP = '''import json,socket,sys
try:
 family = socket.AF_INET if sys.argv[2] == 'A' else socket.AF_INET6
 addresses = sorted({item[4][0] for item in socket.getaddrinfo(sys.argv[1],None,family,socket.SOCK_STREAM)})
 print(json.dumps({'addresses':addresses}))
except socket.gaierror as exc:
 print(json.dumps({'error':exc.errno}))
'''


async def system_lookup(name, qtype, timeout_ms):
    started = time.monotonic()
    result = {'outcome': 'error', 'rcode': None, 'flags': [], 'answers': [], 'authority': [],
              'additional': [], 'ede': [], 'error': None, 'transport': 'system', 'peer_ip': None,
              'address_family': None, 'connection_state': 'unobservable', 'wire_attempts_observable': False,
              'unobservable_fields': ['rcode', 'ttl', 'ad', 'upstream_ip'], 'timing': {}}
    process = None
    try:
        if qtype not in ('A', 'AAAA'):
            result['error'] = {'code': 'SYSTEM_RRTYPE_UNSUPPORTED',
                               'message': 'Native address lookup supports only A and AAAA', 'stage': 'system'}
            return result
        if timeout_ms <= 0: raise TimeoutError
        async with asyncio.timeout(timeout_ms / 1000):
            process = await asyncio.create_subprocess_exec(sys.executable, '-I', '-c', _LOOKUP, name, qtype,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            output, _ = await process.communicate()
            if process.returncode != 0: raise RuntimeError('Native resolver helper failed')
            value = json.loads(output)
            if 'error' in value:
                result['error'] = {'code': 'SYSTEM_LOOKUP_FAILED', 'message': 'Native resolver returned an address lookup error',
                                   'stage': 'system', 'native_code': value['error']}
            else:
                result.update(outcome='response', answers=[{'name': name.rstrip('.') + '.', 'type': qtype,
                    'ttl': None, 'values': value['addresses']}], answer_address_family='ipv4' if qtype == 'A' else 'ipv6')
    except TimeoutError:
        result.update(outcome='timeout', error={'code': 'SYSTEM_TIMEOUT', 'message': 'Native lookup exceeded its deadline', 'stage': 'system'})
    except (OSError, RuntimeError, ValueError) as exc:
        result['error'] = {'code': 'SYSTEM_HELPER_ERROR', 'message': str(exc), 'stage': 'system'}
    finally:
        if process is not None and process.returncode is None:
            try: process.kill()
            except ProcessLookupError: pass
            await process.wait()
        result['timing']['total_ms'] = round((time.monotonic() - started) * 1000, 3)
    return result


def interface_addresses():
    """Enumerate addresses without DNS I/O; data belongs to this process namespace."""
    import psutil
    return {name: [{'address': entry.address, 'family': 'ipv4' if entry.family == socket.AF_INET else 'ipv6',
                    'netmask': entry.netmask}
                   for entry in entries if entry.family in (socket.AF_INET, socket.AF_INET6)]
            for name, entries in psutil.net_if_addrs().items()}


def interface_source(interface, address):
    family = 'ipv6' if ':' in address else 'ipv4'
    values = interface_addresses()
    if interface not in values: raise ValueError('Named interface was not found in the current process network namespace')
    peerscope = ipaddress.ip_address(address.split('%')[0]).is_link_local
    candidates = [e['address'] for e in values[interface] if e['family'] == family and
                  not ipaddress.ip_address(e['address'].split('%')[0]).is_unspecified]
    if family == 'ipv6':
        candidates = [v for v in candidates if ipaddress.ip_address(v.split('%')[0]).is_link_local == peerscope]
    if not candidates: raise ValueError('Named interface has no applicable address for the endpoint address family')
    return candidates[0]
