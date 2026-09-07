"""DNS transports with strict response identity, TLS and bounded I/O.

Each exchange is one attempt. Retry and TC recovery are scheduler decisions.
"""
from __future__ import annotations

import asyncio
import base64
import ipaddress
import socket
import ssl
import struct
import time
from urllib.parse import unquote, urlsplit

import dns.asyncbackend
import dns.asyncquery
import dns.edns
import dns.exception
import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype

from .discovery import system_lookup, interface_source


class TransportError(Exception):
    def __init__(self, code, message, stage, **details):
        self.code, self.message, self.stage, self.details = code, message, stage, details
        super().__init__(message)


def _records(section):
    result = []
    for rrset in section[:128]:
        item = {'name': rrset.name.to_text(), 'type': dns.rdatatype.to_text(rrset.rdtype),
                'ttl': rrset.ttl, 'values': [rr.to_text()[:4096] for rr in list(rrset)[:128]]}
        if rrset.rdtype in (dns.rdatatype.SVCB, dns.rdatatype.HTTPS):
            item['service_bindings'] = [{'priority': rr.priority, 'target': rr.target.to_text(),
                'params': {str(int(key)): value.to_text() if value else '' for key, value in rr.params.items()}}
                for rr in list(rrset)[:128]]
        result.append(item)
    return result


def _query(name, qtype, options):
    opts = []
    if options.get('nsid'): opts.append(dns.edns.GenericOption(dns.edns.NSID, b''))
    if options.get('ecs'):
        value = options['ecs']
        if isinstance(value, str):
            network = ipaddress.ip_network(value, strict=False)
            opts.append(dns.edns.ECSOption(str(network.network_address), network.prefixlen, 0))
        else:
            opts.append(dns.edns.ECSOption(value['address'], value.get('source_prefix', value.get('srclen', 0)), value.get('scope_prefix', 0)))
    q = dns.message.make_query(name, qtype, use_edns=0, want_dnssec=bool(options.get('do')),
                               payload=options.get('edns_payload', 1232), options=opts)
    if options.get('cd'): q.flags |= dns.flags.CD
    if options.get('rd', True) is False: q.flags &= ~dns.flags.RD
    return q


def _response(response, raw=None):
    opts, ede = [], []
    for option in response.options:
        if isinstance(option, dns.edns.EDEOption):
            value = {'code': int(option.code), 'text': option.text or ''}
            ede.append(value); opts.append({'type': 'EDE', **value})
        elif isinstance(option, dns.edns.ECSOption):
            opts.append({'type': 'ECS', 'address': option.address, 'source_prefix': option.srclen, 'scope_prefix': option.scopelen})
        elif option.otype == dns.edns.NSID:
            data = option.to_wire()
            opts.append({'type': 'NSID', 'hex': data.hex(), 'text': data.decode('utf-8', 'replace')[:512]})
        else: opts.append({'type': int(option.otype), 'wire_hex': option.to_wire().hex()[:2048]})
    return {'outcome': 'response', 'rcode': dns.rcode.to_text(response.rcode()),
            'flags': dns.flags.to_text(response.flags).split(), 'answers': _records(response.answer),
            'authority': _records(response.authority), 'additional': _records(response.additional),
            'ede': ede, 'edns_options': opts, 'edns_version': response.edns, 'edns_payload': response.payload,
            'response_wire_b64': base64.b64encode(raw or response.to_wire()).decode(),
            'records_truncated': any(len(s) > 128 or any(len(r) > 128 for r in s) for s in (response.answer, response.authority, response.additional))}


def _parse(wire, query):
    response = dns.message.from_wire(wire, ignore_trailing=False)
    if not query.is_response(response) or query.question != response.question:
        raise TransportError('DNS_RESPONSE_MISMATCH', 'DNS response ID, opcode or question does not match query', 'dns')
    return response


def _ssl_error(exc):
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        if isinstance(exc, ssl.SSLCertVerificationError): return True
        exc = exc.__cause__ or exc.__context__
    return False


class Transport:
    def __init__(self):
        self._streams = {}
        self._locks = {}
        self._http = {}
        self._quic = {}
        self._tasks = set()
        self._closed = False

    async def __aenter__(self): return self

    async def __aexit__(self, *exc): await self.close()

    async def close(self):
        self._closed = True
        current = asyncio.current_task()
        tasks = [t for t in self._tasks if t is not current and not t.done()]
        for task in tasks: task.cancel()
        if tasks: await asyncio.gather(*tasks, return_exceptions=True)
        for _, writer in self._streams.values(): writer.close()
        self._streams.clear()
        clients = list(self._http.values()); self._http.clear()
        if clients: await asyncio.gather(*(client.aclose() for client in clients), return_exceptions=True)
        managers = list(self._quic.values()); self._quic.clear()
        if managers: await asyncio.gather(*(manager.__aexit__(None, None, None) for manager in managers), return_exceptions=True)

    async def exchange(self, endpoint, name, qtype, timeout_ms, options=None):
        options = options or {}
        if endpoint.get('endpoint') in ('system', 'system://'):
            task = asyncio.current_task(); self._tasks.add(task)
            try:
                result = await system_lookup(name, qtype, 0 if options.get('interface') else timeout_ms)
                if options.get('interface'):
                    result.update(outcome='error', error={'code': 'SYSTEM_INTERFACE_UNSUPPORTED',
                        'message': 'The native resolver cannot select an interface per lookup', 'stage': 'input'})
                return result
            finally:
                self._tasks.discard(task)
        started = time.monotonic()
        result = {'outcome': 'error', 'rcode': None, 'flags': [], 'answers': [], 'authority': [], 'additional': [],
                  'ede': [], 'error': None, 'peer_ip': None, 'transport': None, 'address_family': None,
                  'connection_state': 'new', 'timing': {}, 'ignored_packets': 0, 'proxy_mode': 'direct',
                  'wire_attempts_observable': True, 'bootstrap': None}
        task = asyncio.current_task(); self._tasks.add(task)
        stage = 'input'
        try:
            if self._closed: raise TransportError('TRANSPORT_CLOSED', 'Transport context is closed', 'input')
            if timeout_ms <= 0: raise TimeoutError
            async with asyncio.timeout(timeout_ms / 1000):
                parsed = urlsplit(endpoint['endpoint'])
                scheme = {'tls': 'dot', 'https': 'doh', 'quic': 'doq'}.get(parsed.scheme, parsed.scheme)
                if scheme not in ('udp', 'tcp', 'dot', 'doh', 'doq'):
                    raise TransportError('UNSUPPORTED_TRANSPORT', 'Unsupported endpoint transport', 'input')
                host = unquote(parsed.hostname or '')
                if not host: raise TransportError('INVALID_ENDPOINT', 'Endpoint hostname is missing', 'input')
                port = parsed.port or {'udp': 53, 'tcp': 53, 'dot': 853, 'doh': 443, 'doq': 853}[scheme]
                result['transport'] = scheme
                q = _query(name, qtype, options)
                result['query_flags'] = dns.flags.to_text(q.flags).split()
                stage = 'bootstrap'
                address = await self._address(host, endpoint, options, timeout_ms, result)
                result['peer_ip'] = address
                result['address_family'] = 'ipv6' if ':' in address else 'ipv4'
                source = options.get('source_address') or endpoint.get('source_address')
                interface = options.get('interface') or endpoint.get('interface')
                if interface:
                    try: source = interface_source(interface, address)
                    except ValueError as exc: raise TransportError('INTERFACE_ADDRESS_UNAVAILABLE', str(exc), 'input') from exc
                result.update(source_address=source, interface_scope=interface or endpoint.get('interface_scope'),
                    bind_mode='source_address' if source else 'default', route_selection='kernel_selected')
                key = (scheme, host, address, port, endpoint.get('ca_file'), endpoint.get('server_name'), source,
                       endpoint.get('interface_scope'), endpoint.get('proxy_mode', 'direct'))
                stage = 'dns'
                if scheme == 'udp':
                    response, raw = await self._udp(q, address, port, source, result)
                elif scheme in ('tcp', 'dot'):
                    stage = 'tls' if scheme == 'dot' else 'tcp'
                    response, raw = await self._stream(q, key, endpoint, result)
                elif scheme == 'doh':
                    stage = 'http'
                    response, raw = await self._doh(q, endpoint['endpoint'], key, endpoint, timeout_ms, result)
                else:
                    stage = 'quic'
                    response, raw = await self._doq(q, key, timeout_ms, result)
                result.update(_response(response, raw))
        except asyncio.CancelledError:
            raise
        except (TimeoutError, dns.exception.Timeout):
            result.update(outcome='timeout', error={'code': 'BOOTSTRAP_TIMEOUT' if stage == 'bootstrap' else 'TIMEOUT',
                'message': 'Query did not complete within the attempt deadline', 'stage': result.get('_stage', stage)})
        except TransportError as exc:
            result['error'] = {'code': exc.code, 'message': exc.message, 'stage': exc.stage, **exc.details}
        except Exception as exc:
            if _ssl_error(exc): code, stage = 'TLS_CERTIFICATE_ERROR', 'tls'
            elif isinstance(exc, ssl.SSLError): code, stage = 'TLS_ERROR', 'tls'
            elif isinstance(exc, (dns.exception.DNSException, struct.error)): code, stage = 'DNS_MALFORMED_RESPONSE', 'dns'
            elif isinstance(exc, (ConnectionError, OSError)): code = 'CONNECTION_ERROR'
            else: code = 'TRANSPORT_ERROR'
            # Do not expose HTTP bodies, credentials, remote-controlled errors or URL strings.
            result['error'] = {'code': code, 'message': f'{type(exc).__name__} during {stage}', 'stage': stage}
        finally:
            result['timing']['total_ms'] = round((time.monotonic() - started) * 1000, 3)
            self._tasks.discard(task)
            result.pop('_stage', None)
        return result

    async def _address(self, host, endpoint, options, timeout_ms, result):
        try:
            ipaddress.ip_address(host.split('%')[0])
            candidates = [host]
        except ValueError:
            candidates = endpoint.get('bootstrap_ips') or []
            if not candidates:
                start = time.monotonic()
                force = options.get('force_family')
                qtype = 'AAAA' if force in (6, 'ipv6', 'IPv6') else 'A'
                lookup = await system_lookup(host, qtype, timeout_ms)
                result['bootstrap'] = {'source': 'system', 'hostname': host, 'outcome': lookup['outcome'],
                    'wire_attempts_observable': False, 'system_api_calls': 1, 'error': lookup.get('error'),
                    'duration_ms': round((time.monotonic() - start) * 1000, 3)}
                if lookup['outcome'] != 'response':
                    raise TransportError('ENCRYPTED_BOOTSTRAP_FAILED', 'Endpoint hostname could not be resolved by native system bootstrap', 'bootstrap')
                candidates = [v for rr in lookup['answers'] for v in rr['values']]
            else: result['bootstrap'] = {'source': 'explicit', 'hostname': host, 'system_api_calls': 0}
        force = options.get('force_family')
        for address in candidates:
            family = ipaddress.ip_address(address.split('%')[0]).version
            if force in (4, 'ipv4', 'IPv4') and family != 4: continue
            if force in (6, 'ipv6', 'IPv6') and family != 6: continue
            return address
        raise TransportError('ADDRESS_FAMILY_UNAVAILABLE', 'No address matches the requested transport family', 'bootstrap')

    async def _udp(self, query, address, port, source, result):
        family = socket.AF_INET6 if ':' in address else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM); sock.setblocking(False)
        try:
            if source: sock.bind((source, 0))
            loop = asyncio.get_running_loop()
            await loop.sock_connect(sock, (address, port))
            await loop.sock_sendall(sock, query.to_wire())
            while True:
                raw = await loop.sock_recv(sock, 65535)
                try: return _parse(raw, query), raw
                except (dns.exception.DNSException, TransportError): result['ignored_packets'] += 1
        finally: sock.close()

    async def _stream(self, query, key, endpoint, result):
        scheme, host, address, port, ca_file, server_name, source, *_ = key
        async with self._locks.setdefault(key, asyncio.Lock()):
            writer = None
            try:
                stream = self._streams.get(key)
                if stream and (stream[1].is_closing() or stream[0].at_eof()):
                    self._streams.pop(key); stream[1].close(); stream = None
                if stream:
                    reader, writer = stream; result['connection_state'] = 'reused'
                else:
                    context = ssl.create_default_context(cafile=ca_file) if scheme == 'dot' else None
                    if context: context.set_alpn_protocols(['dot'])
                    start = time.monotonic()
                    reader, writer = await asyncio.open_connection(address, port, ssl=context,
                        server_hostname=(server_name or host) if context else None,
                        local_addr=(source, 0) if source else None)
                    result['timing']['connect_tls_ms' if context else 'connect_ms'] = round((time.monotonic() - start) * 1000, 3)
                    self._streams[key] = reader, writer
                result['_stage'] = 'dns'
                wire = query.to_wire(); writer.write(struct.pack('!H', len(wire)) + wire); await writer.drain()
                while True:
                    size = struct.unpack('!H', await reader.readexactly(2))[0]
                    if size < 12: raise TransportError('DNS_MALFORMED_RESPONSE', 'DNS stream frame shorter than header', 'dns')
                    raw = await reader.readexactly(size)
                    try: return _parse(raw, query), raw
                    except TransportError: result['ignored_packets'] += 1
            except BaseException:
                self._streams.pop(key, None)
                if writer: writer.close()
                raise

    async def _doh(self, query, url, key, endpoint, timeout_ms, result):
        import httpx
        client = self._http.get(key)
        if client: result['connection_state'] = 'reused'
        else:
            context = ssl.create_default_context(cafile=endpoint.get('ca_file'))
            transport_cls = dns.asyncbackend.get_backend('asyncio').get_transport_class()
            backend = transport_cls(verify=context, bootstrap_address=key[2], http1=True, http2=True,
                                    local_address=key[6], retries=0)
            client = httpx.AsyncClient(transport=backend, trust_env=False, follow_redirects=False,
                timeout=timeout_ms / 1000, limits=httpx.Limits(max_connections=4, max_keepalive_connections=4))
            self._http[key] = client
        trace_starts = {}
        async def trace(event, info):
            kind, _, phase = event.rpartition('.')
            if phase == 'started':
                trace_starts[kind] = time.monotonic()
                if kind.endswith('connect_tcp'):
                    result['connection_state'] = 'new'; result['_stage'] = 'tcp'
                elif kind.endswith('start_tls'): result['_stage'] = 'tls'
                else: result['_stage'] = 'http'
            elif phase == 'complete' and kind in trace_starts:
                result['timing'][kind.split('.')[-1] + '_ms'] = round((time.monotonic() - trace_starts[kind]) * 1000, 3)
        wire = query.to_wire()
        async with client.stream('POST', url, content=wire,
                headers={'accept': 'application/dns-message', 'content-type': 'application/dns-message'},
                timeout=timeout_ms / 1000, extensions={'trace': trace}) as response:
            result['http_status'] = response.status_code
            result['http_version'] = response.http_version
            if response.status_code != 200:
                raise TransportError('HTTP_STATUS_ERROR', 'DoH endpoint returned an unsuccessful HTTP status', 'http', status=response.status_code)
            if response.headers.get('content-type', '').split(';')[0].strip().lower() != 'application/dns-message':
                raise TransportError('HTTP_MEDIA_TYPE_ERROR', 'DoH response media type is not application/dns-message', 'http')
            if response.headers.get('content-encoding', 'identity') != 'identity':
                raise TransportError('HTTP_ENCODING_UNSUPPORTED', 'Compressed DoH response is not supported', 'http')
            raw = bytearray()
            async for chunk in response.aiter_bytes():
                raw.extend(chunk)
                if len(raw) > 65535: raise TransportError('HTTP_BODY_TOO_LARGE', 'DoH body exceeds maximum DNS message size', 'http')
            return _parse(bytes(raw), query), bytes(raw)


    async def _doq(self, query, key, timeout_ms, result):
        # dnspython's default QUIC close waits for the peer draining timer (about
        # 600 ms on a blackhole). This adapter aborts local tasks/sockets when the
        # attempt expires, while normal exchanges reuse its verified connection.
        from dns.quic._asyncio import AsyncioQuicManager, AsyncioQuicConnection

        class BoundedConnection(AsyncioQuicConnection):
            async def close(self):
                if self._closed: return
                self._closed = self._done = True
                if self._manager is not None: self._manager.closed(self._peer[0], self._peer[1])
                self._connection.close()
                tasks = [t for t in (self._receiver_task, self._sender_task) if t is not None]
                for task in tasks: task.cancel()
                if tasks: await asyncio.gather(*tasks, return_exceptions=True)
                if self._socket is not None: await self._socket.close()

        async with self._locks.setdefault(key, asyncio.Lock()):
            manager = self._quic.get(key)
            if manager: result['connection_state'] = 'reused'
            else:
                manager = AsyncioQuicManager(verify_mode=key[4] or ssl.CERT_REQUIRED, server_name=key[5] or key[1])
                manager._connection_factory = BoundedConnection
                self._quic[key] = manager
            connection = manager.connect(key[2], key[3], key[6])
            try:
                response = await dns.asyncquery.quic(query, key[2], timeout=timeout_ms / 1000,
                    port=key[3], connection=connection, server_hostname=key[5] or key[1])
                return response, response.to_wire()
            except BaseException:
                self._quic.pop(key, None)
                await connection.close()
                raise
