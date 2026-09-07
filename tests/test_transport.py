"""Local transport/discovery contract tests; no public network dependence."""
import asyncio
import ipaddress
import json
import socket
import struct
import time

import pytest


def transport_api():
    from dnsprobe.transport import Transport
    return Transport


@pytest.mark.asyncio
async def test_dns_wire_contract():
    Transport = transport_api()
    import dns.message
    import dns.rrset
    import dns.edns
    import dns.rcode
    import dns.flags
    class Server(asyncio.DatagramProtocol):
        def connection_made(self, transport): self.transport = transport
        def datagram_received(self, data, addr):
            q = dns.message.from_wire(data)
            r = dns.message.make_response(q)
            wrong = dns.message.make_response(q); wrong.id ^= 1
            self.transport.sendto(wrong.to_wire(), addr)
            self.transport.sendto(b'bad', addr)
            missing_question = dns.message.make_response(q); missing_question.question.clear(); missing_question.set_rcode(dns.rcode.SERVFAIL)
            self.transport.sendto(missing_question.to_wire(), addr)
            if q.question[0].name.to_text() == 'negative.test.':
                r.set_rcode(dns.rcode.NXDOMAIN)
            else:
                r.answer.append(dns.rrset.from_text('example.test.', 60, 'IN', 'AAAA', '2001:db8::1'))
            r.authority.append(dns.rrset.from_text('test.', 60, 'IN', 'SOA', 'ns.test. hostmaster.test. 1 2 3 4 5'))
            r.use_edns(options=[dns.edns.EDEOption(15, 'blocked')])
            self.transport.sendto(r.to_wire(), addr)
    loop = asyncio.get_running_loop()
    server, _ = await loop.create_datagram_endpoint(Server, local_addr=('127.0.0.1', 0))
    endpoint = {'endpoint': f'udp://127.0.0.1:{server.get_extra_info("sockname")[1]}'}
    try:
        async with Transport() as transport:
            for name, rcode in [('example.test', 'NOERROR'), ('negative.test', 'NXDOMAIN')]:
                result = await transport.exchange(endpoint, name, 'AAAA', 500)
                assert result['outcome'] == 'response', result
                assert result['rcode'] == rcode
                assert result['authority'][0]['type'] == 'SOA'
                assert result['ede'][0] == {'code': 15, 'text': 'blocked'}
                assert result['ignored_packets'] == 3
                if rcode == 'NOERROR': assert result['answers'][0]['values'] == ['2001:db8::1']
            loopback = next(name for _,name in socket.if_nameindex() if name in ('lo', 'lo0'))
            bound = await transport.exchange(endpoint, 'example.test', 'AAAA', 500, {'interface': loopback})
            assert bound['outcome'] == 'response', bound
            assert bound['bind_mode'] == 'source_address'
            assert bound['source_address'] == '127.0.0.1'
            assert bound['interface_scope'] == loopback
            native = await transport.exchange({'endpoint': 'system'}, 'localhost', 'A', 500, {'interface': loopback})
            assert native['error']['code'] == 'SYSTEM_INTERFACE_UNSUPPORTED'
            mismatch = await transport.exchange(endpoint, 'example.test', 'A', 500, {'force_family': 'ipv6'})
            assert mismatch['error']['code'] == 'ADDRESS_FAMILY_UNAVAILABLE'
    finally: server.close()


@pytest.mark.asyncio
async def test_tcp_truncation_and_deadline():
    Transport = transport_api()
    import dns.message
    import dns.flags
    connections = []
    async def handler(reader, writer):
        connections.append(writer)
        try:
            while True:
                size = struct.unpack('!H', await reader.readexactly(2))[0]
                q = dns.message.from_wire(await reader.readexactly(size))
                if q.question[0].name.to_text() == 'blackhole.test.':
                    await reader.read(); return
                r = dns.message.make_response(q); r.flags |= dns.flags.TC
                wire = r.to_wire(); writer.write(struct.pack('!H', len(wire)) + wire); await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError): pass
        finally: writer.close()
    server = await asyncio.start_server(handler, '127.0.0.1', 0)
    endpoint = {'endpoint': f'tcp://127.0.0.1:{server.sockets[0].getsockname()[1]}'}
    try:
        async with Transport() as transport:
            first = await transport.exchange(endpoint, 'example.test', 'A', 500)
            second = await transport.exchange(endpoint, 'example.test', 'A', 500)
            assert 'TC' in first['flags']
            assert second['connection_state'] == 'reused'
            start = time.monotonic()
            timeout = await transport.exchange(endpoint, 'blackhole.test', 'A', 60)
            assert timeout['outcome'] == 'timeout'
            assert time.monotonic() - start < .25
        await asyncio.sleep(.01)
    finally:
        server.close(); await server.wait_closed()
        for writer in connections: writer.close()


@pytest.mark.asyncio
async def test_native_system_and_discovery_scope():
    from dnsprobe.discovery import system_lookup, parse_scutil_dns, parse_resolv_conf, parse_windows_dns
    result = await system_lookup('localhost', 'A', 1000)
    assert result['outcome'] == 'response', result
    assert '127.0.0.1' in [v for rr in result['answers'] for v in rr['values']]
    assert result['rcode'] is None
    assert result['wire_attempts_observable'] is False
    assert result['address_family'] is None
    assert result['answer_address_family'] == 'ipv4'
    started = time.monotonic()
    short = await system_lookup('localhost', 'A', 0)
    assert short['outcome'] == 'timeout'
    assert time.monotonic() - started < .2
    scoped = parse_scutil_dns('''DNS configuration
resolver #1
  nameserver[0] : 1.1.1.1
  flags : Request A records
resolver #2
  domain : corp.example
  nameserver[0] : fe80::1
  if_index : 12 (utun4)
  flags : Supplemental, Request A records
DNS configuration (for scoped queries)
resolver #1
  nameserver[0] : 192.0.2.1
  if_index : 6 (en0)
''')
    assert len(scoped['system_resolvers']) == 3
    assert scoped['system_resolvers'][1]['interface_scope'] == 'utun4'
    assert scoped['system_resolvers'][1]['routing_domains'] == ['corp.example']
    assert '%utun4' in scoped['system_resolvers'][1]['endpoint']
    assert scoped['private_domains'] == ['corp.example']
    resolv = parse_resolv_conf('nameserver 127.0.0.53\nsearch corp.example local\n')
    assert resolv['private_domains'] == ['corp.example', 'local']
    windows = parse_windows_dns({'servers': [{'InterfaceIndex': 8, 'InterfaceAlias': 'VPN', 'ServerAddresses': ['10.0.0.1']}], 'nrpt': [{'Namespace': ['.corp.example'], 'NameServers': '10.0.0.2'}]})
    assert windows['private_domains'] == ['corp.example']
    assert len(windows['system_resolvers']) == 2


@pytest.mark.asyncio
async def test_encrypted_paths(tmp_path):
    """Certificate trust/identity, HTTP semantics, reuse and QUIC use real local TLS."""
    Transport = transport_api()
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime
    import ssl
    import dns.message
    from aioquic.asyncio import serve
    from aioquic.quic.configuration import QuicConfiguration
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256()))
    certfile = tmp_path / 'cert.pem'; keyfile = tmp_path / 'key.pem'
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(certfile, keyfile)
    async def handler(reader, writer, http=False, quic=False):
        try:
            while True:
                if http:
                    headers = await reader.readuntil(b'\r\n\r\n')
                    size = int(next(line.split(b':', 1)[1] for line in headers.split(b'\r\n') if line.lower().startswith(b'content-length:')))
                    wire = await reader.readexactly(size)
                else:
                    wire = await reader.readexactly(struct.unpack('!H', await reader.readexactly(2))[0])
                q = dns.message.from_wire(wire); target = q.question[0].name.to_text()
                if target == 'blackhole.test.':
                    if quic: await asyncio.Event().wait()
                    else: await reader.read()
                    return
                body = dns.message.make_response(q).to_wire()
                if http:
                    status = b'503 Service Unavailable' if target == 'status.test.' else b'200 OK'
                    media = b'text/html' if target == 'media.test.' else b'application/dns-message'
                    if target == 'close.test.': media += b'\r\nConnection: close'
                    writer.write(b'HTTP/1.1 ' + status + b'\r\nContent-Type: ' + media + b'\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)
                else: writer.write(struct.pack('!H', len(body)) + body)
                await writer.drain()
                if target == 'close.test.': return
        except (asyncio.IncompleteReadError, ConnectionError): pass
        finally: writer.close()
    dot = await asyncio.start_server(handler, '127.0.0.1', 0, ssl=context)
    doh = await asyncio.start_server(lambda r,w: handler(r,w,True), '127.0.0.1', 0, ssl=context)
    configuration = QuicConfiguration(is_client=False, alpn_protocols=['doq'])
    configuration.load_cert_chain(str(certfile), str(keyfile))
    quic_tasks = set()
    def quic_handler(reader, writer):
        task = asyncio.create_task(handler(reader, writer, quic=True)); quic_tasks.add(task); task.add_done_callback(quic_tasks.discard)
    doq = await serve('127.0.0.1', 0, configuration=configuration, stream_handler=quic_handler)
    # aioquic exposes no public local-address accessor on QuicServer.
    quic_port = doq._transport.get_extra_info('sockname')[1]
    try:
        async with Transport() as transport:
            for protocol, port in [('tls', dot.sockets[0].getsockname()[1]), ('https', doh.sockets[0].getsockname()[1]), ('quic', quic_port)]:
                endpoint = {'endpoint': f'{protocol}://localhost:{port}' + ('/dns-query' if protocol == 'https' else ''),
                    'bootstrap_ips': ['127.0.0.1'], 'ca_file': str(certfile)}
                good = await transport.exchange(endpoint, 'example.test', 'A', 1000)
                assert good['outcome'] == 'response', good
                if protocol != 'quic':
                    again = await transport.exchange(endpoint, 'example.test', 'A', 1000)
                    assert again['connection_state'] == 'reused', again
                    bad_trust = await transport.exchange({**endpoint, 'ca_file': None}, 'example.test', 'A', 500)
                    assert bad_trust['error']['code'] == 'TLS_CERTIFICATE_ERROR', bad_trust
                    bad_name = await transport.exchange({**endpoint, 'endpoint': endpoint['endpoint'].replace('localhost', 'wrong.test')}, 'example.test', 'A', 500)
                    assert bad_name['error']['code'] == 'TLS_CERTIFICATE_ERROR', bad_name
                if protocol == 'quic':
                    started = time.monotonic()
                    timeout = await transport.exchange(endpoint, 'blackhole.test', 'A', 50)
                    assert timeout['outcome'] == 'timeout', timeout
                    assert time.monotonic() - started < .25
                if protocol == 'https':
                    for target, code in [('status.test', 'HTTP_STATUS_ERROR'), ('media.test', 'HTTP_MEDIA_TYPE_ERROR')]:
                        result = await transport.exchange(endpoint, target, 'A', 500)
                        assert result['error']['code'] == code, result
                if protocol == 'https':
                    await transport.exchange(endpoint, 'close.test', 'A', 500)
                    reopened = await transport.exchange(endpoint, 'example.test', 'A', 500)
                    assert reopened['connection_state'] == 'new', reopened
                if protocol == 'tls':
                    result = await transport.exchange(endpoint, 'blackhole.test', 'A', 50)
                    assert result['outcome'] == 'timeout'
                    assert result['error']['stage'] == 'dns', result
    finally:
        dot.close(); doh.close(); doq.close()
        await dot.wait_closed(); await doh.wait_closed()
        for task in list(quic_tasks): task.cancel()
        if quic_tasks: await asyncio.gather(*quic_tasks, return_exceptions=True)


@pytest.mark.asyncio
async def test_cancel_blackhole_handshake_and_native_helper(tmp_path, monkeypatch):
    Transport = transport_api()
    from dnsprobe import discovery
    import os
    class Sink(asyncio.DatagramProtocol): pass
    server, _ = await asyncio.get_running_loop().create_datagram_endpoint(Sink, local_addr=('127.0.0.1', 0))
    try:
        async with Transport() as transport:
            for scheme in ('udp', 'quic'):
                started = time.monotonic()
                result = await transport.exchange({'endpoint': f'{scheme}://127.0.0.1:{server.get_extra_info("sockname")[1]}'}, 'test.', 'A', 40)
                assert result['outcome'] == 'timeout', result
                assert time.monotonic() - started < .25
    finally: server.close()
    marker = tmp_path / 'pid'
    monkeypatch.setattr(discovery, '_LOOKUP', f'import os,time,pathlib; pathlib.Path({str(marker)!r}).write_text(str(os.getpid())); time.sleep(30)')
    async with Transport() as transport:
        task = asyncio.create_task(transport.exchange({'endpoint': 'system'}, 'localhost', 'A', 10000))
        for _ in range(100):
            if marker.exists(): break
            await asyncio.sleep(.005)
        assert marker.exists()
        await transport.close()
        assert task.done()
    with pytest.raises(ProcessLookupError): os.kill(int(marker.read_text()), 0)
