#!/usr/bin/python3 -I
"""Bounded native TCP, UDP STUN, DNS and IPv6 probes; no proxy environment."""
import concurrent.futures
import json
import os
import secrets
import socket
import struct
import sys
import time
import urllib.request


def tcp():
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open('https://api.ipify.org/', timeout=7) as response:
        return response.read(80).decode().strip()


def udp():
    transaction = secrets.token_bytes(12)
    request = struct.pack('!HHI',1,0,0x2112A442)+transaction
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
        sock.settimeout(5); sock.sendto(request,('74.125.250.129',19302))
        data,_ = sock.recvfrom(2048)
    if data[8:20] != transaction: raise ValueError('STUN transaction mismatch')
    offset = 20
    while offset+4 <= len(data):
        kind,length = struct.unpack('!HH',data[offset:offset+4]); value=data[offset+4:offset+4+length]
        if kind in (1,0x20) and length >= 8 and value[1] == 1:
            address=value[4:8]
            if kind == 0x20: address=bytes(a^b for a,b in zip(address,bytes.fromhex('2112a442')))
            return socket.inet_ntoa(address)
        offset += 4+(length+3)//4*4
    raise ValueError('No IPv4 mapped address in STUN')


def dns():
    packet = secrets.token_bytes(2)+bytes.fromhex('01000001000000000000')+b'\x06google\x03com\x00\x00\x01\x00\x01'
    for attempt in range(2):
        try:
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
                sock.settimeout(5); sock.sendto(packet,('1.1.1.1',53)); data,_=sock.recvfrom(2048)
            break
        except socket.timeout:
            if attempt: raise
    if data[:2] != packet[:2] or data[3]&15 or int.from_bytes(data[6:8],'big') == 0:
        raise ValueError('DNS resolution failed')
    return 'resolved'


def ipv6():
    with socket.socket(socket.AF_INET6,socket.SOCK_STREAM) as sock:
        sock.settimeout(3); sock.connect(('2606:4700:4700::1111',443))
    return 'connected'


def probe(function):
    try: return function()
    except Exception: return 'blocked'


if __name__ == '__main__':
    expected,mode = sys.argv[1:]
    if mode == 'preflight':
        result=probe(tcp)
        sys.exit(0 if result!='blocked' and (not expected or result==expected) else 1)
    names = {'tcp_exit':tcp,'udp_exit':udp,'dns':dns,'ipv6':ipv6}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = {name:pool.submit(probe,fn) for name,fn in names.items()}
        results = {name:future.result() for name,future in futures.items()}
    results['proxy_env_present'] = any(os.environ.get(k) for k in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy'))
    if mode == 'failure':
        success = all(results[n] == 'blocked' for n in names)
    else:
        success = results['tcp_exit'] != 'blocked' and results['udp_exit'] == results['tcp_exit'] and (not expected or results['tcp_exit'] == expected) and results['dns'] == 'resolved' and results['ipv6'] == 'blocked'
    success = success and not results['proxy_env_present']
    print(json.dumps({'mode':mode,'success':success,**results}))
    sys.exit(0 if success else 1)
