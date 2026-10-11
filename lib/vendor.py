"""Fetch a pinned upstream binary and verify GitHub's release asset SHA-256."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile
import urllib.request

VERSION = '1.13.7'


def download(state,arch):
    name=f'sing-box-{VERSION}-linux-{arch}'
    binary=state/'vendor'/name/'sing-box'
    receipt=state/'vendor'/(name+'.verified.json')
    if binary.exists() and receipt.exists():
        recorded=json.loads(receipt.read_text())
        if hashlib.sha256(binary.read_bytes()).hexdigest()==recorded['binary_sha256']:
            return binary
    request=urllib.request.Request('https://api.github.com/repos/SagerNet/sing-box/releases/tags/v'+VERSION,
        headers={'User-Agent':'tun-it-installer','Accept':'application/vnd.github+json'})
    with urllib.request.urlopen(request,timeout=30) as response: release=json.load(response)
    asset=next(a for a in release['assets'] if a['name']==name+'.tar.gz')
    digest=asset.get('digest') or ''
    if not digest.startswith('sha256:'): raise ValueError('Upstream SHA-256 unavailable; download refused.')
    archive=state/'vendor'/(name+'.tar.gz');archive.parent.mkdir(parents=True,exist_ok=True)
    with urllib.request.urlopen(asset['browser_download_url'],timeout=45) as response:
        data=response.read()
    if hashlib.sha256(data).hexdigest()!=digest[7:]: raise ValueError('Release SHA-256 mismatch.')
    archive.write_bytes(data)
    with tarfile.open(archive,'r:gz') as tar:
        member=tar.getmember(name+'/sing-box')
        if not member.isfile(): raise ValueError('Invalid release member.')
        binary.parent.mkdir(parents=True,exist_ok=True)
        with tar.extractfile(member) as source: binary.write_bytes(source.read())
    receipt.write_text(json.dumps({'version':VERSION,'archive_sha256':digest[7:],
        'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest()}))
    return binary


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--state',type=Path,required=True)
    parser.add_argument('--arch',choices=['amd64','arm64'],required=True);args=parser.parse_args()
    try: print(download(args.state,args.arch))
    except Exception as error: raise SystemExit(type(error).__name__+': verified dependency download failed.')
