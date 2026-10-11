"""v2rayN GUI integration. Private state is kept outside the source checkout."""
import argparse
import base64
import copy
from contextlib import contextmanager
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import sqlite3
import uuid
from urllib.parse import parse_qs, unquote, urlsplit

TARGET = 'tun-it-target'
DNS = 'tun-it-dns'
WSL = 'tun-it-wsl'
CORE_TYPE = 24
TYPES = {1: 'vmess', 3: 'shadowsocks', 5: 'vless', 6: 'trojan'}


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    pending = path.with_suffix(path.suffix + '.tmp')
    pending.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding='utf-8')
    pending.replace(path)


@contextmanager
def database(config, writable=False):
    path = Path(config['v2rayn_home'])/'guiConfigs/guiNDB.db'
    if not path.exists():
        raise ValueError('v2rayN database not found. Start v2rayN once before deployment.')
    db = sqlite3.connect(str(path) if writable else path.as_uri()+'?mode=ro', uri=not writable, timeout=10)
    db.row_factory = sqlite3.Row
    try:
        with db:
            for table, required in {'ProfileItem': {'indexId','configType','address','port','id'},
                    'FullConfigTemplateItem': {'Id','CoreType','Enabled','Config','TunConfig','AddProxyOnly','ProxyDetour'}}.items():
                names = {r['name'] for r in db.execute('PRAGMA table_info('+table+')')}
                if not required <= names:
                    raise ValueError('Unsupported v2rayN database schema; nothing was written.')
            yield db
    finally:
        db.close()


def template_row(config):
    with database(config) as db:
        rows = db.execute('SELECT * FROM FullConfigTemplateItem WHERE CoreType=?',(CORE_TYPE,)).fetchall()
        if len(rows) > 1:
            raise ValueError('Multiple sing-box templates found; choose one in v2rayN first.')
        return dict(rows[0]) if rows else None


def decode64(text):
    return base64.urlsafe_b64decode(text+'='*(-len(text)%4)).decode()


def parse_uri(text):
    """Return only normalized GUI fields; never log a share URI."""
    if text.startswith('vmess://'):
        data = json.loads(decode64(text[8:]))
        fields = {'configType':1, 'address':data['add'], 'port':int(data['port']), 'id':data['id'],
            'alterId':int(data.get('aid') or 0), 'security':data.get('scy') or 'auto',
            'network':data.get('net') or 'tcp', 'streamSecurity':'tls' if data.get('tls') == 'tls' else '',
            'sni':data.get('sni') or data.get('host') or '', 'requestHost':data.get('host') or '',
            'path':data.get('path') or '', 'remarks':data.get('ps') or 'tun-it target'}
    else:
        url = urlsplit(text.strip())
        query = {k:v[-1] for k,v in parse_qs(url.query).items()}
        if url.scheme not in ('vless','trojan','ss') or not url.hostname or not url.port:
            raise ValueError('Use a VLESS, VMess, Trojan or SIP002 Shadowsocks share URI.')
        fields = {'address':url.hostname, 'port':url.port, 'remarks':unquote(url.fragment) or 'tun-it target',
            'network':query.get('type','tcp'), 'streamSecurity':query.get('security','tls' if url.scheme=='trojan' else ''),
            'sni':query.get('sni') or query.get('peer') or url.hostname,
            'flow':query.get('flow',''), 'fingerprint':query.get('fp','chrome'),
            'publicKey':query.get('pbk',''), 'shortId':query.get('sid',''),
            'requestHost':query.get('host',''), 'path':query.get('path') or query.get('serviceName',''),
            'alpn':query.get('alpn','')}
        if fields['streamSecurity']=='none': fields['streamSecurity']=''
        if url.scheme == 'ss':
            if query.get('plugin'):
                raise ValueError('Shadowsocks plugins are not supported by this importer.')
            credentials = unquote(url.username or '')
            if url.password is not None:
                method,password = credentials,unquote(url.password)
            else:
                method,password = decode64(credentials).split(':',1)
            fields.update(configType=3, security=method, id=password, network='tcp', streamSecurity='')
        else:
            fields.update(configType=5 if url.scheme=='vless' else 6, id=unquote(url.username or ''))
    fields.update(configVersion=2, subid='', isSub=0, coreType=None, displayLog=1)
    profile_outbound(fields)
    return fields


def profile_outbound(profile):
    kind = TYPES.get(profile.get('configType'))
    if not kind:
        raise ValueError('Supported GUI profiles: VLESS, VMess, Trojan, Shadowsocks.')
    network = profile.get('network') or 'tcp'
    if network not in ('tcp','raw','ws','grpc','httpupgrade'):
        raise ValueError('Supported transports: TCP/raw, WebSocket, gRPC, HTTPUpgrade.')
    if not profile.get('address') or not 0 < int(profile.get('port') or 0) < 65536:
        raise ValueError('Server address and port are required.')
    node = {'type':kind,'tag':TARGET,'server':profile['address'],'server_port':int(profile['port'])}
    if kind in ('vless','vmess'):
        uuid.UUID(profile['id']); node['uuid']=profile['id']
    if kind == 'vless' and profile.get('flow'):
        node['flow']=profile['flow']
    if kind == 'vmess':
        node.update(security=profile.get('security') or 'auto',alter_id=int(profile.get('alterId') or 0))
    if kind == 'trojan': node['password']=profile['id']
    if kind == 'shadowsocks':
        if network not in ('tcp','raw'):
            raise ValueError('Shadowsocks transport plugins are not supported.')
        node.update(method=profile['security'],password=profile['id'])
    security = profile.get('streamSecurity')
    if security:
        if security not in ('tls','reality'):
            raise ValueError('Unsupported TLS security mode.')
        tls = {'enabled':True,'server_name':profile.get('sni') or profile['address']}
        if str(profile.get('allowInsecure','')).lower() == 'true': tls['insecure']=True
        if profile.get('alpn'): tls['alpn']=profile['alpn'].split(',')
        if profile.get('fingerprint') or security == 'reality':
            tls['utls']={'enabled':True,'fingerprint':profile.get('fingerprint') or 'chrome'}
        if security == 'reality':
            if kind != 'vless' or not profile.get('publicKey'):
                raise ValueError('REALITY requires VLESS and a public key.')
            tls['reality']={'enabled':True,'public_key':profile['publicKey'],'short_id':profile.get('shortId') or ''}
        node['tls']=tls
    if network in ('ws','httpupgrade'):
        transport={'type':network,'path':profile.get('path') or '/'}
        if profile.get('requestHost'):
            if network == 'ws': transport['headers']={'Host':profile['requestHost']}
            else: transport['host']=profile['requestHost']
        node['transport']=transport
    elif network == 'grpc':
        node['transport']={'type':'grpc','service_name':profile.get('path') or ''}
    return node


def node_from_gui(config):
    with database(config) as db:
        row=db.execute('SELECT * FROM ProfileItem WHERE indexId=?',(config['profile_id'],)).fetchone()
        if row is None: raise ValueError('Configured target GUI profile is missing.')
        return profile_outbound(dict(row)),row['remarks']


def profiles(config):
    with database(config) as db:
        return [dict(r) for r in db.execute('SELECT indexId,remarks,configType FROM ProfileItem WHERE configType IN (1,3,5,6)')]


def import_node(config, state, input_path):
    fields=parse_uri(read(input_path)['uri'])
    fields['indexId']='tun-it-'+uuid.uuid4().hex
    with database(config,True) as db:
        names={r['name'] for r in db.execute('PRAGMA table_info(ProfileItem)')}
        fields={k:v for k,v in fields.items() if k in names}
        keys=list(fields)
        db.execute('INSERT INTO ProfileItem ('+','.join('"'+k+'"' for k in keys)+') VALUES ('+','.join('?' for _ in keys)+')',list(fields.values()))
    config['profile_id']=fields['indexId']
    config['owned_profile_ids']=[*config.get('owned_profile_ids',[]),fields['indexId']]
    write(state/'config.json',config)
    return {'profile_id':fields['indexId'],'name':fields['remarks']}


def blocked_sources(allowed):
    result=[]
    for version,whole,loopback in ((4,'0.0.0.0/0','127.0.0.0/8'),(6,'::/0','::1/128')):
        networks=[ipaddress.ip_network(whole)]
        excluded=[ipaddress.ip_network(loopback)]+[ipaddress.ip_network(n,strict=False) for n in allowed if ipaddress.ip_network(n,strict=False).version==version]
        if version==6: excluded.append(ipaddress.ip_network('::/128'))
        for permitted in excluded:
            updated=[]
            for network in networks:
                if permitted.subnet_of(network): updated.extend(network.address_exclude(permitted))
                elif not network.subnet_of(permitted): updated.append(network)
            networks=updated
        result.extend(str(n) for n in networks)
    return result


def process_entries(config):
    entries=[]
    android=config.get('android',{})
    if android.get('enabled'):
        sdk=Path(android['sdk'])
        entries.append({'id':'android','executables':[str(sdk/'emulator/qemu/windows-x86_64/qemu-system-x86_64.exe'),
            str(sdk/'emulator/netsimd.exe'),str(sdk/'emulator/emulator.exe')]})
    for entry in config.get('process_adapters',[]):
        if entry.get('enabled',True):
            if not entry.get('id') or not entry.get('executables'):
                raise ValueError('Process adapters need an id and executable paths.')
            entries.append(entry)
    ids=[entry['id'] for entry in entries]
    if len(ids)!=len(set(ids)) or any(not all(c.isalnum() or c in '_-' for c in i) for i in ids):
        raise ValueError('Process adapter ids must be unique letters, numbers, underscores or hyphens.')
    return entries


def owned(config):
    migration=config.get('migration',{})
    return ({TARGET,*migration.get('outbounds',[])},{DNS,*migration.get('dns',[])},{WSL,*migration.get('inbounds',[])})


def clean_template(template,config):
    template=copy.deepcopy(template)
    out,dns,ins=owned(config)
    template['outbounds']=[o for o in template.get('outbounds',[]) if o.get('tag') not in out]
    template['inbounds']=[i for i in template.get('inbounds',[]) if i.get('tag') not in ins|{'tun-protect-ss'}]
    template.setdefault('route',{})['rules']=[r for r in template.get('route',{}).get('rules',[])
        if r.get('outbound') not in out and not set(r.get('inbound',[])) & (ins|{'tun-protect-ss'})]
    template.setdefault('dns',{})['servers']=[s for s in template.get('dns',{}).get('servers',[]) if s.get('tag') not in dns]
    template['dns']['rules']=[r for r in template['dns'].get('rules',[]) if r.get('server') not in dns]
    return template


def capture_baseline(config,state):
    path=Path(config['v2rayn_home'])/'binConfigs/configPre.json'
    data=read(path)
    if not any(i.get('type')=='tun' for i in data.get('inbounds',[])):
        raise ValueError('No generated sing-box TUN baseline. Enable v2rayN TUN first.')
    data=clean_template(data,config)
    # v2rayN appends all dynamic ordinary outbounds/endpoints when it applies a template.
    data['outbounds']=[]
    data.pop('endpoints',None)
    write(state/'native-baseline.json',data)
    return {'baseline_captured':True}


def base_template(config,state):
    row=template_row(config)
    if row and row.get('Enabled') and row.get('TunConfig'):
        return clean_template(json.loads(row['TunConfig']),config)
    if (state/'native-baseline.json').exists():
        return read(state/'native-baseline.json')
    capture_baseline(config,state)
    return read(state/'native-baseline.json')


def build(config,state,host=None,prefix=None):
    template=base_template(config,state)
    node,label=node_from_gui(config)
    template['outbounds'].append(node)
    dns_server=config.get('dns_server','1.1.1.1')
    ipaddress.ip_address(dns_server)
    template['dns']['servers'].insert(0,{'type':'https','tag':DNS,'server':dns_server,'path':'/dns-query','detour':TARGET})
    routes=[]; dns_rules=[]
    entries=process_entries(config)
    for entry in entries:
        paths=entry['executables']
        routes.append({'process_path':paths,'outbound':TARGET})
        dns_rules.append({'process_path':paths,'server':DNS,'strategy':'ipv4_only'})
    wsl=config.get('wsl',{})
    if wsl.get('enabled'):
        if not host or not prefix:
            raise ValueError('WSL2 NAT host adapter missing. Disable the WSL adapter or configure NAT networking.')
        address=ipaddress.ip_address(host); network=ipaddress.ip_network(prefix)
        if not address.is_private or address not in network:
            raise ValueError('WSL entry must be scoped to the verified private host interface.')
        auth_path=state/'carrier-auth.json'
        if not auth_path.exists(): write(auth_path,{'password':secrets.token_hex(32)})
        password=read(auth_path)['password']
        # Wildcard bind keeps ordinary Windows TUN working when WSL has not started yet.
        # Windows guards explicitly block every non-WSL local address and remote subnet.
        template['inbounds'].append({'type':'shadowsocks','tag':WSL,'listen':'0.0.0.0','listen_port':wsl['listen_port'],
            'method':'chacha20-ietf-poly1305','password':password})
        routes.insert(0,{'inbound':[WSL],'outbound':TARGET})
        dns_rules.insert(0,{'inbound':[WSL],'server':DNS,'strategy':'ipv4_only'})
        write(state/'wsl-runtime-base.json',{'gateway':host,'port':wsl['listen_port'],'password':password,
            'expected_exit':config.get('expected_exit') or '', 'dns_server':dns_server})
        write(state/'wsl-block-local.json',blocked_sources([host+'/32']))
        write(state/'wsl-block-remote.json',blocked_sources([prefix]))
    template['route']['rules']=routes+template['route']['rules']
    template['dns']['rules']=dns_rules+template['dns']['rules']
    tun=[i for i in template['inbounds'] if i.get('type')=='tun']
    if len(tun)!=1: raise ValueError('Exactly one Windows TUN inbound is required.')
    addresses=tun[0].get('address') or tun[0].get('inet4_address') or []
    if isinstance(addresses,str): addresses=[addresses]
    if not addresses: raise ValueError('TUN interface addresses could not be identified.')
    write(state/'blocked-sources.json',blocked_sources(addresses))
    write(state/'process-entries.json',entries)
    write(state/'candidate-tun.json',template)
    validation=copy.deepcopy(template)
    live=Path(config['v2rayn_home'])/'binConfigs/configPre.json'
    dynamic=read(live).get('outbounds',[]) if live.exists() else [{'type':'direct','tag':'proxy'},{'type':'direct','tag':'direct'}]
    tags={o['tag'] for o in validation['outbounds']}; outs,_,_=owned(config)
    validation['outbounds'] += [o for o in dynamic if o.get('tag') not in tags|outs]
    write(state/'validation.json',validation)
    write(state/'node-probe.json',{'log':{'level':'error'},'inbounds':[{'type':'socks','tag':'probe','listen':'127.0.0.1','listen_port':19088}],
        'outbounds':[node],'route':{'final':TARGET}})
    plan={'profile_id':config['profile_id'],'profile_name':label,'adapters':{'android':config.get('android',{}).get('enabled',False),
        'wsl':wsl.get('enabled',False),'processes':[e['id'] for e in entries]},'gateway':host,
        'revision':hashlib.sha256(json.dumps(node,sort_keys=True).encode()).hexdigest()[:16]}
    write(state/'plan.json',plan)
    return plan


def snapshot(config,state):
    row=template_row(config)
    write(state/'before-sync-template.json',row)
    if not (state/'original-template.json').exists(): write(state/'original-template.json',row)
    return {'template_saved':True}


def apply(config,state):
    candidate=(state/'candidate-tun.json').read_text(encoding='utf-8')
    row=template_row(config)
    with database(config,True) as db:
        if row:
            db.execute('UPDATE FullConfigTemplateItem SET Enabled=1,Remarks=?,TunConfig=?,AddProxyOnly=0,ProxyDetour=NULL WHERE Id=?',('tun-it',candidate,row['Id']))
        else:
            row={'Id':'tun-it-'+uuid.uuid4().hex}
            db.execute('INSERT INTO FullConfigTemplateItem (Id,CoreType,Enabled,Remarks,TunConfig,AddProxyOnly) VALUES (?,?,1,?,?,0)',(row['Id'],CORE_TYPE,'tun-it',candidate))
    write(state/'owned-template-id.json',row['Id'])
    write(state/'applied-plan.json',read(state/'plan.json'))
    return {'synchronized':True}


def restore(config,state,path=None):
    row=read(path or state/'original-template.json')
    with database(config,True) as db:
        if row is None:
            owned_path=state/'owned-template-id.json'
            if owned_path.exists(): db.execute('DELETE FROM FullConfigTemplateItem WHERE Id=?',(read(owned_path),))
        else:
            keys=[k for k in row if k!='Id']
            result=db.execute('UPDATE FullConfigTemplateItem SET '+','.join('"'+k+'"=?' for k in keys)+' WHERE Id=?',[row[k] for k in keys]+[row['Id']])
            if result.rowcount!=1: raise ValueError('Original template row is missing; protection was retained.')
    return {'restored':True}


def status(config,state):
    row=template_row(config); template=json.loads(row['TunConfig']) if row and row.get('TunConfig') else {}
    node,label=node_from_gui(config)
    current=next((o for o in template.get('outbounds',[]) if o.get('tag')==TARGET),None)
    gui=read(Path(config['v2rayn_home'])/'guiConfigs/guiNConfig.json')
    return {'profile_name':label,'node_synced':current==node,'tun_enabled':gui['TunModeItem']['EnableTun'],
        'ordinary_profile':gui.get('IndexId'),'adapters':{'android':config.get('android',{}).get('enabled',False),
        'wsl':config.get('wsl',{}).get('enabled',False),'processes':[e['id'] for e in process_entries(config)]}}


def main():
    parser=argparse.ArgumentParser(description='tun-it v2rayN configuration engine')
    parser.add_argument('action',choices=['profiles','import-node','capture','build','snapshot','apply','restore','status'])
    parser.add_argument('--state',required=True,type=Path)
    parser.add_argument('--input');parser.add_argument('--snapshot');parser.add_argument('--host');parser.add_argument('--prefix')
    args=parser.parse_args(); config=read(args.state/'config.json')
    if args.action=='profiles': result=profiles(config)
    elif args.action=='import-node': result=import_node(config,args.state,args.input)
    elif args.action=='capture': result=capture_baseline(config,args.state)
    elif args.action=='build': result=build(config,args.state,args.host,args.prefix)
    elif args.action=='snapshot': result=snapshot(config,args.state)
    elif args.action=='apply': result=apply(config,args.state)
    elif args.action=='restore': result=restore(config,args.state,args.snapshot)
    else: result=status(config,args.state)
    print(json.dumps(result,ensure_ascii=False))


if __name__=='__main__':
    try: main()
    except Exception as error:
        # Sanitized errors: avoid logging supplied URIs/credentials or complete configs.
        if isinstance(error,ValueError) and str(error).startswith(('Use ','Supported ','Unsupported ','Server ','REALITY ','Shadowsocks ','WSL','TUN','Exactly','No ','Multiple','Configured','Original','v2rayN')):
            raise SystemExit(str(error))
        raise SystemExit(type(error).__name__+': operation failed; private diagnostics/config remain local.')
