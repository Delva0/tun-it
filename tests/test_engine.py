import base64
import importlib.util
import ipaddress
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('engine',ROOT/'lib/engine.py')
engine=importlib.util.module_from_spec(spec);spec.loader.exec_module(engine)
ID='12345678-1234-4234-8234-123456789abc'


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.home=Path(self.temp.name)
        self.state=self.home/'private';self.state.mkdir()
        (self.home/'guiConfigs').mkdir();(self.home/'binConfigs').mkdir()
        self.config={'v2rayn_home':str(self.home),'profile_id':'fixture','dns_server':'1.1.1.1',
            'android':{'enabled':True,'sdk':str(self.home/'sdk')},
            'wsl':{'enabled':True,'listen_port':18118},'process_adapters':[]}
        self.baseline={'inbounds':[{'type':'tun','tag':'tun','address':['198.18.0.1/30']}],
            'outbounds':[], 'dns':{'servers':[{'type':'local','tag':'local'}], 'rules':[{'domain':['example.org'],'server':'local'}]},
            'route':{'rules':[{'domain':['example.org'],'outbound':'proxy'}],'final':'proxy'}}
        db=sqlite3.connect(self.home/'guiConfigs/guiNDB.db')
        db.executescript('''CREATE TABLE ProfileItem (indexId TEXT PRIMARY KEY, remarks TEXT, configType INT,
            address TEXT,port INT,id TEXT,network TEXT,streamSecurity TEXT,flow TEXT,publicKey TEXT,
            shortId TEXT,fingerprint TEXT,sni TEXT,security TEXT,configVersion INT,isSub INT,displayLog INT,subid TEXT);
            CREATE TABLE FullConfigTemplateItem (Id TEXT PRIMARY KEY, CoreType INT,Enabled INT,Remarks TEXT,
            Config TEXT,TunConfig TEXT,AddProxyOnly INT,ProxyDetour TEXT);''')
        db.execute('INSERT INTO ProfileItem (indexId,remarks,configType,address,port,id,network) VALUES (?,?,?,?,?,?,?)',
            ('fixture','Example target',5,'192.0.2.10',443,ID,'tcp'))
        db.execute('INSERT INTO FullConfigTemplateItem VALUES (?,?,?,?,?,?,?,?)',
            ('template',24,0,'Original','{"untouched":true}',None,0,None))
        db.commit();db.close()
        engine.write(self.state/'config.json',self.config)
        engine.write(self.state/'native-baseline.json',self.baseline)
        engine.write(self.home/'binConfigs/configPre.json',{'outbounds':[{'type':'direct','tag':'proxy'},{'type':'direct','tag':'direct'}]})
        engine.write(self.home/'guiConfigs/guiNConfig.json',{'TunModeItem':{'EnableTun':True},'IndexId':'ordinary'})

    def tearDown(self): self.temp.cleanup()

    def build(self): return engine.build(self.config,self.state,'172.28.0.1','172.28.0.0/20')

    def test_adapters_precede_ordinary_rules_and_dns(self):
        self.build();t=engine.read(self.state/'candidate-tun.json')
        self.assertEqual(t['route']['rules'][0]['inbound'],[engine.WSL])
        self.assertEqual(t['route']['rules'][1]['outbound'],engine.TARGET)
        self.assertEqual(t['route']['rules'][-1],self.baseline['route']['rules'][0])
        self.assertEqual(t['dns']['servers'][0]['detour'],engine.TARGET)
        self.assertEqual(len(t['outbounds']),1)

    def test_adapter_removal_preserves_other_adapter_and_ordinary_profile(self):
        self.build();engine.snapshot(self.config,self.state);engine.apply(self.config,self.state)
        self.config['android']['enabled']=False;self.build()
        t=engine.read(self.state/'candidate-tun.json')
        self.assertFalse(any('process_path' in r for r in t['route']['rules']))
        self.assertTrue(any(i.get('tag')==engine.WSL for i in t['inbounds']))
        self.assertEqual(engine.read(self.home/'guiConfigs/guiNConfig.json')['IndexId'],'ordinary')
        self.config['wsl']['enabled']=False;self.config['android']['enabled']=True;self.build()
        t=engine.read(self.state/'candidate-tun.json')
        self.assertFalse(any(i.get('tag')==engine.WSL for i in t['inbounds']))
        self.assertEqual(sum('process_path' in r for r in t['route']['rules']),1)

    def test_apply_and_restore_preserve_non_tun_template(self):
        original=engine.template_row(self.config)
        self.build();engine.snapshot(self.config,self.state);engine.apply(self.config,self.state)
        self.assertEqual(engine.template_row(self.config)['Config'],original['Config'])
        self.assertEqual(engine.status(self.config,self.state)['ordinary_profile'],'ordinary')
        engine.restore(self.config,self.state)
        self.assertEqual(engine.template_row(self.config),original)

    def test_fresh_database_removal_deletes_only_owned_row(self):
        with engine.database(self.config,True) as db: db.execute('DELETE FROM FullConfigTemplateItem')
        self.build();engine.snapshot(self.config,self.state);engine.apply(self.config,self.state)
        with engine.database(self.config,True) as db:
            db.execute('INSERT INTO FullConfigTemplateItem (Id,CoreType) VALUES (?,?)',('other-core',1))
        engine.restore(self.config,self.state)
        self.assertIsNone(engine.template_row(self.config))
        with engine.database(self.config) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM FullConfigTemplateItem').fetchone()[0],1)

    def test_default_guard_blocks_physical_ipv4_and_ipv6(self):
        blocked=[ipaddress.ip_network(n) for n in engine.blocked_sources(['198.18.0.1/30'])]
        for text,expected in [('192.0.2.55',True),('fd00::1',True),('2001:db8::1',True),
                              ('198.18.0.1',False),('127.0.0.1',False),('::1',False)]:
            ip=ipaddress.ip_address(text)
            self.assertEqual(any(ip.version==n.version and ip in n for n in blocked),expected)

    def test_template_refresh_is_idempotent(self):
        self.build();first=engine.read(self.state/'candidate-tun.json')
        engine.apply(self.config,self.state);self.build()
        self.assertEqual(engine.read(self.state/'candidate-tun.json'),first)

    def test_import_creates_gui_node_without_modifying_existing_profile(self):
        engine.write(self.state/'input.json',{'uri':f'vless://{ID}@192.0.2.99:443?security=none#Imported'})
        result=engine.import_node(self.config,self.state,self.state/'input.json')
        self.assertTrue(result['profile_id'].startswith('tun-it-'))
        with engine.database(self.config) as db:
            self.assertEqual(db.execute('SELECT address FROM ProfileItem WHERE indexId="fixture"').fetchone()[0],'192.0.2.10')
        self.assertEqual(engine.node_from_gui(self.config)[0]['server'],'192.0.2.99')

    def test_public_or_unscoped_carrier_refused(self):
        for host,prefix in [('192.0.2.1','172.28.0.0/20'),('8.8.8.8','8.8.8.0/24')]:
            with self.assertRaises(ValueError): engine.build(self.config,self.state,host,prefix)

    def test_share_protocols_and_rejected_plugin(self):
        real=engine.parse_uri(f'vless://{ID}@192.0.2.10:443?security=reality&pbk=test-public-key&sid=abcd&flow=xtls-rprx-vision&sni=example.org')
        self.assertEqual(engine.profile_outbound(real)['tls']['reality']['short_id'],'abcd')
        self.assertEqual(engine.parse_uri('trojan://test-password@192.0.2.10:443')['configType'],6)
        encoded=base64.urlsafe_b64encode(b'chacha20-ietf-poly1305:test-password').decode().rstrip('=')
        self.assertEqual(engine.parse_uri(f'ss://{encoded}@192.0.2.10:443')['security'],'chacha20-ietf-poly1305')
        vm=base64.b64encode(json.dumps({'add':'192.0.2.10','port':443,'id':ID,'net':'ws','host':'example.org','path':'/socket'}).encode()).decode()
        self.assertEqual(engine.profile_outbound(engine.parse_uri('vmess://'+vm))['transport']['headers']['Host'],'example.org')
        with self.assertRaises(ValueError): engine.parse_uri(f'ss://{encoded}@192.0.2.10:443?plugin=unknown')


if __name__=='__main__': unittest.main()
