"""Capture producer tests use synthetic executables and never run dudect."""
from datetime import datetime, timezone
import hashlib
import io
import subprocess
from types import SimpleNamespace
from unittest.mock import patch
import json
from pathlib import Path
import tempfile
import unittest

from v115_capture import (canonical, source_inventory, normalized_resolution,
                          build_environment, authorize_pass, record_pass, seal, IDENTITY_FILES, digest)


def metadata(root):
    return {'packages':[{'id':'local','name':'core','version':'1.0','source':None,'manifest_path':str(root/'crates/core/Cargo.toml')},
                        {'id':'reg','name':'dep','version':'2.0','source':'registry+test','manifest_path':'/registry/dep/Cargo.toml'}],
            'workspace_members':['local'], 'resolve':{'nodes':[
                {'id':'local','features':['b','a'],'deps':[{'name':'dep','pkg':'reg','dep_kinds':[{'kind':None,'target':None}]}]},
                {'id':'reg','features':[],'deps':[]} ]}}


class SnapshotTests(unittest.TestCase):
    def test_canonical_json_and_resolution_ignore_checkout_locations(self):
        self.assertEqual(canonical({'z':1,'a':2}),b'{\n  "a": 2,\n  "z": 1\n}\n')
        a=Path('/synthetic/one');b=Path('/synthetic/two')
        self.assertEqual(normalized_resolution(metadata(a),a),normalized_resolution(metadata(b),b))
        m=metadata(a);m['resolve']['nodes'][0]['features'].append('changed')
        self.assertNotEqual(normalized_resolution(m,a),normalized_resolution(metadata(a),a))
        m=metadata(a);m['packages'][1]['version']='3.0'
        self.assertNotEqual(normalized_resolution(m,a),normalized_resolution(metadata(a),a))

    def test_unexpected_external_path_dependency_refused(self):
        m=metadata(Path('/synthetic'));m['packages'][1]['source']=None
        with self.assertRaises(ValueError):normalized_resolution(m,Path('/synthetic'))

    def test_full_source_inventory_catches_added_changed_and_symlinked_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'crates/core/src').mkdir(parents=True)
            (root/'Cargo.toml').write_text('manifest');(root/'rust-toolchain.toml').write_text('pin')
            path=root/'crates/core/src/lib.rs';path.write_text('base')
            first=source_inventory(root);path.write_text('change')
            self.assertNotEqual(first,source_inventory(root))
            path.write_text('base');extra=root/'crates/core/src/added.rs';extra.write_text('added')
            self.assertNotEqual(first,source_inventory(root))
            extra.unlink();extra.symlink_to(path)
            with self.assertRaises(ValueError):source_inventory(root)

    def test_environment_pin_and_unfrozen_build_overrides_refused(self):
        self.assertEqual(build_environment({'RUSTUP_TOOLCHAIN':'1.95.0','CARGO_TERM_COLOR':'always'})['toolchain'],'1.95.0')
        for env in ({}, {'RUSTUP_TOOLCHAIN':'stable'}, {'RUSTUP_TOOLCHAIN':'1.95.0','RUSTFLAGS':'-C target-cpu=native'},
                    {'RUSTUP_TOOLCHAIN':'1.95.0','RUSTC_WRAPPER':'wrapper'}, {'RUSTUP_TOOLCHAIN':'1.95.0','CARGO_PROFILE_BENCH_OPT_LEVEL':'0'}):
            with self.subTest(env=env),self.assertRaises(ValueError):build_environment(env)


class LedgerTests(unittest.TestCase):
    def setup_capture(self, root):
        evidence=root/'evidence';evidence.mkdir()
        (evidence/'timing.bin').write_bytes(b'synthetic')
        sha=hashlib.sha256(b'synthetic').hexdigest()
        c={'schema':1,'metadata':{'event':'schedule','run_attempt':1,'started_at':'2030-01-01T05:00:00Z','feature_leg':'default'},
           'processes':[], 'binary_before_sha256':sha,'measurement_enabled':True,
           'identity_sha256':{name:'f'*64 for name in IDENTITY_FILES}}
        f={'calibration_start':'2030-01-01','calibration_end':'2030-02-12',
           'identity_sha256_by_leg':{'default':{name:'f'*64 for name in IDENTITY_FILES}}}
        c['freeze_sha256']=digest(canonical(f))
        return evidence,c,f

    def test_no_measurement_without_complete_freeze_and_window(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);e,c,f=self.setup_capture(root);now=datetime(2030,1,1,5,1,tzinfo=timezone.utc)
            self.assertGreater(authorize_pass(c,f,e,1,now),0)
            for field,value in [('measurement_enabled',False),('identity_sha256',{})]:
                changed=dict(c);changed[field]=value
                with self.assertRaises(ValueError):authorize_pass(changed,f,e,1,now)
            with self.assertRaises(ValueError):authorize_pass(c,{},e,1,now)
            with self.assertRaises(ValueError):authorize_pass(c,f,e,1,datetime(2029,12,31,tzinfo=timezone.utc))
            with self.assertRaises(ValueError):authorize_pass(c,f,e,1,datetime(2030,1,1,5,41,tzinfo=timezone.utc))
            for field,value in [('event','workflow_dispatch'),('run_attempt',2),('started_at','2030-02-12T05:00:00Z')]:
                changed=json.loads(json.dumps(c));changed['metadata'][field]=value
                with self.assertRaises(ValueError):authorize_pass(changed,f,e,1,now)

    def test_binary_drift_and_duplicate_pass_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            e,c,f=self.setup_capture(Path(tmp));now=datetime(2030,1,1,5,1,tzinfo=timezone.utc)
            c['processes']=[{'pass':1,'status':'started'}]
            with self.assertRaises(ValueError):authorize_pass(c,f,e,1,now)
            with self.assertRaises(ValueError):authorize_pass(c,f,e,2,now)
            c['processes']=[];(e/'timing.bin').write_bytes(b'changed')
            with self.assertRaises(ValueError):authorize_pass(c,f,e,1,now)

    def test_failed_process_retains_partial_output_and_cannot_be_retried(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);e,c,f=self.setup_capture(root)
            # Inject a fake launcher; no crypto or timing program is run.
            def fail(command, **kwargs):
                kwargs['stdout'].write(b'partial synthetic output\n')
                return 7
            code=record_pass(root,e,c,1,120,launcher=fail)
            self.assertEqual(code,7);self.assertEqual(c['processes'][0]['status'],'failed')
            self.assertIn(b'partial synthetic output',(e/'output.log').read_bytes())
            self.assertEqual((root/'dudect-nightly-1.log').read_bytes(),b'partial synthetic output\n')
            with self.assertRaises(ValueError):authorize_pass(c,f,e,1,datetime(2030,1,1,5,2,tzinfo=timezone.utc))
            seal(e,c)
            self.assertEqual(c['files']['output.log'],hashlib.sha256((e/'output.log').read_bytes()).hexdigest())
            self.assertNotIn('capture.json',c['files'])



class IntegrationTests(unittest.TestCase):
    def test_five_synthetic_passes_replay_through_the_real_qualifier(self):
        import v115_capture as producer
        from v115_evidence import qualify_capture
        from test_v115_evidence import captured, output
        j, frozen, c, files = captured()
        c['metadata'].update(event='schedule', started_at='2030-01-01T05:00:00Z')
        c['processes'] = []
        c['measurement_enabled'] = True
        c['identity_sha256'] = frozen['identity_sha256_by_leg']['default']
        frozen.update(calibration_start='2030-01-01', calibration_end='2030-02-12')
        c['freeze_sha256'] = digest(canonical(frozen))
        one_pass = output().split('=== dudect run 1/5 (features=crypto-bigint-scalar) ===\n',1)[1].split('=== dudect run 2/5',1)[0].encode()
        def fake(command, **kwargs):
            self.assertEqual(command[-1], '--bench')
            self.assertEqual(kwargs['env']['DUDECT_SAMPLES'], '100000')
            kwargs['stdout'].write(one_pass)
            return 0
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);e=root/'evidence';e.mkdir()
            for name,data in files.items():
                if name=='output.log':continue
                path=e/name;path.parent.mkdir(exist_ok=True);path.write_bytes(data)
            with patch.object(producer.sys, 'stdout', SimpleNamespace(buffer=io.BytesIO())):
                for i in range(1,6):
                    remaining=authorize_pass(c,frozen,e,i,datetime(2030,1,1,5,i,tzinfo=timezone.utc))
                    self.assertEqual(record_pass(root,e,c,i,remaining,launcher=fake),0)
            with patch.object(producer,'snapshot',return_value=c['identity_sha256']):
                producer.finalize(root,e,c)
            archived={p.relative_to(e).as_posix():p.read_bytes() for p in e.rglob('*') if p.is_file() and p.name!='capture.json'}
            result=qualify_capture(j,frozen,c,archived)
            self.assertTrue(result['capture_qualified'],result['issues'])

    def test_prepare_builds_only_and_failure_does_not_replace_a_drifted_lock(self):
        import v115_capture as producer
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);binary=root/'fake-compiled-binary';binary.write_bytes(b'fake')
            lock=root/'frozen.lock';lock.write_bytes(b'frozen')
            meta=root/'metadata.json';meta.write_text(json.dumps({'run_id':1,'job_id':2,'run_attempt':1,'head_sha':'a'*40,'feature_leg':'default'}))
            def snapshot(root,directory,leg,env):
                directory.mkdir(exist_ok=True)
                values={name:digest(name.encode()) for name in IDENTITY_FILES}
                for name in values:(directory/name).write_text(name)
                return values
            calls=[]
            def build(command,**kwargs):
                calls.append(command)
                self.assertEqual(command[:4],['cargo','bench','--no-run','--locked'])
                kwargs['stdout'].write((json.dumps({'reason':'compiler-artifact','target':{'name':'timing_leaks'},'executable':str(binary)})+'\n').encode())
            with patch.dict(producer.os.environ,{'RUSTUP_TOOLCHAIN':'1.95.0'},clear=True), patch.object(producer,'LOCK_SHA',digest(b'frozen')), patch.object(producer,'read_cpu',return_value='synthetic CPU'), patch.object(producer,'command_output',return_value='a'*40), patch.object(producer,'snapshot',side_effect=snapshot), patch.object(producer.subprocess,'run',side_effect=build):
                c=producer.prepare(root,root/'evidence','default',lock,meta,None)
                self.assertEqual(len(calls),1)
                self.assertEqual(c['status'],'prepared-no-timing-run')
                self.assertFalse(c['measurement_enabled']);self.assertEqual(c['processes'],[])
                (root/'Cargo.lock').write_bytes(b'drifted')
                with self.assertRaises(ValueError):producer.prepare(root,root/'failed','default',lock,meta,None)
                self.assertEqual((root/'Cargo.lock').read_bytes(),b'drifted')
                failed=json.loads((root/'failed/capture.json').read_text())
                self.assertEqual(failed['status'],'preparation-failed')
                self.assertEqual(len(calls),1)

    def test_timeout_retains_output_and_started_attempt(self):
        import v115_capture as producer
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);e,c,f=LedgerTests().setup_capture(root)
            def timeout(command,**kwargs):
                kwargs['stdout'].write(b'timeout partial\n')
                raise subprocess.TimeoutExpired(command,1)
            with patch.object(producer.sys,'stdout',SimpleNamespace(buffer=io.BytesIO())), self.assertRaises(subprocess.TimeoutExpired):
                record_pass(root,e,c,1,1,launcher=timeout)
            self.assertEqual(c['processes'][0]['status'],'failed')
            self.assertIn(b'timeout partial',(e/'output.log').read_bytes())


if __name__=='__main__':unittest.main()
