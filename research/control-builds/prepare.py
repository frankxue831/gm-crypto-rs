"""Build control binaries and run ONLY untimed qualification executables.

A successful job is still pending optimized-code review; it does not authorize
measurements or start C0. Timing executables are copied/disassembled, never run.
"""
from pathlib import Path
import ast
import difflib
import hashlib
import json
import os
import shutil
import subprocess
import sys
from recipe import CORE, TARGETS, patch, probe, variants

HERE=Path(__file__).resolve().parent
LOCK_HASH='e2800837c468ba45d21e759d50e94dc115e3f72eb3139c579305a908b60ed1c8'
LEGS=('default','sm4-bitsliced','sm4-bitsliced-simd',
      'sm4-bitsliced-simd,sm4-aead,sm4-xts,sm2-key-exchange,tlcp')


def run(command, root, output, env=None):
    with output.open('w') as out, output.with_suffix(output.suffix+'.stderr').open('w') as err:
        subprocess.run(command,cwd=root,env=env,stdout=out,stderr=err,check=True)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def archive_changes(original, changed, out):
    records=[];diff=''
    for p in sorted((changed/CORE).rglob('*')):
        if not p.is_file():continue
        rel=p.relative_to(changed);before=original/rel
        if before.exists() and before.read_bytes()==p.read_bytes():continue
        b=p.read_bytes();records.append({'path':str(rel),'bytes':len(b),'sha256':digest(p)})
        diff+=''.join(difflib.unified_diff(before.read_text().splitlines(True) if before.exists() else [],
            p.read_text().splitlines(True),fromfile='base/'+str(rel),tofile='control/'+str(rel)))
    (out/'source.patch').write_text(diff)
    (out/'changed-files.json').write_text(json.dumps(records,indent=2)+'\n')


def metadata(root,out,features,env):
    run(['cargo','metadata','--locked','--features',features,'--filter-platform',
         'x86_64-unknown-linux-gnu','--format-version','1'],root,out,env)
    return {(x['name'],x['version'],x['source']) for x in json.loads(out.read_text())['packages']}


def compile_artifact(root,out,features,kind,env):
    name='timing_leaks' if kind=='timing' else 'v115_qualify'
    command=(['cargo','bench','--no-run','--bench',name] if kind=='timing' else
             ['cargo','build','--release','--example',name])
    run(command+['--locked','--features',features,'--message-format=json'],root,out/'build.json',env)
    paths=[x['executable'] for line in (out/'build.json').read_text().splitlines()
           if (x:=json.loads(line)).get('reason')=='compiler-artifact'
           and x.get('target',{}).get('name')==name and x.get('executable')]
    if len(paths)!=1:raise ValueError('expected exactly one executable')
    dest=out/(kind+'.bin');shutil.copyfile(paths[0],dest);dest.chmod(0o755)
    if kind=='timing':
        run(['objdump','-d','-C',str(dest)],root,out/'timing.asm',env)
        run(['nm','-C',str(dest)],root,out/'symbols.txt',env)
    else:
        # This generated example has no dudect call or timing loop.
        run([str(dest)],root,out/'untimed.log',env)
    return digest(dest)


def parse_probe(path):
    outputs={};counts={}
    for line in path.read_text().splitlines():
        tag,label,value=line.split(' ',2)
        target=outputs if tag=='OUTPUT' else counts if tag=='COUNTS' else None
        if target is None or label not in ('left','right') or label in target:
            raise ValueError('unexpected/duplicate untimed output')
        target[label]=ast.literal_eval(value)
    if outputs.keys()!=counts.keys() or outputs.keys()!={'left','right'}:
        raise ValueError('incomplete untimed output')
    if any(not isinstance(v,list) or not v or any(type(x)is not int or not 0 <= x <= 255 for x in v) for v in outputs.values()):
        raise ValueError('invalid crypto output bytes')
    if any(not isinstance(v,list) or len(v)!=4 or any(type(x)is not int or x<0 for x in v) for v in counts.values()):
        raise ValueError('invalid operation counters')
    return outputs,counts


def verify_probe(target,variant,output,baseline):
    values,counts=parse_probe(output);expected_values,base_counts=baseline
    if values!=expected_values:raise ValueError('crypto output changed')
    n,direction=next((n,d) for name,n,d in variants(target) if name==variant)
    calls=2 if target=='ct_sign_k_class' else 1
    for label,bit in [('left',0),('right',1)]:
        work=calls*n if bit==direction else 0
        extra_compressions=work if target=='ct_hmac_sm3' else 0
        expected=[calls,calls*bit,work,base_counts[label][3]+extra_compressions]
        if counts[label]!=expected:raise ValueError(f'{target}/{variant}/{label}: {counts[label]} != {expected}')
    return counts


def validate_record(record, validator, ledger, path):
    try:
        result=validator()
        record['status']='untimed-qualified-optimized-inspection-pending'
        record['validation']=result
        return result
    except Exception as error:
        record.update(status='validation-failed',error=str(error))
        raise
    finally:
        path.write_text(json.dumps(ledger,indent=2)+'\n')


def baseline_probe(path):
    baseline=parse_probe(path)
    if any(c[:3]!=[0,0,0] for c in baseline[1].values()):
        raise ValueError('baseline unexpectedly injected work')
    return baseline


def main(source,work,evidence,leg):
    if leg not in LEGS:raise ValueError('unknown exact feature leg')
    source,work,evidence=map(lambda p:Path(p).resolve(),(source,work,evidence))
    sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip()
    if sha!=(HERE/'source-id.txt').read_text().strip():raise ValueError('wrong source checkout')
    frozen=(HERE/'frozen.lock').read_bytes()
    if hashlib.sha256(frozen).hexdigest()!=LOCK_HASH:raise ValueError('lock drift')
    features='crypto-bigint-scalar' if leg=='default' else leg+',crypto-bigint-scalar'
    work.mkdir();evidence.mkdir(exist_ok=True)
    env=os.environ.copy();env['CARGO_TARGET_DIR']=str(work/'target')
    (source/'Cargo.lock').write_bytes(frozen)
    names=subprocess.check_output(['git','ls-tree','-r','--name-only','HEAD','crates','Cargo.toml','rust-toolchain.toml','.cargo'],cwd=source,text=True).splitlines()
    inputs=[{'path':name,'bytes':(source/name).stat().st_size,'sha256':digest(source/name)} for name in names]
    (evidence/'base-input-manifest.json').write_text(json.dumps(inputs,indent=2)+'\n')
    expected=metadata(source,evidence/'base-metadata.json',features,env)
    for p in HERE.iterdir():
        if p.is_file():shutil.copyfile(p,evidence/p.name)
    ledger=[]
    def build(target,variant,instrumented):
        label=target+'-'+variant+('-counted' if instrumented else '-timing')
        out=evidence/label;out.mkdir();root=work/label
        record={'target':target,'variant':variant,'instrumented':instrumented,'status':'started','directory':label}
        ledger.append(record);(evidence/'build-ledger.json').write_text(json.dumps(ledger,indent=2)+'\n')
        try:
            shutil.copytree(source,root,ignore=shutil.ignore_patterns('.git','target','evidence'))
            patch(root,target,variant,instrumented)
            if instrumented:probe(root,target,variant)
            archive_changes(source,root,out)
            actual=metadata(root,out/'metadata.json',features,env)
            if actual!=expected:raise ValueError('resolved package identity drift')
            if (root/'Cargo.lock').read_bytes()!=frozen:raise ValueError('lock rewritten')
            kind='probe' if instrumented else 'timing'
            record['binary_sha256']=compile_artifact(root,out,features,kind,env)
            record['patch_sha256']=digest(out/'source.patch')
            record['status']='probe-executed-validation-pending' if instrumented else 'built-not-executed'
            (evidence/'build-ledger.json').write_text(json.dumps(ledger,indent=2)+'\n')
        except Exception as error:
            record.update(status='build-or-probe-failed',error=str(error))
            raise
        finally:
            (evidence/'build-ledger.json').write_text(json.dumps(ledger,indent=2)+'\n')
        return out,record
    build('ct_fn_invert','baseline',False)  # One unmodified full-suite binary per leg.
    validation=[]
    for target in TARGETS:
        base,base_record=build(target,'baseline',True)
        baseline=validate_record(base_record,lambda:baseline_probe(base/'untimed.log'),ledger,evidence/'build-ledger.json')
        for variant,n,direction in variants(target):
            normal,normal_record=build(target,variant,False)
            counted,counted_record=build(target,variant,True)
            counts=validate_record(counted_record,lambda:verify_probe(target,variant,counted/'untimed.log',baseline),ledger,evidence/'build-ledger.json')
            if 'v115_research::injected_work' not in (normal/'symbols.txt').read_text():
                raise ValueError('missing control symbol; needs structural correction')
            validation.append({'target':target,'variant':variant,'work_per_call':n,
                               'predicate_direction':direction,'counts':counts})
    (evidence/'structural-result.json').write_text(json.dumps({
        'status':'untimed qualification passed; optimized inspection pending; measurement forbidden',
        'source':sha,'feature_leg':leg,'bench_features':features,'lock_sha256':LOCK_HASH,
        'timing_executables_run':0,'variants':validation},indent=2)+'\n')


if __name__=='__main__':
    try:main(*sys.argv[1:])
    except Exception as error:
        evidence=Path(sys.argv[3]);evidence.mkdir(exist_ok=True)
        (evidence/'preparation-failure.json').write_text(json.dumps({'error':str(error),'type':type(error).__name__},indent=2)+'\n')
        raise
