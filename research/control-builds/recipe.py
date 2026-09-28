"""Generate disposable controls fixed by accepted protocol 05035d5.

Never apply to the maintained checkout. No timing-dependent knobs are exposed.
"""
from pathlib import Path

TARGETS = ('ct_fn_invert', 'ct_fp_invert', 'ct_sign_k_class', 'ct_hmac_sm3')
CORE = Path('crates/gmcrypto-core')


def variants(target):
    if target not in TARGETS:
        raise ValueError('unknown target')
    modest, gross = (1, 64) if target == 'ct_hmac_sm3' else (16, 1024)
    return [('sham',0,0), ('modest-left',modest,0), ('modest-right',modest,1),
            ('gross-left',gross,0), ('gross-right',gross,1)]


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('source anchor missing or ambiguous: '+old[:90])
    return text.replace(old, new)


def helper(target, count, direction, instrumented):
    if (count,direction) not in [(n,d) for _,n,d in variants(target)]:
        raise ValueError('effect not predeclared')
    result = '// ISOLATED INTENTIONALLY LEAKY RESEARCH BUILD. NEVER SHIP.\nuse core::hint::black_box;\n'
    if instrumented:
        result += '''use core::sync::atomic::{AtomicUsize, Ordering};
pub static CALLS: AtomicUsize = AtomicUsize::new(0);
pub static PRED_ONE: AtomicUsize = AtomicUsize::new(0);
pub static WORK: AtomicUsize = AtomicUsize::new(0);
pub static COMPRESS: AtomicUsize = AtomicUsize::new(0);
pub fn reset() {
    for x in [&CALLS, &PRED_ONE, &WORK, &COMPRESS] { x.store(0, Ordering::SeqCst); }
}
pub fn counts() -> [usize; 4] {
    [CALLS.load(Ordering::SeqCst), PRED_ONE.load(Ordering::SeqCst),
     WORK.load(Ordering::SeqCst), COMPRESS.load(Ordering::SeqCst)]
}
'''
    if target == 'ct_hmac_sm3':
        result += '''#[inline(never)]
pub fn injected_work(key: &[u8]) {
    let predicate = black_box(key.first().copied().unwrap_or(0) >> 7);
    let mut block = [0u8; 64];
    // Only the pinned 32-byte class keys are control inputs. Other public key
    // lengths retain their original output; their timing is not study evidence.
    if key.len() == 32 {
        block[..32].copy_from_slice(key);
        block[32..].copy_from_slice(key);
    }
    let block = black_box(block);
    let mut state = black_box(crate::sm3::Sm3::new());
'''
        operation = 'black_box(&mut state).update(black_box(&block));\n            black_box(&mut state);'
    else:
        field = 'Fp' if target == 'ct_fp_invert' else 'Fn'
        result += f'''#[inline(never)]
pub fn injected_work(x: &crate::sm2::{field}) {{
    let predicate = black_box(x.retrieve().to_be_bytes()[0] >> 7);
    let mut state = black_box(*x);
'''
        operation = 'state = black_box(black_box(state).square());'
    if instrumented:
        result += '''    CALLS.fetch_add(1, Ordering::SeqCst);
    PRED_ONE.fetch_add(predicate as usize, Ordering::SeqCst);
'''
    result += f'''    // Sham evaluates the same predicate and setup, with zero work.
    if predicate == {direction} {{
        for _ in 0..{count} {{
            {operation}
'''
    if instrumented:
        result += '            WORK.fetch_add(1, Ordering::SeqCst);\n'
    result += '''        }
    }
    black_box(state);
}
'''
    return result


def patch(root, target, variant, instrumented):
    """Patch exactly one target in a disposable source tree; baseline stays plain."""
    config = {name:(n,d) for name,n,d in variants(target)}
    if variant != 'baseline' and variant not in config:
        raise ValueError('unknown variant')
    root = Path(root)
    if variant == 'baseline' and not instrumented:
        return
    count,direction = config.get(variant,(0,0))
    lib = root/CORE/'src/lib.rs'
    lib.write_text(lib.read_text()+'\n#[doc(hidden)]\npub mod v115_research;\n')
    (root/CORE/'src/v115_research.rs').write_text(helper(target,count,direction,instrumented))
    if variant != 'baseline':
        if target in ('ct_fn_invert','ct_fp_invert'):
            p = root/CORE/'benches/timing_leaks.rs';text=p.read_text()
            start=text.index('fn '+target+'(');end=text.index('\n}\n',start)
            block=text[start:end]
            block=replace_once(block,'runner.run_one(class, || x.invert());',
                'runner.run_one(class, || { gmcrypto_core::v115_research::injected_work(x); x.invert() });')
            p.write_text(text[:start]+block+text[end:])
        elif target == 'ct_sign_k_class':
            p=root/CORE/'src/sm2/sign.rs';text=p.read_text()
            marker='    let (mut k, sample_ok) = sample_nonzero_scalar(rng)?;'
            p.write_text(replace_once(text,marker,marker+'\n    crate::v115_research::injected_work(&k);'))
        else:
            p=root/CORE/'src/hmac.rs';text=p.read_text()
            marker='pub fn hmac_sm3(key: &[u8], message: &[u8]) -> [u8; DIGEST_SIZE] {'
            p.write_text(replace_once(text,marker,marker+'\n    crate::v115_research::injected_work(key);'))
    if instrumented:
        p=root/CORE/'src/sm3.rs';text=p.read_text()
        marker='pub(crate) fn compress(state: &mut [u32; 8], block: &[u8; BLOCK_SIZE]) {'
        p.write_text(replace_once(text,marker,marker+'\n    crate::v115_research::COMPRESS.fetch_add(1, core::sync::atomic::Ordering::SeqCst);'))


def probe(root, target, variant):
    """Untimed executable exercises original crypto outputs and instrumented work."""
    root=Path(root)
    text='''use crypto_bigint::U256;
use gmcrypto_core::sm2::{Fn as Scalar, Fp, Sm2PrivateKey, DEFAULT_SIGNER_ID, sign_raw_with_id};
use gmcrypto_core::v115_research::{reset, counts};
use gmcrypto_core::hmac::hmac_sm3;
use core::convert::Infallible;
use rand_core::{TryRng, TryCryptoRng};
'''
    bench=(root/CORE/'benches/timing_leaks.rs').read_text()
    start=bench.index('struct ClassKRng {');end=bench.index('impl TryCryptoRng for ClassKRng {}',start)+len('impl TryCryptoRng for ClassKRng {}')
    text+=bench[start:end]+'\nfn main() {\n'
    text+='''    for (label, right) in [("left", false), ("right", true)] {
        reset();
'''
    if target == 'ct_fn_invert':
        text+='''        let x = Scalar::new(&U256::ONE) + Scalar::new(&U256::from_be_hex(if right {
            "B9E5B7C12E48BAB7CC0E91A57F8A48E8C8F87DDD25EBF52F2A75E612CB1A9E4F"
        } else { "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8" }));
'''
    elif target == 'ct_fp_invert':
        text+='''        let x = Fp::new(&if right { U256::from_be_hex(
            "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210")
        } else { U256::from_u64(0x1234) });
'''
    if target in ('ct_fn_invert','ct_fp_invert'):
        text+='        assert_eq!(x.retrieve().to_be_bytes()[0] >> 7, u8::from(right));\n'
        if variant != 'baseline':text+='        gmcrypto_core::v115_research::injected_work(&x);\n'
        text+='        let result = x.invert().unwrap().retrieve().to_be_bytes();\n'
    elif target == 'ct_sign_k_class':
        text+='''        let key = Sm2PrivateKey::from_scalar(U256::from_be_hex(
            "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8")).unwrap();
        let mut rng = if right { ClassKRng::new_right() } else { ClassKRng::new_left() };
        let (r, s) = sign_raw_with_id(&key, DEFAULT_SIGNER_ID, b"timing target", &mut rng).unwrap();
        let mut result = r.to_be_bytes().to_vec();
        result.extend_from_slice(&s.to_be_bytes());
'''
    else:
        text+='''        let key = if right { [0xa5u8;32] } else { [0x42u8;32] };
        assert_eq!(key[0] >> 7, u8::from(right));
        let result = hmac_sm3(&key, &[0u8;64]);
'''
    text+='''        println!("OUTPUT {label} {result:?}");
        println!("COUNTS {label} {:?}", counts());
    }
}
'''
    p=root/CORE/'examples/v115_qualify.rs';p.parent.mkdir(exist_ok=True);p.write_text(text)
