//! F21 functional preflight: fixed inputs for a future
//! `Sm4CbcDecryptor::finalize()` timing study, plus the single-consumption
//! wrapper such a study needs.
//!
//! This file checks *function only*. It does not measure time, does not run
//! the dudect harness, and does not close F21. See
//! `docs/f21-finalize-preflight.md` for the method and its limits.
//!
//! Every value here (key, IV, plaintext) is a fixed public research sample,
//! not a secret-bearing product path.
//!
//! The ciphertexts are built with the public SM4 block API rather than the
//! high-level CBC encryptor, because the encryptor always appends its own
//! valid PKCS#7 padding and so cannot produce a chosen invalid final block.

use std::cell::RefCell;

use gmcrypto_core::sm4::{BLOCK_SIZE, KEY_SIZE, Sm4CbcDecryptor, Sm4Cipher};

const KEY: [u8; KEY_SIZE] = [0x42; KEY_SIZE];
const IV: [u8; BLOCK_SIZE] = [0x33; BLOCK_SIZE];
/// First plaintext block, shared by every sample.
const FIRST_PLAIN: [u8; BLOCK_SIZE] = *b"f21 public block";
/// Pad value carried by the last byte of every final block.
const PAD: u8 = 16;
/// The single wrong byte written into an invalid final block.
const WRONG: u8 = 0x0f;
/// Error position of the "early" invalid class.
const EARLY_INDEX: usize = 0;
/// Error position of the "late" invalid class.
const LATE_INDEX: usize = 14;
const TOTAL_LEN: usize = 2 * BLOCK_SIZE;

/// One prepared sample: a fully-updated decryptor that can be finalized once.
type Sample = RefCell<Option<Sm4CbcDecryptor>>;

fn xor_in_place(block: &mut [u8; BLOCK_SIZE], mask: &[u8; BLOCK_SIZE]) {
    for (b, m) in block.iter_mut().zip(mask.iter()) {
        *b ^= *m;
    }
}

/// Final plaintext block: all `PAD`, with at most one byte replaced.
const fn tail_block(error_index: Option<usize>) -> [u8; BLOCK_SIZE] {
    let mut tail = [PAD; BLOCK_SIZE];
    if let Some(index) = error_index {
        tail[index] = WRONG;
    }
    tail
}

/// Two-block CBC ciphertext built by hand from the raw block cipher.
fn build_ciphertext(error_index: Option<usize>) -> [u8; TOTAL_LEN] {
    let cipher = Sm4Cipher::new(&KEY);

    let mut first = FIRST_PLAIN;
    xor_in_place(&mut first, &IV);
    cipher.encrypt_block(&mut first);

    let mut second = tail_block(error_index);
    xor_in_place(&mut second, &first);
    cipher.encrypt_block(&mut second);

    let mut out = [0u8; TOTAL_LEN];
    out[..BLOCK_SIZE].copy_from_slice(&first);
    out[BLOCK_SIZE..].copy_from_slice(&second);
    out
}

/// Independent CBC decrypt of one block, again from the raw block cipher.
fn recover_block(ciphertext: &[u8; TOTAL_LEN], index: usize) -> [u8; BLOCK_SIZE] {
    let start = index * BLOCK_SIZE;
    let mut prev = IV;
    if index > 0 {
        prev.copy_from_slice(&ciphertext[start - BLOCK_SIZE..start]);
    }
    let mut block = [0u8; BLOCK_SIZE];
    block.copy_from_slice(&ciphertext[start..start + BLOCK_SIZE]);
    Sm4Cipher::new(&KEY).decrypt_block(&mut block);
    xor_in_place(&mut block, &prev);
    block
}

/// Every index whose byte differs from `PAD`.
fn error_positions(tail: &[u8; BLOCK_SIZE]) -> Vec<usize> {
    let mut positions = Vec::new();
    for (i, byte) in tail.iter().enumerate() {
        if *byte != PAD {
            positions.push(i);
        }
    }
    positions
}

/// Streaming decryptor with the whole ciphertext already absorbed, so that
/// only `finalize` remains.
fn prepare(ciphertext: &[u8]) -> Sm4CbcDecryptor {
    let mut dec = Sm4CbcDecryptor::new(&KEY, &IV);
    dec.update(ciphertext);
    dec
}

fn fresh_sample(ciphertext: &[u8]) -> Sample {
    RefCell::new(Some(prepare(ciphertext)))
}

fn oneshot(ciphertext: &[u8]) -> Option<Vec<u8>> {
    gmcrypto_core::sm4::mode_cbc::decrypt(&KEY, &IV, ciphertext)
}

/// Stand-in for a harness entry point that only accepts `Fn`. A closure that
/// moved the decryptor in would be `FnOnce` and would not compile here.
fn run_fn<F: Fn() -> Option<Vec<u8>>>(f: F) -> Option<Vec<u8>> {
    f()
}

/// Take the decryptor out of the slot and finalize it. Panics if the slot was
/// already consumed: a sample is good for exactly one `finalize`.
fn consume_once(slot: &Sample) -> Option<Vec<u8>> {
    let taken = slot.borrow_mut().take();
    let dec = taken.expect("sample already consumed");
    dec.finalize()
}

fn second_take_panics(slot: &Sample) -> bool {
    let attempt = std::panic::AssertUnwindSafe(|| run_fn(|| consume_once(slot)));
    std::panic::catch_unwind(attempt).is_err()
}

#[test]
fn inputs_have_equal_shape_and_exact_error_positions() {
    let early = build_ciphertext(Some(EARLY_INDEX));
    let late = build_ciphertext(Some(LATE_INDEX));

    // Equal public shape: same length, identical first ciphertext block, and
    // only the final block carries the class label.
    assert_eq!(early.len(), TOTAL_LEN);
    assert_eq!(late.len(), TOTAL_LEN);
    assert_eq!(&early[..BLOCK_SIZE], &late[..BLOCK_SIZE]);
    assert_ne!(&early[BLOCK_SIZE..], &late[BLOCK_SIZE..]);

    // Both classes share the first plaintext block.
    assert_eq!(recover_block(&early, 0), FIRST_PLAIN);
    assert_eq!(recover_block(&late, 0), FIRST_PLAIN);

    // Independently rebuilt final blocks: exactly one wrong byte each, at the
    // intended index, and the last byte is still pad = 16.
    let early_tail = recover_block(&early, 1);
    let late_tail = recover_block(&late, 1);
    assert_eq!(error_positions(&early_tail), [EARLY_INDEX]);
    assert_eq!(error_positions(&late_tail), [LATE_INDEX]);
    assert_eq!(early_tail[EARLY_INDEX], WRONG);
    assert_eq!(late_tail[LATE_INDEX], WRONG);
    assert_eq!(early_tail[BLOCK_SIZE - 1], PAD);
    assert_eq!(late_tail[BLOCK_SIZE - 1], PAD);
}

#[test]
fn both_invalid_classes_are_rejected() {
    for index in [EARLY_INDEX, LATE_INDEX] {
        let ciphertext = build_ciphertext(Some(index));

        // Streaming, whole ciphertext in one update.
        assert!(prepare(&ciphertext).finalize().is_none());

        // Streaming, one block per update.
        let mut split = Sm4CbcDecryptor::new(&KEY, &IV);
        split.update(&ciphertext[..BLOCK_SIZE]);
        split.update(&ciphertext[BLOCK_SIZE..]);
        assert!(split.finalize().is_none());

        // One-shot decrypt shares the same strip and must agree.
        assert!(oneshot(&ciphertext).is_none());
    }
}

#[test]
fn valid_padding_control_succeeds() {
    let ciphertext = build_ciphertext(None);
    assert_eq!(ciphertext.len(), TOTAL_LEN);
    assert_eq!(recover_block(&ciphertext, 1), [PAD; BLOCK_SIZE]);

    // Same first ciphertext block as the invalid classes.
    let early = build_ciphertext(Some(EARLY_INDEX));
    assert_eq!(&ciphertext[..BLOCK_SIZE], &early[..BLOCK_SIZE]);

    // The hand-built control is byte-identical to the library encryptor, so
    // the manual CBC construction used for the invalid classes is sound.
    let reference = gmcrypto_core::sm4::mode_cbc::encrypt(&KEY, &IV, &FIRST_PLAIN);
    assert_eq!(reference, ciphertext);

    let streamed = prepare(&ciphertext).finalize();
    assert_eq!(streamed.as_deref(), Some(&FIRST_PLAIN[..]));
    let single = oneshot(&ciphertext);
    assert_eq!(single.as_deref(), Some(&FIRST_PLAIN[..]));
}

#[test]
fn fn_wrapper_consumes_once() {
    let invalid = build_ciphertext(Some(EARLY_INDEX));
    let slot = fresh_sample(&invalid);
    assert!(slot.borrow().is_some());

    // First consumption goes through an `Fn` bound and finalizes.
    let first = run_fn(|| consume_once(&slot));
    assert!(first.is_none());
    assert!(slot.borrow().is_none());

    // Second consumption of the same state fails loudly and leaves the slot
    // empty and still borrowable.
    assert!(second_take_panics(&slot));
    assert!(slot.borrow().is_none());

    // Same contract on the success path.
    let valid = build_ciphertext(None);
    let control = fresh_sample(&valid);
    let plain = run_fn(|| consume_once(&control));
    assert_eq!(plain.as_deref(), Some(&FIRST_PLAIN[..]));
    assert!(control.borrow().is_none());
    assert!(second_take_panics(&control));
}

#[test]
fn fresh_samples_are_independent() {
    let early = build_ciphertext(Some(EARLY_INDEX));
    let late = build_ciphertext(Some(LATE_INDEX));
    let valid = build_ciphertext(None);

    // Preparation is deterministic: rebuilding gives the same bytes.
    assert_eq!(early, build_ciphertext(Some(EARLY_INDEX)));
    assert_eq!(late, build_ciphertext(Some(LATE_INDEX)));

    let first = fresh_sample(&early);
    let second = fresh_sample(&early);
    let third = fresh_sample(&late);
    let control = fresh_sample(&valid);

    // Consuming one sample leaves every other sample untouched.
    assert!(run_fn(|| consume_once(&first)).is_none());
    assert!(first.borrow().is_none());
    assert!(second.borrow().is_some());
    assert!(third.borrow().is_some());
    assert!(control.borrow().is_some());

    // Each remaining sample still yields its own result.
    assert!(run_fn(|| consume_once(&second)).is_none());
    assert!(run_fn(|| consume_once(&third)).is_none());
    let plain = run_fn(|| consume_once(&control));
    assert_eq!(plain.as_deref(), Some(&FIRST_PLAIN[..]));

    // A spent sample stays spent; a new measurement needs a newly prepared
    // sample, which works regardless of the spent one.
    assert!(second_take_panics(&first));
    let again = fresh_sample(&early);
    assert!(run_fn(|| consume_once(&again)).is_none());
    assert!(second_take_panics(&again));
    assert!(second_take_panics(&first));
}
