//! Fuzz target: the low-level strict-canonical DER reader primitives that
//! every higher decoder is built on. Direct fuzzing reaches malformed
//! length/tag shapes the higher grammars constrain away. First byte selects
//! the expected tag / context number; the rest is the TLV input.
//! Invariant: every primitive returns `Some`/`None` — never panics.
#![no_main]

use gmcrypto_core::asn1::reader;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (tag, input) = match data.split_first() {
        Some((t, rest)) => (*t, rest),
        None => return,
    };
    let _ = reader::read_length(input);
    let _ = reader::read_tag(input, tag);
    let _ = reader::read_tlv(input, tag);
    let _ = reader::read_integer(input);
    let _ = reader::read_octet_string(input);
    let _ = reader::read_null(input);
    let _ = reader::read_oid(input);
    let _ = reader::read_bit_string(input);
    let _ = reader::read_sequence(input);
    let _ = reader::read_context_tagged_explicit(input, tag & 0x1f);
});
