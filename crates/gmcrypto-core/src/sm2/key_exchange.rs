//! SM2 key exchange — GM/T 0003.3 (≡ GB/T 32918.3-2016) with key confirmation.
//!
//! Two role state-machines, `Sm2KxInitiator` and `Sm2KxResponder`. Pure-core;
//! reuses the SM2 curve arithmetic, the masked ephemeral sampler, the SM3 KDF,
//! `compute_z`, and the SEC1 point validation. Confidentiality of the agreed
//! key relies on the caller keeping each ephemeral single-use (the typestate
//! enforces it).

extern crate alloc;
