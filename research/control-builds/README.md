# v1.15 structural control preparation — build only

Research branch only. Never merge the nightly-workflow replacement or generated
crate patches. Implements the already accepted `docs/v1.15-protocol.md` section 5
recipes, before C0 and before any control timing. No timing executable is run.
No timing values are inputs to this preparation and effects cannot be retuned.

Each of the four exact nightly feature legs uses Rust 1.95.0 and the frozen
research lock against accepted source b22718fd545501ec42ce578808dcbdea22b9d9d4.
Preserve full effective compiler/cargo/flags, CPU, image and kernel metadata.
A clock starts before checkout; the preparation wrapper subtracts all elapsed
setup time and a ten-minute evidence reserve from the 90-minute job cap. The
80-minute enclosing step is an additional limit, not the reserve calculation.
On expiration the wrapper terminates its own preparation process group and
records the timeout before partial evidence hashing and upload. Build failures require source/build
correction before qualification; there are no measurement draws to replace.

Build one unmodified full-suite baseline timing executable plus five variants
for each of the four targets: sham, modest-left, modest-right, gross-left and
gross-right. Every normal binary is built with `cargo bench --no-run` and only
copied/disassembled. All outputs, source patches, lock/metadata and binary hashes
are retained. No raw timing exporter change is needed for build qualification.

The generated research helper evaluates the real input predicate inside the
existing timed window. For field work it barriers the initial state and both
sides of each square. For HMAC it uses a separate state and key-repeated block,
unconditionally barriers the completed block before the predicate branch,
barriers state/input around update, consumes state without finalize, and leaves
original HMAC outputs unchanged. Sham uses the identical predicate and setup with
zero work. Modest/gross counts are fixed at 16/1024 squares or 1/64 SM3 blocks;
directions are highest input bit zero (left) or one (right).

For each target/variant, a separate untimed instrumented build uses the same
recipe, adding atomic counters after predicate evaluation and each extra
operation, plus a counter at actual SM3 compression entry. An untimed generated
example checks both original class inputs and records crypto outputs. Those
outputs must match an instrumented but uninjected baseline. Expected work is
checked against the protocol counts; the HMAC compression increment must exactly
match the extra block count. Signing applies work to each of its two fixed
retries: 32/2048 total squares on the selected class. Its four-draw sampler keeps
the first valid candidate, so each retry selects nonce 1 or n-5 from the actual
ClassKRng, whose source is copied verbatim into the untimed probe.

Counters are absent from the normal binaries. Passing instrumented checks and
finding the normal helper symbol are necessary, not sufficient: each normal
binary still requires optimized-code inspection of input predicate, direction,
retained chain and exact work count. `structural-result.json` explicitly says
optimized inspection pending and measurement forbidden. Preserve the inspection
record and exact patch/build hashes before freezing a study manifest or C0.
This preparation is not calibration, confirmation, or sensitivity evidence.
