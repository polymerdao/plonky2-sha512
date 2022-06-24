# plonky2-sha512

This repository contains [SNARK](https://en.wikipedia.org/wiki/Non-interactive_zero-knowledge_proof) circuits of a
cryptographic hash function [SHA-512](https://en.wikipedia.org/wiki/SHA-2) implemented
with [Plonky2](https://github.com/mir-protocol/plonky2).

Run benchmarks

```console
cargo run --release --package plonky2_sha512 --bin plonky2_sha512
```

Benchmark on a Macbook Pro (M1), preimage message size = 128 (block count = 2)

```console
Constructing inner proof with 50095 gates
[INFO  plonky2::plonk::circuit_builder] Degree before blinding & padding: 50186
[INFO  plonky2::plonk::circuit_builder] Degree after blinding & padding: 65536
[DEBUG plonky2::plonk::circuit_builder] Building circuit took 3.4014452s
[DEBUG plonky2::util::timing] 3.8840s to prove
[DEBUG plonky2::util::timing] 0.0055s to verify
```
