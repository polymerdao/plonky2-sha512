# plonky2-sha512

```console
cargo run --release --package plonky2_sha512 --bin plonky2_sha512
```

Benchmark on Macbook Pro M1

```console
    Finished release [optimized] target(s) in 0.03s
     Running `target/release/plonky2_sha512`
Constructing inner proof with 40830 gates
[INFO  plonky2::plonk::circuit_builder] Degree before blinding & padding: 40921
[INFO  plonky2::plonk::circuit_builder] Degree after blinding & padding: 65536
[DEBUG plonky2::plonk::circuit_builder] Building circuit took 3.5057101s
[DEBUG plonky2::util::timing] 5.7480s to prove
[DEBUG plonky2::util::timing] 0.0065s to verify
```
