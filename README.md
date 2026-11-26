# qlma-sovereign-stack

A small, tested set of classical cryptanalysis and inter-process telemetry examples.

## Scope

This repository does **not** claim quantum acceleration, P=NP resolution, real hardware entropy, or a verified post-quantum implementation. The Rust bridge is a mock and must not be used in production.

- `python/decryption_engine_solver.py`: Base64, URL, hexadecimal, binary, Morse, Caesar, Atbash, Vigenère, Rail Fence, and XOR tooling.
- `cpp/telemetry_ring.cpp`: bounded POSIX shared-memory SPSC example.
- `rust/demo_crypto_bridge.rs`: fixed-data FFI demonstration; not ML-DSA-65.

## Build and test

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
make cpp-build
make cpp-run
make check
```

Python 3.9+ is required. The C++ example requires Linux, POSIX shared memory, and C++23.

## Safety

Use only with authorized test data. Validate untrusted frame contents before use. Shared-memory objects must have restrictive permissions and should be cleaned up on failure.
