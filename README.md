# halo2-franchise-proof

This is an experimental port of the Vocdoni voting anonymizer zk circuit (see [current implementation](https://https://github.com/vocdoni/zk-franchise-proof-circuit) using [Groth16](http://www.zeroknowledgeblog.com/index.php/groth16)/[circom](https://github.com/iden3/circom)) to the [ZCash Halo2](https://zcash.github.io/halo2) proving system that do not have trusted setup.

## Run benchmarks

run `cargo bench`

current results in an M1 are:

| Merkle tree levels | Prove (ms) | Verify (ms) |
| -------- | -------- | -------- |
| 9     | 172.49     | 6.29     |
| 21     | 283.62     | 8.32     |

when running in a wasm/browser context in a mobile (Galaxy A41) the execution time is about 10s in a single-threaded environment.

