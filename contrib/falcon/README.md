# Falcon Verify on AVX-512

AVX-512 implementation of Falcon signature verification.

The implementation lives upstream in **Firedancer** under
[`src/ballet/falcon`](https://github.com/firedancer-io/firedancer/tree/main/src/ballet/falcon), and is described in the paper
**Falcon Verify on AVX-512: Speed Records** [2026/1234](https://eprint.iacr.org/2026/1234).

This repository is self-contained so the benchmarks in the paper can be reproduced without the rest of the Firedancer tree.

## Build

```
make            # builds bench and test_falcon
make test       # runs the correctness tests
./bench         # runs the benchmark
```

Default toolchain is `gcc`; pass `CC=clang` to override. The build
assumes `-march=native`. See `bench --help` for options.

## Citation

```bibtex
@misc{rubin-cesena-falcon-avx512,
  author       = {David Rubin and Emanuele Cesena},
  title        = {Falcon Verify on {AVX-512}: Speed Records},
  howpublished = {Cryptology {ePrint} Archive, Paper 2026/1234},
  year         = {2026},
  url          = {https://eprint.iacr.org/2026/1234}
}
```

## License

Apache 2.0; see [`LICENSE`](LICENSE). The vendored sources in
`vendor/` keep their upstream licenses.

**Disclaimer. This alpha software has been open sourced. All software and code are provided “as is,” without any warranty of any kind, and should be used at your own risk.**
