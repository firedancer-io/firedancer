# Experimental Linux RV64 port

Firedancer's supported target remains x86-64 Linux. This port is experimental:
passing tests or following testnet does not establish complete correctness
under RVWMO. Do not treat it as production validator support.

Build with an explicit machine profile:

```sh
make -j4 MACHINE=linux_gcc_riscv firedancer-dev
```

The support-only patch targets RV64GC. The subsequent acceleration patches
raise the explicit profile's ISA requirements as described below.
The port enables the Linux RV64 seccomp audit
architecture, uses the ppoll-based supervisor policy, and orders shared-memory
publication and credit return without assuming x86 TSO. Host asset-generation
tools use `HOSTCC`; cross-compilation requires a matching target toolchain.
No distribution-specific environment or host-network configuration is included.

The native profile also detects RV64 for memory ordering. Existing compiler
version restrictions still apply. The explicit profile is not an assertion
that a compiler rejected by the native profile is safe.

## Validation

Build the tests before running them. Review [testing.md](testing.md) for memory,
hugepage and privilege requirements. Relevant checks include:

- `test_pool_para --tile-cpus 0-3 --ele-max 16 --iter-cnt 10000000`
- `test_txncache --publication-only` (the full suite requires much more memory)
- `test_mcache_ordering` (requires two allowed CPUs)
- `test_mcache`, `test_fseq`, `test_stem_sticky_poll`, `test_cpu_isolation`
- `test_sched` for dispatch across different execution-worker counts

Select CPU IDs that are actually available on the test machine. Heterogeneous
systems may have vendor-specific affinity restrictions and different vector
performance per core. No vendor-specific thread classification is installed
or invoked by this port.

The configurable stake-cache and vote-history limits preserve production
values by default. Reducing them is intended for constrained non-voting replay
experiments, not for production voting. Shared tiles should use housekeeping
CPUs; dedicated replay/execution CPUs should remain isolated.

## Acceleration patches

With the complete series applied, the explicit profile requires
`rv64gcv_zbb_zvkb_zvknhb_zvl128b`: full V for Ed25519 field arithmetic,
Zvkb/Zvknhb for vector SHA-256/SHA-512, and VLEN >= 128. Feature selection is
compile-time, not runtime dispatch. Do not run that binary on a CPU missing
these extensions. The native profile selects backends from compiler macros.

The timer uses the shared `time` CSR, not per-hart cycle counts. User-mode
`rdtime` must be permitted by the kernel/firmware; platforms without it need
`FD_TICKCOUNT_STYLE=0`. `test_tickcount` checks rate and migration behavior;
`test_tempo` and `test_clock` cover calibration and clock conversion.

Run `test_sha256`, `test_sha512` and `test_ed25519` for correctness. Add
`--bench` for throughput measurements. RVV is not necessarily faster than
scalar code on every CPU. The explicit profile permits a scalar-field
comparison without disabling vector SHA-2:

```sh
make -j4 MACHINE=linux_gcc_riscv BUILDDIR=riscv-ed25519-scalar \
  FD_HAS_RISCV_ED25519=0 test_ed25519
```

Use separate build directories and matched CPU placement when comparing
backends; do not benchmark on a live validator's dedicated CPUs. The
Ed25519 switch does not remove the profile's V/vector-crypto ISA requirement.
