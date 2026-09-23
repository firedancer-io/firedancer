# Experimental Linux RV64 port

Firedancer's supported target remains x86-64 Linux. This port is experimental:
passing tests or following testnet does not establish complete correctness
under RVWMO. Do not treat it as production validator support.

Build with an explicit machine profile:

```sh
make -j4 MACHINE=linux_gcc_riscv firedancer-dev
```

The baseline profile targets RV64GC. It enables the Linux RV64 seccomp audit
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
