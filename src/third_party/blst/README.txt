This directory contains a subset of the blst library at
https://github.com/supranational/blst

Files are copied exactly from tag v0.3.13, with no Firedancer
specific modifications.  Do not edit vendored files locally; update
by re-running `vendor.sh` against a new pinned tag.

The build mirrors upstream build.sh: exactly two objects,
src/server.c (a unity build #including every other .c) and
build/assembly.S (which #includes the pre-generated per-arch .s
bodies from build/elf/ at preprocess time).  The src/asm/*.pl
perlasm generators that produce build/elf/ are not imported; the
checked-in .s files are upstream's own pre-generated output, the
same ones build.sh consumes.

On x86-64 Firedancer compiles with -D__BLST_PORTABLE__: both the
ADX (mulx/adcx/adox) and portable asm bodies are assembled and
selected at runtime via cpuid (__blst_platform_cap).  Upstream's
build.sh instead bakes -D__ADX__ from the build host's /proc/cpuinfo
into the artifact; portable dispatch is safer for binaries deployed
to heterogeneous CPUs at ~2x asm footprint.  On aarch64 assembly.S
selects the armv8 bodies (build/elf/*-armv8.S); there is no variant
dispatch.  -fno-builtin is required: without it the compiler
pattern-matches blst's constant-time memory routines into libc
memcpy/memset calls, silently breaking constant-time guarantees.

For licensing information (Apache-2.0), see LICENSE in this
directory and NOTICE in the root of this repo.
