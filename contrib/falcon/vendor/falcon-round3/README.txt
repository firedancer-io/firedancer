Falcon
======

This archive contains the following files and directories:

Reference_Implementation/
    falcon512/
        falcon512int/
            Reference implementation of Falcon with recommended
            parameters "N=512,q=12289", using NIST API (api.h).

    falcon1024/
        falcon1024int/
            Reference implementation of Falcon with recommended
            parameters "N=1024,q=12289", using NIST API (api.h).

Optimized_Implementation/
    falcon512/
        falcon512avx2/
            Optimized implementation of Falcon with recommended
            parameters "N=512,q=12289", using NIST API (api.h).
            This implementation uses AVX2 intrinsics (x86 only).

        falcon512fpu/
            Optimized implementation of Falcon with recommended
            parameters "N=512,q=12289", using NIST API (api.h).
            This implementation uses floating-point types and relies
            on the underlying hardware providing strict IEEE-754
            support with constant-time operations. It should work
            on x86, ARM, Aarch64 and POWER/PowerPC systems.

        falcon512cxm4/
            Optimized implementation of Falcon with recommended
            parameters "N=512,q=12289", using NIST API (api.h).
            This implementation uses inline assembly meant for
            the ARM Cortex M4 processor (ARMv7-M architecture).

    falcon1024/
        falcon1024avx2/
            Optimized implementation of Falcon with recommended
            parameters "N=1024,q=12289", using NIST API (api.h).
            This implementation uses AVX2 intrinsics (x86 only).

        falcon1024fpu/
            Optimized implementation of Falcon with recommended
            parameters "N=1024,q=12289", using NIST API (api.h).
            This implementation uses floating-point types and relies
            on the underlying hardware providing strict IEEE-754
            support with constant-time operations. It should work
            on x86, ARM, Aarch64 and POWER/PowerPC systems.

        falcon1024cxm4/
            Optimized implementation of Falcon with recommended
            parameters "N=1024,q=12289", using NIST API (api.h).
            This implementation uses inline assembly meant for
            the ARM Cortex M4 processor (ARMv7-M architecture).

KAT/
    generator/
        NIST-provided code to generate KAT files.

    falcon512-KAT.req
    falcon512-KAT.rsp
        KAT vectors for Falcon-512 (N = 512, q = 12289)

    falcon1024-KAT.req
    falcon1024-KAT.rsp
        KAT vectors for Falcon-1024 (N = 1024, q = 12289)

Supporting_Documentation/
    falcon.pdf
        Detailed specification of Falcon.

Extra/
    c/
        Unified C implementation; includes all the reference and
        optimized versions, with basic tests, speed benchmarks, and a
        command-line tool. This code offers an API meant for easy
        integration in applications.


Notes
=====

Each implementation under Reference_Implementation and
Optimized_Implementation has its own Makefile; when used, it compiles
the code along with the test vector generator in KAT/generator/. The
resulting binary (created in a subdirectory called "build"), when
executed, produced the .req and .rsp files, which should be identical
to the ones provided in KAT/.

The *cxm4 implementations are for the ARM Cortex M4, a CPU normally
found in microcontrollers. Cross-compilation is normally used for such
implementations. The Makefiles invoke the compiler under the name
'arm-linux-gcc' and expect that compiler to come with a minimal but
functional libc; moreover, the use of inline assembly follows the syntax
extensions supported by GCC and Clang. The Buildroot project
(https://buildroot.org/) can be used to obtain an appropriate
cross-compilation toolchain. The resulting binary can be executed under
emulation with QEMU (https://www.qemu.org/).

All other implementations assume a native C compiler which is invoked
with the command name 'c99' and flags '-W -Wall -O2'.

The implementation in "Extra/c/" has its own Makefile; it compiles into
two command-line tools, "test_falcon" and "speed". "test_falcon" runs
some self-tests. "speed" runs some benchmarks.


License
=======

This Falcon implementation is provided under the MIT license, whose text
is included at the start of every source file.
