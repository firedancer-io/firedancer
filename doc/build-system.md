Build System
============

This page explains the philosophy and technical details of the
build system and source code management in Firedancer.

Users are strongly encouraged to build Firedancer from source instead
of downloading compiled binaries.  The build system therefore has a
particular focus on simplicity and robustness.  In summary, it should
be trivial to build Firedancer on a fresh installation of an arbitrary
GNU/Linux distribution.

Build process
-------------

The project uses the build process of a typical statically linked
C application for Linux.

The figure below describes the transformation of source code into
release artifacts.

```
┌────────────┐
│   C        │  cc
│  sources   ├─────────────┬──────────────────────────────────────────┐
└────────────┘             │                                          │ cc
                           │                                          │
┌────────────┐       ┌─────▼─────┐       ┌─────────────┐       ┌──────▼───────┐
│  Assembly  │  as   │  Static   │  ar   │   Static    │  cc   │  Executable  │
│  sources   ├───────►  Objects  ├───────►  Libraries  ├───────►   Binaries   │
└────────────┘       └─────▲─────┘       └─────────────┘       │              │
                           │                                   │   Shared     │
┌────────────┐             │                                   │   Objects    │
│ Generated  │  cc         │                                   └──────▲───────┘
│   C code   ├─────────────┤                                          │
└────────────┘             │                                          │ cc
                           │                                          │
┌────────────┐             │                                   ┌──────┴───────┐
│  Embedded  │  cc         │                                   │  External    │
│   files    ├─────────────┘                                   │  Static      │
└────────────┘                                                 │  Libraries   │
                                                               └──────────────┘
```

### Compile Units

A compile unit is a set of C/C++ files, assembly files, and embedded
files.  Each compile unit gets compiled into a static object by
invoking the GCC or Clang frontend.

On Linux, compile units are position-independent to support ASLR.

Compile units define at least one externally linked symbol for use
in other Firedancer compile units.

Embedded files are arbitrary binary content included via the `.incbin`
assembler directive.  (See `FD_IMPORT_BINARY`)  Used for vendoring
eBPF programs and large text files (e.g. command-line help text).

### System Dependencies

Firedancer depends on the GNU C Library (glibc) and the C++ standard library.
Both are linked dynamically.

```
$ ldd build/native/gcc/bin/fdctl
        linux-vdso.so.1 (0x00007ffce652e000)
        librt.so.1 => /lib64/librt.so.1 (0x00007f0d0398c000)
        libdl.so.2 => /lib64/libdl.so.2 (0x00007f0d03788000)
        libstdc++.so.6 => /lib64/libstdc++.so.6 (0x00007f0d033f3000)
        libm.so.6 => /lib64/libm.so.6 (0x00007f0d03071000)
        libgcc_s.so.1 => /lib64/libgcc_s.so.1 (0x00007f0d02e59000)
        libpthread.so.0 => /lib64/libpthread.so.0 (0x00007f0d02c39000)
        libc.so.6 => /lib64/libc.so.6 (0x00007f0d02874000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f0d097e0000)
```

### ABI stability

Firedancer does not aim to be ABI-stable, with a few exceptions.
This means that symbols may change or disappear arbitrarily between
different versions of the source code.

The parts of the project written in C try to achieve cross-compiler
stability.  It should be fine to link together units compiled with
different versions of GCC, or even a mix of GCC and Clang (as long
as all originate from the same revision of Firedancer).

Some small parts of Firedancer explicitly offer a stable ABI for use
as a shared library.  The shared library includes the cross-client
compatibility layer and a target for differential fuzzing.

### Code Generation

Generated code is checked into the repository.
This minimizes the tooling dependencies by only requiring the code
generation tools during development.

All tools used generate C code for Firedancer are currently written
in Python 3.9.

### Out-of-tree Dependencies

Firedancer aims to have zero out-of-tree library dependencies.
We are not quite there yet.  For reasons of practicality, some large
external dependencies are fetched externally.

The `deps.sh` script fetches and builds those dependencies (using the
dependency's build script).  It then installs includes and static
libraries into a custom prefix (the `opt` directory).

The compiler discovers those via `-isystem ./opt/include -L./opt/lib`.
(No need for pkg-config or overcomplicated configure scripts)

Make configuration
------------------

GNU Make serves to automate the build process as described above.

### Summary

The Firedancer Makefile goes through the following steps each time
it is evaluated.

1. Generate compiler and linker configuration for selected machine target
2. Compiler checks
3. Discover available build targets
4. Execute build rules until selected targets are met

### Machine targets

The `config/machine` directory defines a variety of machine types
which can be selected via the `MACHINE` variable.
