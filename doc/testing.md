# Testing Firedancer

## Golden Configuration

The most reliable system configuration to run tests is as follows.

- Kernel version: Linux 4.18 or newer
- Operating system: RHEL 8 or Ubuntu 22.04 (or Fedora/Debian equivalents)
- Compiler versions: GCC 12 or Clang 15
- CPU: Icelake Server or Epyc 2 (or newer)
- Memory: 2 gigantic pages (2x1 GiB) per core, reserved via `fd_shmem_cfg`.

Although we aim to support tests on a wide variety of hosts (including
architectures other than x86), the above configuration is what the
Firedancer team uses internally.  It also helps eliminate various system
noise such as page table walks, page faults, allocation failures, OOM
kills, etc.

For further info on system tuning, refer to [getting-started.md](./getting-started.md).

## Quick Start

Assuming system is configured and dependencies are installed:

```
sudo src/util/shmem/fd_shmem_cfg alloc 2 gigantic 0
make -j
make run-unit-test
```

For large page and NUMA configuration, refer to `./test.sh --help`.

## Test Configuration

### Unit Tests

**Unit tests** are C programs that contain test logic for Firedancer's
modules.  They can be found adjacent to source code in the `/src` dir
and are titled `test_{...}.c`.  Example `Local.mk` configuration:
```make
# call make-unit-test,name,         object list,dependencies
$(call make-unit-test,test_mymodule,test_module,fd_ballet fd_util)
```

**Automatic unit tests** are C programs that run without any command-line
parameters.  They may only run on the main thread and complete successfully
given 2 GiB memory (backed by any page type).  They are tested on every
commit as-is, and are run at least weekly with extended instrumentation.
Typically, they only use the main thread and complete in under 5 minutes.
Example `Local.mk` configuration:
```make
# call run-unit-test,name
$(call run-unit-test,test_mymodule)
```

### Fuzz Tests

**Fuzz tests** verify the behavior of a component given a large number
of arbitrary byte sequences.  Fuzzing is typically effective at finding
bugs in parsers.  Differential fuzz tests can detect diverging behavior
when comparing a module to a reference implementation (for example, the
virtual machine).

Fuzz tests are typically combined with sanitizers for improved error
detection.

Example `Local.mk` configuration:
```make
# call make-fuzz-test,name,         object list,  dependencies
$(call make-fuzz-test,fuzz_mymodule,fuzz_mymodule,fd_ballet fd_util)
```

In order to find new test inputs, a fuzz engine is required.

| Engine    | Compile command                                         |
|-----------|---------------------------------------------------------|
| libFuzzer | `make CC=clang EXTRAS=fuzz`                             |
| AFL++     | `make CC=clang EXTRAS=afl++ AFL_LIB=/usr/local/lib/afl` |
| Honggfuzz | `make MACHINE=linux_clang_haswell EXTRAS=honggfuzz`     |

The **[libFuzzer]** engine is part of recent versions of LLVM, making
it the most convenient way to get started. It requires Clang.

To use the **[AFL++]** engine the build is provided with the path to
the AFL++ library install dir.  This is usually `/usr/local/lib/afl`.
Look for the following output when installing AFL++.
```
$ git clone https://github.com/AFLplusplus/AFLplusplus
$ make all
...
Build Summary:
[+] afl-fuzz and supporting tools successfully built
[+] LLVM basic mode successfully built
[+] LLVM mode successfully built
[+] LLVM LTO mode successfully built
$ sudo make install
...
```

To use the **[Honggfuzz]** engine (persistent fuzzing mode with
sanitizer-coverage instrumentation), install `hfuzz-clang`.
Note that building with Honggfuzz is only supported via
`make MACHINE=linux_clang_{...} EXTRAS=honggfuzz`, but not via `make CC=hfuzz-clang`.

  [libFuzzer](https://llvm.org/docs/LibFuzzer.html)
  [AFL++](https://aflplus.plus/)
  [Honggfuzz](https://honggfuzz.dev/)

If no fuzzing engine is provided, the fuzz tests are still built with a
stub engine.  The stub engine cannot find any new inputs, but can still
regression test against old inputs like so:
```
$ build/native/gcc/fuzz-test/fuzz_bla/fuzz_bla <input1> <input2> ...
```

### Sanitizers

The codebase supports a number of **sanitizers** that bake in various
runtime checks.  Using sanitizers is not recommended for production.

Sanitizers can be combined with fuzzers.  (You can specify multiple
extras like `make EXTRAS="fuzz asan"`)

| Sanitizer                  | Compile command     |
|----------------------------|---------------------|
| AddressSanitizer           | `make EXTRAS=asan`  |
| UndefinedBehaviorSanitizer | `make EXTRAS=ubsan` |

**[AddressSanitizer]** helps detect invalid memory accesses.

**[UndefinedBehaviorSanitizer]** detects various kinds of hardware and
linguistic U.B.

  [AddressSanitizer](https://github.com/google/sanitizers/wiki/AddressSanitizer)
  [UndefinedBehaviorSanitizer](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)

## Best Practices

We try to encourage in-depth testing by ensuring that the test suite is
reliable and runs on a wide-variety of hosts.

**Determinism**: Running the same test program (with unvarying inputs)
should result in predictable behavior.  When randomness is required, the
program should use a deterministic pseudorandom number generator such as
`fd_rng_t`.  The program may allow the user to change the RNG seed or
iteration count via command-line flags.  Examples of breaking test
determinism include using the current time as a random value, or
expecting the order in which tests are executed to stay the same.

**No inputs**: Unit tests should try to support automatic configuration
to ensure they are run frequently.  Apart from aforementioned requirements,
this is achieved by bundling inputs (`FD_IMPORT_BINARY`), and being able
to run without additional command-line arguments.

**Memory management**: DO NOT CALL `MALLOC()` IN TESTS.  Instead, refer
to the instructions below to acquire memory.

**Use static variables**: If your program requires small-ish amount of
memory (e.g. 4 MiB), use `.bss` by declaring uninitialized static
variables.  This has the benefit of better support for some embedded
targets such as on-chain virtual machines.

**Memory allocation**: If a larger amount of memory is required, tests
should allocate an anon workspace from shmem given the following flags:
- `--page-sz`: Size of memory pages to request (normal/huge/gigantic)
- `--page-cnt`: Number of pages to request for given type
- `--numa-idx`: NUMA node on which memory should be allocated
- Most tests default to 1 "gigantic" page, as per our recommendation to
  use x86 1 GiB pages.
- This can be achieved with the following pattern:
  ```c
  ...
  /* setup */
  ...

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "gigantic" );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 1UL        );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx(cpu_idx) );

  FD_LOG_NOTICE(( "Creating workspace with --page-cnt %lu --page-sz %s pages on --numa-idx %lu", page_cnt, _page_sz, numa_idx ));
  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  ...
  /* tests */
  ...

  fd_wksp_delete_anonymous( wksp );
  ```
- Using `fd_scratch` over "raw" shmem pages or `static uchar[]` is also fine.
