# GitHub Copilot Instructions for Firedancer

## Project Overview

Firedancer is a high-performance validator client for Solana, written from scratch in C for speed, security, and independence. The project emphasizes low-latency design patterns from the trading industry and maintains strict coding standards.

## Code Style and Standards

### Language and Types
- Use C17 standard with permitted GNU C extensions (compatible with Clang and CBMC)
- Use custom integer types from `fd_util_base.h` instead of `stdint.h`:
  - `uchar`, `schar` instead of `uint8_t`, `int8_t`
  - `ushort`, `short` instead of `uint16_t`, `int16_t`
  - `uint`, `int` instead of `uint32_t`, `int32_t`
  - `ulong`, `long` instead of `uint64_t`, `int64_t`, `size_t`, `ptrdiff_t`
- Use `int` for booleans, not `bool` (`1` for true, `0` for false)

### Formatting
- Wrap comments at 72 columns for readability
- Use vertical alignment for better readability in variable declarations and defines
- Function prototypes: modifiers and return types on separate lines, one argument per line
- Vertically align function argument types and names

### Spacing
- Function calls with arguments: spaces inside brackets, no space before brackets
  - Example: `printf( "Hello %s\n", "World" );`
  - Exception: no spaces with `sizeof`: `sizeof(fd_rng_t)`
- Control flow: spaces in brackets, no spaces before brackets
  - Example: `if( c==1 ) c = 2;`
- Single-line if statements: no braces required
- Multi-line branches: braces are mandatory

### Include Guards
Use `ifndef` include guards, not `#pragma once`:
```c
#ifndef HEADER_fd_src_path_to_file_fd_file_name_h
#define HEADER_fd_src_path_to_file_fd_file_name_h
...
#endif /* HEADER_fd_path_to_file_fd_file_name_h */
```

### Macros
- Enclose arguments in parentheses (to ensure proper operator precedence)
- Enclose macro bodies in `do/while(0)` scopes (use braces `{}` for statement blocks)
- Only evaluate macro arguments once

Example:
```c
#define wwl_abs(x) _mm512_abs_epi64( (x) )  /* good - parentheses around argument */
```

### Error Handling
- Annotate uncommon error paths with `FD_UNLIKELY`
- Use graceful error handling instead of aborting/crashing
- For complex control flow with cleanup, use `do/while` scopes or cleanup attributes

## Build System

### Building and Testing
```bash
# Build (no output implies success)
make -j 2>&1 | grep error:

# Build with Clang
make CC=clang

# Build libFuzzer harnesses
make BUILDDIR=clang-fuzz CC=clang EXTRAS=fuzz

# Build with fuzzing and ASan
make BUILDDIR=clang-fuzz-asan CC=clang EXTRAS="fuzz asan"

# Run unit tests
build/native/gcc/unit-test/<test_name>

# Run binaries directly
build/native/gcc/bin/<bin_name>
```

## Development

### File Organization
- See `doc/organization.txt` for structure
- Avoid cluttering repository root
- File extensions:
  - `.c`: Standalone C translation unit or include-once C file with symbol definitions
  - `.h`: Reusable C include file, no symbol definitions (header)
  - `.s`: Assembly files
  - (none): Shell scripts

### Security
- Most code should be covered by fuzz tests
- Use `fd_io` over `stdio.h` for streaming file I/O
- Handle `EINTR` correctly in I/O operations
- Firedancer runs with strict seccomp profiles limiting syscalls
- Note: glibc often uses different syscall names than libc wrappers would imply; always lean on existing seccomp profiles that can be assumed to work

## Testing

- Conformance tests against Agave validator in CI
- Test vectors in separate repository: https://github.com/firedancer-io/test-vectors
- To add new test vectors:
  1. PR to test-vectors repository with fixtures
  2. Update `contrib/test/test-vectors-fixtures/test-vectors-commit-sha.txt` with commit SHA
- Run unit tests: `build/native/gcc/unit-test/<test_name>`

## Documentation

Function documentation goes before the function prototype in a comment block, mentioning the function name near the beginning. Public API functions must be documented. Don't repeat documentation in implementation.

Example:
```c
/* fd_rng_seq_set sets the sequence to be used by rng and returns
   the replaced value. */

static inline uint
fd_rng_seq_set( fd_rng_t * rng,
                uint       seq );
```

## Project Structure

- `src/`: Main source code organized by component
  - `src/tango/`: Core concurrency model (defines code style)
  - `src/ballet/`: Cryptographic primitives
  - `src/disco/`: Distributed system components
  - `src/waltz/`: Network stack
  - `src/flamenco/`: Solana runtime implementation
  - `src/util/`: Utility libraries
- `contrib/`: Contributed tools and scripts
- `config/`: Build configuration
- `doc/`: Documentation

## Key Principles

1. **Performance First**: Low-latency design patterns, minimal allocations
2. **Security**: Strict sandboxing, minimal syscalls, extensive fuzzing
3. **Independence**: No dependencies on Agave code (for full Firedancer build)
4. **Readability**: Consistent style, vertical alignment, clear documentation

## Additional Resources

- Contributing Guide: `CONTRIBUTING.md`
- Security Policy: `SECURITY.md`
- Documentation: `book/` directory (source for docs.firedancer.io)
- Code organization: `doc/organization.txt`
