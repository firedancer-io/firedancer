## Firedancer Code Style Guide

Below is an incomplete list of code style rules.

This document is not authoritative.  The code style is defined by the
code in `src/tango`.

Most contributors do not use a code formatting tool.

### 1. General

#### 1.1. Text Word Wrap

Aspire to word wrap text (comments, not code) at 72 columns for
readability. After accounting for the indent, this is right around the
level the publishing industry has used for hundreds of years for making
print easily readable with minimal eye strain and also makes default
behaviors of various common development environments like emacs.

#### 1.2. Organization

See [organization.txt](./doc/organization.txt).

Please avoid cluttering the repository root.

#### 1.3. File Extensions

| Extension | File Type                                        |
|-----------|--------------------------------------------------|
| `.c`      | Standalone C translation unit                    |
| `.h`      | Reusable C include file, no symbol defs (header) |
| `.c`      | Include-once C file, with symbol defs            |
| `.s`      | Assembly files                                   |
| (none)    | Shell scripts                                    |

#### 1.4. Include Guards

Header files that are intended to be included by other compile units
should use an ifndef include guard.

Given file: `src/path/to/file/fd_file_name.h`:

```c
/* good */

#ifndef HEADER_fd_src_path_to_file_fd_file_name_h
#define HEADER_fd_src_path_to_file_fd_file_name_h

...

#endif /* HEADER_fd_path_to_file_fd_file_name_h */

/* WRONG! */

#pragma once
```

### 2. Vertical Alignment

Popular code formatting tools would produce code like this.
This sort of code is discouraged in Firedancer.

```c
#define FD_FOO_SUCCESS (0)
#define FD_FOO_ERR_PROTO (1)
#define FD_FOO_ERR_IO (20)

void
foo( void ) {
  char const * _init = fd_env_strip_cmdline_cstr( &argc, &argv, "--init", NULL, NULL );
  uint seed = fd_env_strip_cmdline_uint( &argc, &argv, "--seed", NULL, (uint)fd_tickcount() );
  int lazy = fd_env_strip_cmdline_int( &argc, &argv, "--lazy", NULL, 7 );
}
```

Instead, use vertical alignment for better readability:

```c
#define FD_FOO_SUCCESS    (0)
#define FD_FOO_ERR_PROTO  (1)
#define FD_FOO_ERR_IO    (20)

void
foo( void ) {
  char const * _init = fd_env_strip_cmdline_cstr( &argc, &argv, "--init", NULL, NULL                 );
  uint         seed  = fd_env_strip_cmdline_uint( &argc, &argv, "--seed", NULL, (uint)fd_tickcount() );
  int          lazy  = fd_env_strip_cmdline_int ( &argc, &argv, "--lazy", NULL, 7                    );
}
```

### 3. Spacing Rules

#### 3.1. Function Calls

No spaces for function calls with zero arguments:

```c
abort();   /* good */

abort( );  /* WRONG! */
abort ();  /* WRONG! */
```

For function calls with arguments, spaces inside brackets.
No space before brackets.

```c
printf( "Hello %s\n", "World" );  /* good */

printf ( "Hello" );  /* WRONG! */
printf("Hello");     /* WRONG! */
```

Exception: Usually, no spaces with `sizeof`:

```c
memcpy( dst, src, sizeof(fd_rng_t) );  /* good */

memcpy( dst, src, sizeof( fd_rng_t ) );  /* WRONG! */
```

Exception: No spaces between double bracket macros:

```c
FD_LOG_NOTICE(( "pass" ));  /* good */

FD_LOG_NOTICE( ( "pass" ) );  /* WRONG! */
```

#### 3.2. Control Flow

Annotate uncommon error paths with `FD_UNLIKELY`.

For single-line if statements, no braces required:

```c
if( FD_UNLIKELY( do_crash ) ) abort();
```

Spaces in brackets.  No spaces before brackets.

```c
if( c==1 ) c = 2;  /* good */

if (c==1) c = 2;    /* WRONG! */
if ( c==1 ) c = 2;  /* WRONG! */
if( c==1) c = 2;    /* VERY WRONG! */
```

If a branch goes on a separate line, braces are mandatory:

```c
/* good */
if( FD_UNLIKELY( status!=3 ) ) {
  FD_LOG_CRIT(( "Critical error, aborting" ));
}

/* WRONG! */
if( FD_UNLIKELY( status!=3 ) )
  FD_LOG_CRIT(( "Critical error, aborting" ));
```

#### 3.3. Function Prototypes

- Modifiers and return types on separate lines
- One function argument per line
- Vertically align function argument types and names

```c
/* good */
static inline uint
fd_rng_seq_set( fd_rng_t * rng,
                uint       seq );

/* WRONG! */
static inline uint fd_rng_seq_set( fd_rng_t * rng, uint seq );
```

### 4. Type System

#### 4.1. Integers

Use `fd_util_base.h` types instead of `stdint.h` integer types.

FAQ: Why not `stdint.h`? For more information, see
- [`fd_util_base.h`](./src/util/fd_util_base.h)
- [Kevin's rant](./doc/rant/integer-types.md)

**Mapping**

| stdint      | fd_util_base |
|-------------|--------------|
| `int8_t`    | `schar`      |
| `uint8_t`   | `uchar`      |
| `int16_t`   | `short`      |
| `uint16_t`  | `ushort`     |
| `int32_t`   | `int`        |
| `uint32_t`  | `uint`       |
| `int64_t`   | `long`       |
| `ptrdiff_t` | `long`       |
| `uint64_t`  | `ulong`      |
| `size_t`    | `ulong`      |

#### 4.2. Bools

Do not use `bool` (stdbool).  Instead use `int`.

The value `1` is "true" and the value `0` is "false".

```
int is_working = 1;
if( is_working ) { ... }
```

### 5. Function Documentation

- Documentation for a function is typically before the function
  prototype in a comment block to help with potential automated
  documentation extraction ala Doxygen.
- Such comments should try to mention the name of the function they are
  toward the beginning of the comment to eliminate ambiguity. E.g. no
  confusion from devs from environments where comments chase the
  prototype.
- Function declarations belonging to a public API must be documented
- Implementations of these functions must not repeat the comment.
- Functions that are not public (e.g. static function in an
  implementation source code file) are nice to document like this, but
  this is more aspirational.  (Depends on code maturity, complexity, etc.)

```c
/* fd_rng_seq_set sets the sequence to be used by rng and returns
   the replaced value.  fd_rng_idx_set sets the next slot that will be
   consumed next by rng and returns the replaced value. */

static inline uint
fd_rng_seq_set( fd_rng_t * rng,
                uint       seq );
```

Rant about our documentation style: https://github.com/firedancer-io/firedancer/pull/302#issuecomment-1530810227

### 6. Macros

Note: These are recommendations.  Depending on macro scope, these rules
might not make sense.

Enclose arguments in braces:

```c
#define wwl_abs(x) _mm512_abs_epi64( (x) )  /* good */

#define wwl_abs(x) _mm512_abs_epi64( x )  /* WRONG! */
```

Enclose macro bodies in do/while(0) scopes:

```c
/* good */
#define FD_R43X6_SQR2_INL( za,xa, zb,xb ) \
  do {                                    \
    (za) = fd_r43x6_sqr( (xa) );          \
    (zb) = fd_r43x6_sqr( (xb) );          \
  } while(0)

/* WRONG! */
#define FD_R43X6_SQR2_INL( za,xa, zb,xb ) \
  (za) = fd_r43x6_sqr( (xa) );            \
  (zb) = fd_r43x6_sqr( (xb) );
```

Only evaluate macro arguments once:

```c
/* good */
#define TRAP(x)               \
  do {                        \
    int _cnt = (x);           \
    if( _cnt<0 ) return _cnt; \
    cnt += _cnt;              \
  } while(0)

/* WRONG! */
#define TRAP(x)             \
  do {                      \
    if( (x)<0 ) return (x); \
    cnt += (x);             \
  } while(0)

/* Note: A user might do this */
TRAP( ++y );
```

### 7. Portability

#### 7.1. Build capabilities

Generally, Firedancer aspires to compile fine under any LP64
environment.  If any component has more assumptions (e.g. needs a POSIX
like target), it should check for these capabilities via the
`FD_HAS_{...}` switches.

Example Makefile:

```makefile
ifdef FD_HAS_HOSTED
$(call add-objs,fd_numa,fd_util)
endif
```

Example C code:

```c
#if FD_HAS_HOSTED

...

#endif /* FD_HAS_HOSTED */
```

Example

#### 7.2. Language features

Try to stick to ISO C17.  GNU C extensions are permitted as long as they
are well supported by Clang and CBMC many years back.

#### 7.3. Compiler compatibility

As of 2024-Jul, Firedancer builds on GNU/Linux sysroots with GCC 8.5 or
newer.  Clang and CBMC are also supported build environments.

The "Frankendancer" build target (fdctl) only targets x86_64 with a
Haswell like minimum feature set (AVX2, FMA).

Experimental support exists for the following targets:
- musl Linux, macOS, FreeBSD, Solana (SVM) C programs
- arm64, ppc64le, sBPFv1, sBPFv2

#### 7.4. seccomp

Firedancer uses a strict sandbox architecture on Linux platforms using
seccomp.  During initialization, a seccomp profile is installed to each
tile containing rules for allowed syscalls.

Be mindful of what syscalls glibc could use under the hood when using
standard library APIs.  Note that the syscalls used can differ between
different glibc versions.

If a syscall is triggered unexpectedly, seccomp will crash Firedancer.

#### 7.5. File I/O

Prefer `fd_io` over `stdio.h` for streaming file I/O.

Make sure to handle `EINTR` correctly.

### 8. Security

#### 8.1. Fuzzing

Most code should be covered by fuzz tests.

Try to:
- Use graceful error handling instead of aborting/crashing/exiting even
  when that is the only reasonable behavior from an app pov.
- Provide test APIs for mocking state.  (e.g. encryption keys when
  fuzzing a network protocol)

#### 8.2. Complex Function Exit

Sometimes complex control flow is unavoidable.

A typical error is failure to release resources on variables that go
out of scope.

```c
...
if( fail1 ) {
  cleanup();
  return;
}
... 800 lines later ...
if( fail2 ) {
  return;  /* we forgot to call cleanup() !!! */
}
...
cleanup();
return;
```

Instead, you could use a `do/while` scope like so:

```c
...
do {
  if( fail1 ) break;
  ...
  if( fail2 ) break;
  ...
} while(0);

cleanup();
return;
```

In egregious cases, you may use the `cleanup` attribute to execute an
inline function when a variable goes out of scope.

```c
static inline void
release_lock( int * lock ) {
  ...
}

void
my_func( void ) {
  ...
  int my_lock __attribute__((cleanup(release_lock))) = acquire_lock();
  ...
  if( fail1 ) return;  /* calls release_lock when returning */
  ...
  /* calls release_lock when going out of scope */
}
```

To improve readability, wrap the cleanup attribute in macros like so:
See `FD_SCRATCH_SCOPE_BEGIN` in `src/util/scratch/fd_scratch.h`.

```c
int my_lock;
FD_MY_LOCK_BEGIN(my_lock) {
  if( fail1 ) return;  /* releases lock */
  if( fail2 ) break;   /* releases lock */
  ...
  /* releases lock */
}
FD_MY_LOCK_END;
```
