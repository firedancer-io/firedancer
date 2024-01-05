## Firedancer Code Style Guide

### General

**Text Word Wrap**

Aspire to word wrap text (comments, not code) at 72 columns for
readability. After accounting for the indent, this is right around the
level the publishing industry has used for hundreds of years for making
print easily readable with minimal eye strain and also makes default
behaviors of various common development environments like emacs.

### Organization

See [organization.txt](./doc/organization.txt).

Please avoid cluttering the repository root.

### File Extensions

| Extension | File Type                                        |
|-----------|--------------------------------------------------|
| `.c`      | Standalone C translation unit                    |
| `.h`      | Reusable C include file, no symbol defs (header) |
| `.c`      | Include-once C file, with symbol defs            |
| `.s`      | Assembly files                                   |
| (none)    | Shell scripts                                    |

### Integer Types

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

### Function Argument Lists

- Spaces inside brackets
- Spaces after commas

```c
fd_wksp_pod_map( verify_pod, "fseq" )
```

### Function Documentation

- Documentation for a function is typically before the function
  prototype in a comment block to help with potential automated
  documentation extraction ala Doxygen.
- Such comments should try to mention the name of the function they are
  toward the beginning of the comment to eliminate ambiguity. E.g. no
  confusion from devs from environments where comments chase the
  prototype.
- Functions in a prototype should have very detailed comments.
- Implementations of these functions do not need to repeat the comment.
- Functions that are not public (e.g. static function in an
  implementation source code file) are nice to document like this, but
  this is more aspirational.  (Depends on code maturity, complexity, etc.)

```
/* fd_rng_seq_set sets the sequence to be used by rng and returns
   the replaced value.  fd_rng_idx_set sets the next slot that will be
   consumed next by rng and returns the replaced value. */
```

### Function Declarations

- Modifiers and return types on separate lines
- One function argument per line
- Vertically align function argument types and names

```c
static inline uint
fd_rng_seq_set( fd_rng_t * rng,
                uint       seq );
```

### Code Documentation

Some elaborations re code documentation are within https://github.com/firedancer-io/firedancer/pull/302#issuecomment-1530810227
