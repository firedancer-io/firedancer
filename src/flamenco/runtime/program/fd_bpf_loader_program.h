#ifndef HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_program_h
#define HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_program_h

/* fd_bpf_loader_v3_program.h is the third version of the BPF loader
   program.

   Address: BPFLoaderUpgradeab1e11111111111111111111111 */

#include "../../progcache/fd_progcache_rec.h"
#include "../../features/fd_features.h"
#include "../../types/fd_types.h"
#include "../../../funk/fd_funk_base.h"

/* https://github.com/anza-xyz/agave/blob/77daab497df191ef485a7ad36ed291c1874596e5/programs/bpf_loader/src/lib.rs#L67-L69 */
#define DEFAULT_LOADER_COMPUTE_UNITS     (570UL )
#define DEPRECATED_LOADER_COMPUTE_UNITS  (1140UL)
#define UPGRADEABLE_LOADER_COMPUTE_UNITS (2370UL)

/* https://github.com/anza-xyz/agave/blob/77daab497df191ef485a7ad36ed291c1874596e5/sdk/program/src/bpf_loader_upgradeable.rs#L29-L120 */
#define SIZE_OF_PROGRAM                  (36UL  ) /* UpgradeableLoaderState::size_of_program() */
#define BUFFER_METADATA_SIZE             (37UL  ) /* UpgradeableLoaderState::size_of_buffer_metadata() */
#define PROGRAMDATA_METADATA_SIZE        (45UL  ) /* UpgradeableLoaderState::size_of_programdata_metadata() */
#define SIZE_OF_UNINITIALIZED            (4UL   ) /* UpgradeableLoaderState::size_of_uninitialized() */

/* InstructionError conversions
   https://github.com/anza-xyz/agave/blob/ced98f1ebe73f7e9691308afa757323003ff744f/sdk/program/src/program_error.rs#L127-L160 */
#define BUILTIN_BIT_SHIFT                           (32UL)

#define CUSTOM_ZERO                                 ((1UL)  << BUILTIN_BIT_SHIFT)
#define INVALID_ARGUMENT                            ((2UL)  << BUILTIN_BIT_SHIFT)
#define INVALID_INSTRUCTION_DATA                    ((3UL)  << BUILTIN_BIT_SHIFT)
#define INVALID_ACCOUNT_DATA                        ((4UL)  << BUILTIN_BIT_SHIFT)
#define ACCOUNT_DATA_TOO_SMALL                      ((5UL)  << BUILTIN_BIT_SHIFT)
#define INSUFFICIENT_FUNDS                          ((6UL)  << BUILTIN_BIT_SHIFT)
#define INCORRECT_PROGRAM_ID                        ((7UL)  << BUILTIN_BIT_SHIFT)
#define MISSING_REQUIRED_SIGNATURES                 ((8UL)  << BUILTIN_BIT_SHIFT)
#define ACCOUNT_ALREADY_INITIALIZED                 ((9UL)  << BUILTIN_BIT_SHIFT)
#define UNINITIALIZED_ACCOUNT                       ((10UL) << BUILTIN_BIT_SHIFT)
#define NOT_ENOUGH_ACCOUNT_KEYS                     ((11UL) << BUILTIN_BIT_SHIFT)
#define ACCOUNT_BORROW_FAILED                       ((12UL) << BUILTIN_BIT_SHIFT)
#define MAX_SEED_LENGTH_EXCEEDED                    ((13UL) << BUILTIN_BIT_SHIFT)
#define INVALID_SEEDS                               ((14UL) << BUILTIN_BIT_SHIFT)
#define BORSH_IO_ERROR                              ((15UL) << BUILTIN_BIT_SHIFT)
#define ACCOUNT_NOT_RENT_EXEMPT                     ((16UL) << BUILTIN_BIT_SHIFT)
#define UNSUPPORTED_SYSVAR                          ((17UL) << BUILTIN_BIT_SHIFT)
#define ILLEGAL_OWNER                               ((18UL) << BUILTIN_BIT_SHIFT)
#define MAX_ACCOUNTS_DATA_ALLOCATIONS_EXCEEDED      ((19UL) << BUILTIN_BIT_SHIFT)
#define INVALID_ACCOUNT_DATA_REALLOC                ((20UL) << BUILTIN_BIT_SHIFT)
#define MAX_INSTRUCTION_TRACE_LENGTH_EXCEEDED       ((21UL) << BUILTIN_BIT_SHIFT)
#define BUILTIN_PROGRAMS_MUST_CONSUME_COMPUTE_UNITS ((22UL) << BUILTIN_BIT_SHIFT)
#define INVALID_ACCOUNT_OWNER                       ((23UL) << BUILTIN_BIT_SHIFT)
#define ARITHMETIC_OVERFLOW                         ((24UL) << BUILTIN_BIT_SHIFT)
#define IMMUTABLE                                   ((25UL) << BUILTIN_BIT_SHIFT)
#define INCORRECT_AUTHORITY                         ((26UL) << BUILTIN_BIT_SHIFT)

/* UpgradeableLoaderInstruction wire format (u32 discriminant).

   https://github.com/anza-xyz/agave/blob/v2.2.6/sdk/program/src/bpf_loader_upgradeable.rs */

#define FD_BPF_INSTR_INITIALIZE_BUFFER        (0U)
#define FD_BPF_INSTR_WRITE                    (1U)
#define FD_BPF_INSTR_DEPLOY_WITH_MAX_DATA_LEN (2U)
#define FD_BPF_INSTR_UPGRADE                  (3U)
#define FD_BPF_INSTR_SET_AUTHORITY            (4U)
#define FD_BPF_INSTR_CLOSE                    (5U)
#define FD_BPF_INSTR_EXTEND_PROGRAM           (6U)
#define FD_BPF_INSTR_SET_AUTHORITY_CHECKED    (7U)
#define FD_BPF_INSTR_MIGRATE                  (8U)
#define FD_BPF_INSTR_EXTEND_PROGRAM_CHECKED   (9U)

/* Per-variant payload structs.

   The `write` variant uses zero-copy for its `bytes` field: after a
   successful decode `bytes` points directly into the caller-owned
   instruction buffer, and the caller must keep that buffer alive for
   the lifetime of the decoded struct. */

struct fd_bpf_instruction_write {
  uint          offset;
  uchar const * bytes;
  ulong         bytes_len;
};
typedef struct fd_bpf_instruction_write fd_bpf_instruction_write_t;

struct fd_bpf_instruction_deploy_with_max_data_len {
  ulong max_data_len;
};
typedef struct fd_bpf_instruction_deploy_with_max_data_len fd_bpf_instruction_deploy_with_max_data_len_t;

struct fd_bpf_instruction_extend_program {
  uint additional_bytes;
};
typedef struct fd_bpf_instruction_extend_program fd_bpf_instruction_extend_program_t;

struct fd_bpf_instruction_extend_program_checked {
  uint additional_bytes;
};
typedef struct fd_bpf_instruction_extend_program_checked fd_bpf_instruction_extend_program_checked_t;

union fd_bpf_instruction_inner {
  fd_bpf_instruction_write_t                    write;
  fd_bpf_instruction_deploy_with_max_data_len_t deploy_with_max_data_len;
  fd_bpf_instruction_extend_program_t           extend_program;
  fd_bpf_instruction_extend_program_checked_t   extend_program_checked;
};
typedef union fd_bpf_instruction_inner fd_bpf_instruction_inner_t;

struct fd_bpf_instruction {
  uint                       discriminant;
  fd_bpf_instruction_inner_t inner;
};
typedef struct fd_bpf_instruction fd_bpf_instruction_t;

/* UpgradeableLoaderState wire format (u32 discriminant).

   https://github.com/anza-xyz/agave/blob/v2.2.6/sdk/program/src/bpf_loader_upgradeable.rs */

#define FD_BPF_STATE_UNINITIALIZED (0U)
#define FD_BPF_STATE_BUFFER        (1U)
#define FD_BPF_STATE_PROGRAM       (2U)
#define FD_BPF_STATE_PROGRAM_DATA  (3U)

/* State struct field layout MUST be preserved: callers initialize and
   read these fields by name (e.g. `state.inner.buffer.has_authority_address`,
   `state.inner.program.programdata_address`, etc). */

struct fd_bpf_state_buffer {
  fd_pubkey_t authority_address;
  uchar       has_authority_address;
};
typedef struct fd_bpf_state_buffer fd_bpf_state_buffer_t;

struct fd_bpf_state_program {
  fd_pubkey_t programdata_address;
};
typedef struct fd_bpf_state_program fd_bpf_state_program_t;

struct fd_bpf_state_program_data {
  ulong       slot;
  fd_pubkey_t upgrade_authority_address;
  uchar       has_upgrade_authority_address;
};
typedef struct fd_bpf_state_program_data fd_bpf_state_program_data_t;

union fd_bpf_state_inner {
  fd_bpf_state_buffer_t       buffer;
  fd_bpf_state_program_t      program;
  fd_bpf_state_program_data_t program_data;
};
typedef union fd_bpf_state_inner fd_bpf_state_inner_t;

struct fd_bpf_state {
  uint                 discriminant;
  fd_bpf_state_inner_t inner;
};
typedef struct fd_bpf_state fd_bpf_state_t;

/* fd_bpf_upgradeable_loader_state_is_* helpers mirror the (now-removed)
   generated bincode helpers so existing call sites keep working. */

static inline uchar
fd_bpf_state_is_uninitialized( fd_bpf_state_t const * self ) {
  return (uchar)( self->discriminant==FD_BPF_STATE_UNINITIALIZED );
}

static inline uchar
fd_bpf_state_is_buffer( fd_bpf_state_t const * self ) {
  return (uchar)( self->discriminant==FD_BPF_STATE_BUFFER );
}

static inline uchar
fd_bpf_state_is_program( fd_bpf_state_t const * self ) {
  return (uchar)( self->discriminant==FD_BPF_STATE_PROGRAM );
}

static inline uchar
fd_bpf_state_is_program_data( fd_bpf_state_t const * self ) {
  return (uchar)( self->discriminant==FD_BPF_STATE_PROGRAM_DATA );
}

/* fd_bpf_upgradeable_loader_program_instruction_decode parses a
   bincode-encoded UpgradeableLoaderInstruction from [data, data+data_sz).
   Variable-length fields (`write.bytes`) point directly into `data`, so
   callers must keep that buffer alive.  Trailing bytes beyond the parsed
   region are accepted (matches Agave's default `allow_trailing_bytes()`).
   Returns 0 on success, -1 on malformed input. */

static inline int
fd_bpf_instruction_decode( fd_bpf_instruction_t * out,
                           uchar const *          data,
                           ulong                  data_sz ) {
  uchar const * _payload    = data;
  ulong const   _payload_sz = data_sz;
  ulong         _i          = 0UL;

# define CHECK( cond )   { if( FD_UNLIKELY( !(cond) ) ) { return -1; } }
# define CHECK_LEFT( n ) CHECK( (n)<=(_payload_sz-_i) )
# define INC( n )        (_i += (ulong)(n))
# define CURSOR          (_payload+_i)

  CHECK_LEFT( 4UL );
  uint disc = FD_LOAD( uint, CURSOR ); INC( 4UL );
  out->discriminant = disc;

  switch( disc ) {

  case FD_BPF_INSTR_WRITE: {
    fd_bpf_instruction_write_t * w = &out->inner.write;
    CHECK_LEFT( 4UL ); w->offset    = FD_LOAD( uint,  CURSOR ); INC( 4UL );
    CHECK_LEFT( 8UL ); w->bytes_len = FD_LOAD( ulong, CURSOR ); INC( 8UL );
    CHECK_LEFT( w->bytes_len );
    w->bytes = w->bytes_len ? CURSOR : NULL;
    INC( w->bytes_len );
    return 0;
  }

  case FD_BPF_INSTR_DEPLOY_WITH_MAX_DATA_LEN: {
    fd_bpf_instruction_deploy_with_max_data_len_t * d = &out->inner.deploy_with_max_data_len;
    CHECK_LEFT( 8UL );
    d->max_data_len = FD_LOAD( ulong, CURSOR ); INC( 8UL );
    return 0;
  }

  case FD_BPF_INSTR_EXTEND_PROGRAM: {
    fd_bpf_instruction_extend_program_t * e = &out->inner.extend_program;
    CHECK_LEFT( 4UL );
    e->additional_bytes = FD_LOAD( uint, CURSOR ); INC( 4UL );
    return 0;
  }

  case FD_BPF_INSTR_EXTEND_PROGRAM_CHECKED: {
    fd_bpf_instruction_extend_program_checked_t * e = &out->inner.extend_program_checked;
    CHECK_LEFT( 4UL );
    e->additional_bytes = FD_LOAD( uint, CURSOR ); INC( 4UL );
    return 0;
  }

  case FD_BPF_INSTR_INITIALIZE_BUFFER:
  case FD_BPF_INSTR_UPGRADE:
  case FD_BPF_INSTR_SET_AUTHORITY:
  case FD_BPF_INSTR_CLOSE:
  case FD_BPF_INSTR_SET_AUTHORITY_CHECKED:
  case FD_BPF_INSTR_MIGRATE:
    return 0;

  default: return -1;
  }

# undef CHECK
# undef CHECK_LEFT
# undef INC
# undef CURSOR
}

/* fd_bpf_upgradeable_loader_program_instruction_encode serializes an
   UpgradeableLoaderInstruction into [buf, buf+bufsz).  On success stores
   the number of bytes written to *out_sz and returns 0.  Returns -1 on
   short buffer or unknown discriminant. */

static inline int
fd_bpf_instruction_encode( fd_bpf_instruction_t const * in,
                           uchar *                      buf,
                           ulong                        bufsz,
                           ulong *                      out_sz ) {
  uchar * const _payload    = buf;
  ulong const   _payload_sz = bufsz;
  ulong         _i          = 0UL;

# define CHECK_LEFT( n ) { if( FD_UNLIKELY( (n)>(_payload_sz-_i) ) ) { return -1; } }
# define INC( n )        (_i += (ulong)(n))
# define CURSOR          (_payload+_i)

  CHECK_LEFT( 4UL ); FD_STORE( uint, CURSOR, in->discriminant ); INC( 4UL );

  switch( in->discriminant ) {

  case FD_BPF_INSTR_WRITE: {
    fd_bpf_instruction_write_t const * w = &in->inner.write;
    CHECK_LEFT( 4UL );  FD_STORE( uint,  CURSOR, w->offset    ); INC( 4UL );
    CHECK_LEFT( 8UL );  FD_STORE( ulong, CURSOR, w->bytes_len ); INC( 8UL );
    if( w->bytes_len ) {
      CHECK_LEFT( w->bytes_len );
      fd_memcpy( CURSOR, w->bytes, w->bytes_len );
      INC( w->bytes_len );
    }
    break;
  }

  case FD_BPF_INSTR_DEPLOY_WITH_MAX_DATA_LEN: {
    fd_bpf_instruction_deploy_with_max_data_len_t const * d = &in->inner.deploy_with_max_data_len;
    CHECK_LEFT( 8UL );
    FD_STORE( ulong, CURSOR, d->max_data_len ); INC( 8UL );
    break;
  }

  case FD_BPF_INSTR_EXTEND_PROGRAM: {
    fd_bpf_instruction_extend_program_t const * e = &in->inner.extend_program;
    CHECK_LEFT( 4UL );
    FD_STORE( uint, CURSOR, e->additional_bytes ); INC( 4UL );
    break;
  }

  case FD_BPF_INSTR_EXTEND_PROGRAM_CHECKED: {
    fd_bpf_instruction_extend_program_checked_t const * e = &in->inner.extend_program_checked;
    CHECK_LEFT( 4UL );
    FD_STORE( uint, CURSOR, e->additional_bytes ); INC( 4UL );
    break;
  }

  case FD_BPF_INSTR_INITIALIZE_BUFFER:
  case FD_BPF_INSTR_UPGRADE:
  case FD_BPF_INSTR_SET_AUTHORITY:
  case FD_BPF_INSTR_CLOSE:
  case FD_BPF_INSTR_SET_AUTHORITY_CHECKED:
  case FD_BPF_INSTR_MIGRATE:
    break;

  default: return -1;
  }

  *out_sz = _i;

# undef CHECK_LEFT
# undef INC
# undef CURSOR

  return 0;
}

/* fd_bpf_upgradeable_loader_program_instruction_size returns the
   bincode-exact wire size for encoding.  Returns 0 for unknown
   discriminants. */

static inline ulong
fd_bpf_instruction_size( fd_bpf_instruction_t const * in ) {
  switch( in->discriminant ) {
    case FD_BPF_INSTR_WRITE:                    return 4UL + 4UL + 8UL + in->inner.write.bytes_len;
    case FD_BPF_INSTR_DEPLOY_WITH_MAX_DATA_LEN: return 4UL + 8UL;
    case FD_BPF_INSTR_EXTEND_PROGRAM:           return 4UL + 4UL;
    case FD_BPF_INSTR_EXTEND_PROGRAM_CHECKED:   return 4UL + 4UL;
    case FD_BPF_INSTR_INITIALIZE_BUFFER:
    case FD_BPF_INSTR_UPGRADE:
    case FD_BPF_INSTR_SET_AUTHORITY:
    case FD_BPF_INSTR_CLOSE:
    case FD_BPF_INSTR_SET_AUTHORITY_CHECKED:
    case FD_BPF_INSTR_MIGRATE:                  return 4UL;
    default:                                    return 0UL;
  }
}

/* fd_bpf_upgradeable_loader_state_decode parses a bincode-encoded
   UpgradeableLoaderState from [data, data+data_sz).  The output struct
   has no variable-length fields, so the decoder performs a fixed-size
   copy and does not retain any pointer into `data`.  Trailing bytes
   beyond the parsed region are accepted (matches Agave's top-level
   `bincode::deserialize` which uses `allow_trailing_bytes()`).  Returns
   0 on success, -1 on malformed input. */

static inline int
fd_bpf_state_decode( fd_bpf_state_t * out,
                     uchar const *    data,
                     ulong            data_sz ) {
  uchar const * _payload    = data;
  ulong const   _payload_sz = data_sz;
  ulong         _i          = 0UL;

# define CHECK( cond )   { if( FD_UNLIKELY( !(cond) ) ) { return -1; } }
# define CHECK_LEFT( n ) CHECK( (n)<=(_payload_sz-_i) )
# define INC( n )        (_i += (ulong)(n))
# define CURSOR          (_payload+_i)

  CHECK_LEFT( 4UL );
  uint disc = FD_LOAD( uint, CURSOR ); INC( 4UL );
  out->discriminant = disc;

  switch( disc ) {

  case FD_BPF_STATE_UNINITIALIZED:
    return 0;

  case FD_BPF_STATE_BUFFER: {
    fd_bpf_state_buffer_t * b = &out->inner.buffer;
    CHECK_LEFT( 1UL ); uchar tag = *CURSOR; INC( 1UL );
    CHECK( tag<=1 );
    b->has_authority_address = tag;
    if( tag ) {
      CHECK_LEFT( 32UL );
      fd_memcpy( b->authority_address.key, CURSOR, 32UL ); INC( 32UL );
    } else {
      fd_memset( b->authority_address.key, 0, 32UL );
    }
    return 0;
  }

  case FD_BPF_STATE_PROGRAM: {
    fd_bpf_state_program_t * p = &out->inner.program;
    CHECK_LEFT( 32UL );
    fd_memcpy( p->programdata_address.key, CURSOR, 32UL ); INC( 32UL );
    return 0;
  }

  case FD_BPF_STATE_PROGRAM_DATA: {
    fd_bpf_state_program_data_t * pd = &out->inner.program_data;
    CHECK_LEFT( 8UL ); pd->slot = FD_LOAD( ulong, CURSOR ); INC( 8UL );
    CHECK_LEFT( 1UL ); uchar tag = *CURSOR; INC( 1UL );
    CHECK( tag<=1 );
    pd->has_upgrade_authority_address = tag;
    if( tag ) {
      CHECK_LEFT( 32UL );
      fd_memcpy( pd->upgrade_authority_address.key, CURSOR, 32UL ); INC( 32UL );
    } else {
      fd_memset( pd->upgrade_authority_address.key, 0, 32UL );
    }
    return 0;
  }

  default: return -1;
  }

# undef CHECK
# undef CHECK_LEFT
# undef INC
# undef CURSOR
}

/* fd_bpf_upgradeable_loader_state_encode serializes an
   UpgradeableLoaderState into [buf, buf+bufsz).  On success stores the
   number of bytes written to *out_sz and returns 0.  Returns -1 on
   short buffer or unknown discriminant. */

static inline int
fd_bpf_state_encode( fd_bpf_state_t const * in,
                     uchar *                buf,
                     ulong                  bufsz,
                     ulong *                out_sz ) {
  uchar * const _payload    = buf;
  ulong const   _payload_sz = bufsz;
  ulong         _i          = 0UL;

# define CHECK_LEFT( n ) { if( FD_UNLIKELY( (n)>(_payload_sz-_i) ) ) { return -1; } }
# define INC( n )        (_i += (ulong)(n))
# define CURSOR          (_payload+_i)

  CHECK_LEFT( 4UL ); FD_STORE( uint, CURSOR, in->discriminant ); INC( 4UL );

  switch( in->discriminant ) {

  case FD_BPF_STATE_UNINITIALIZED:
    break;

  case FD_BPF_STATE_BUFFER: {
    fd_bpf_state_buffer_t const * b = &in->inner.buffer;
    CHECK_LEFT( 1UL ); *CURSOR = (uchar)( !!b->has_authority_address ); INC( 1UL );
    if( b->has_authority_address ) {
      CHECK_LEFT( 32UL );
      fd_memcpy( CURSOR, b->authority_address.key, 32UL ); INC( 32UL );
    }
    break;
  }

  case FD_BPF_STATE_PROGRAM: {
    fd_bpf_state_program_t const * p = &in->inner.program;
    CHECK_LEFT( 32UL );
    fd_memcpy( CURSOR, p->programdata_address.key, 32UL ); INC( 32UL );
    break;
  }

  case FD_BPF_STATE_PROGRAM_DATA: {
    fd_bpf_state_program_data_t const * pd = &in->inner.program_data;
    CHECK_LEFT( 8UL ); FD_STORE( ulong, CURSOR, pd->slot ); INC( 8UL );
    CHECK_LEFT( 1UL ); *CURSOR = (uchar)( !!pd->has_upgrade_authority_address ); INC( 1UL );
    if( pd->has_upgrade_authority_address ) {
      CHECK_LEFT( 32UL );
      fd_memcpy( CURSOR, pd->upgrade_authority_address.key, 32UL ); INC( 32UL );
    }
    break;
  }

  default: return -1;
  }

  *out_sz = _i;

# undef CHECK_LEFT
# undef INC
# undef CURSOR

  return 0;
}

/* fd_bpf_upgradeable_loader_state_size returns the bincode-exact wire
   size for encoding.  Returns 0 for unknown discriminants. */

static inline ulong
fd_bpf_state_size( fd_bpf_state_t const * in ) {
  switch( in->discriminant ) {
    case FD_BPF_STATE_UNINITIALIZED: return 4UL;
    case FD_BPF_STATE_BUFFER:        return 4UL + 1UL + ( in->inner.buffer.has_authority_address ? 32UL : 0UL );
    case FD_BPF_STATE_PROGRAM:       return 4UL + 32UL;
    case FD_BPF_STATE_PROGRAM_DATA:  return 4UL + 8UL + 1UL + ( in->inner.program_data.has_upgrade_authority_address ? 32UL : 0UL );
    default:                         return 0UL;
  }
}

/* Compatibility aliases for pre-rename callers.  The handwritten loader
   implementation now uses the shorter `fd_bpf_*` naming scheme
   internally, but much of the runtime still refers to the older
   `fd_bpf_upgradeable_loader_*` symbols. */

typedef fd_bpf_instruction_write_t                    fd_bpf_upgradeable_loader_program_instruction_write_t;
typedef fd_bpf_instruction_deploy_with_max_data_len_t fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_t;
typedef fd_bpf_instruction_extend_program_t           fd_bpf_upgradeable_loader_program_instruction_extend_program_t;
typedef fd_bpf_instruction_extend_program_checked_t   fd_bpf_upgradeable_loader_program_instruction_extend_program_checked_t;
typedef fd_bpf_instruction_inner_t                    fd_bpf_upgradeable_loader_program_instruction_inner_t;
typedef fd_bpf_instruction_t                          fd_bpf_upgradeable_loader_program_instruction_t;

typedef fd_bpf_state_buffer_t                         fd_bpf_upgradeable_loader_state_buffer_t;
typedef fd_bpf_state_program_t                        fd_bpf_upgradeable_loader_state_program_t;
typedef fd_bpf_state_program_data_t                   fd_bpf_upgradeable_loader_state_program_data_t;
typedef fd_bpf_state_inner_t                          fd_bpf_upgradeable_loader_state_inner_t;
typedef fd_bpf_state_t                                fd_bpf_upgradeable_loader_state_t;

#define FD_BPF_UPGRADEABLE_LOADER_INSTR_INITIALIZE_BUFFER        FD_BPF_INSTR_INITIALIZE_BUFFER
#define FD_BPF_UPGRADEABLE_LOADER_INSTR_WRITE                    FD_BPF_INSTR_WRITE
#define FD_BPF_UPGRADEABLE_LOADER_INSTR_DEPLOY_WITH_MAX_DATA_LEN FD_BPF_INSTR_DEPLOY_WITH_MAX_DATA_LEN
#define FD_BPF_UPGRADEABLE_LOADER_INSTR_UPGRADE                  FD_BPF_INSTR_UPGRADE
#define FD_BPF_UPGRADEABLE_LOADER_INSTR_SET_AUTHORITY            FD_BPF_INSTR_SET_AUTHORITY
#define FD_BPF_UPGRADEABLE_LOADER_INSTR_CLOSE                    FD_BPF_INSTR_CLOSE
#define FD_BPF_UPGRADEABLE_LOADER_INSTR_EXTEND_PROGRAM           FD_BPF_INSTR_EXTEND_PROGRAM
#define FD_BPF_UPGRADEABLE_LOADER_INSTR_SET_AUTHORITY_CHECKED    FD_BPF_INSTR_SET_AUTHORITY_CHECKED
#define FD_BPF_UPGRADEABLE_LOADER_INSTR_MIGRATE                  FD_BPF_INSTR_MIGRATE
#define FD_BPF_UPGRADEABLE_LOADER_INSTR_EXTEND_PROGRAM_CHECKED   FD_BPF_INSTR_EXTEND_PROGRAM_CHECKED

#define fd_bpf_upgradeable_loader_program_instruction_enum_initialize_buffer      FD_BPF_INSTR_INITIALIZE_BUFFER
#define fd_bpf_upgradeable_loader_program_instruction_enum_write                  FD_BPF_INSTR_WRITE
#define fd_bpf_upgradeable_loader_program_instruction_enum_deploy_with_max_data_len FD_BPF_INSTR_DEPLOY_WITH_MAX_DATA_LEN
#define fd_bpf_upgradeable_loader_program_instruction_enum_upgrade                FD_BPF_INSTR_UPGRADE
#define fd_bpf_upgradeable_loader_program_instruction_enum_set_authority          FD_BPF_INSTR_SET_AUTHORITY
#define fd_bpf_upgradeable_loader_program_instruction_enum_close                  FD_BPF_INSTR_CLOSE
#define fd_bpf_upgradeable_loader_program_instruction_enum_extend_program         FD_BPF_INSTR_EXTEND_PROGRAM
#define fd_bpf_upgradeable_loader_program_instruction_enum_set_authority_checked  FD_BPF_INSTR_SET_AUTHORITY_CHECKED
#define fd_bpf_upgradeable_loader_program_instruction_enum_migrate                FD_BPF_INSTR_MIGRATE
#define fd_bpf_upgradeable_loader_program_instruction_enum_extend_program_checked FD_BPF_INSTR_EXTEND_PROGRAM_CHECKED

#define fd_bpf_upgradeable_loader_state_enum_uninitialized FD_BPF_STATE_UNINITIALIZED
#define fd_bpf_upgradeable_loader_state_enum_buffer        FD_BPF_STATE_BUFFER
#define fd_bpf_upgradeable_loader_state_enum_program       FD_BPF_STATE_PROGRAM
#define fd_bpf_upgradeable_loader_state_enum_program_data  FD_BPF_STATE_PROGRAM_DATA

#define fd_bpf_upgradeable_loader_program_instruction_decode fd_bpf_instruction_decode
#define fd_bpf_upgradeable_loader_program_instruction_encode fd_bpf_instruction_encode
#define fd_bpf_upgradeable_loader_program_instruction_size   fd_bpf_instruction_size

#define fd_bpf_upgradeable_loader_state_decode fd_bpf_state_decode
#define fd_bpf_upgradeable_loader_state_encode fd_bpf_state_encode
#define fd_bpf_upgradeable_loader_state_size   fd_bpf_state_size

#define fd_bpf_upgradeable_loader_state_is_uninitialized fd_bpf_state_is_uninitialized
#define fd_bpf_upgradeable_loader_state_is_buffer        fd_bpf_state_is_buffer
#define fd_bpf_upgradeable_loader_state_is_program       fd_bpf_state_is_program
#define fd_bpf_upgradeable_loader_state_is_program_data  fd_bpf_state_is_program_data

FD_PROTOTYPES_BEGIN

/* Mirrors solana_sdk::transaction_context::BorrowedAccount::get_state()
   https://github.com/anza-xyz/agave/blob/v2.1.14/sdk/src/transaction_context.rs#L965-L969 */

int
fd_bpf_loader_program_get_state( fd_account_meta_t const *           meta,
                                 fd_bpf_state_t * state );

int
fd_deploy_program( fd_exec_instr_ctx_t * instr_ctx,
                   uchar const *         programdata,
                   ulong                 programdata_size );

int
fd_bpf_execute( fd_exec_instr_ctx_t *      instr_ctx,
                fd_progcache_rec_t const * program,
                uchar                      is_deprecated );

int
fd_bpf_loader_program_execute( fd_exec_instr_ctx_t * instr_ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_bpf_loader_program_h */
