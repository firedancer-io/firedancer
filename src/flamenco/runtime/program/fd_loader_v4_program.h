#ifndef HEADER_fd_src_flamenco_runtime_program_fd_loader_v4_program_h
#define HEADER_fd_src_flamenco_runtime_program_fd_loader_v4_program_h

#include "../../fd_flamenco_base.h"
#include "fd_bpf_loader_program.h"

/*
  Notes about loader v4 since it differs slightly from the previous BPF v3 loader...
    - There are three possible states for a loader v4 program:
      - Retracted
        - This name is a little bit misleading since it applies to programs that are either in the process of deployment,
          or already deployed and in maintenance (and thus cannot be invoked).
      - Deployed
        - This is the normal state for a program that is ready to be invoked.
        - Programs cannot be retracted within `LOADER_V4_DEPLOYMENT_COOLDOWN_IN_SLOTS` (1) slot of deployment.
      - Finalized
        - The program is immutable.
        - Users must specify a "next version" which, from my inspection, serves no functional purpose besides showing up
          as extra information on a block explorer.
    - There is no longer a concept of a program account vs. a program data account. The program account is the program data account.
      - "Look at me... I'm the programdata account now..."
    - Buffer accounts are no longer necessary. Instead, the `write` instruction writes directly into the program account.
      - Optionally, when calling `deploy`, the user can provide a source buffer account to overwrite the program data
        instead of calling retract -> write -> deploy.
      - There is no direct `upgrade` instruction anymore. The user must either retract the program, call set_program_length,
        write new bytes, and redeploy, or they can write new bytes to a source buffer account and call `deploy`.
    - There is no `close` instruction anymore. Instead, the user must call `set_program_length` with a new size of 0 bytes, which
      automatically closes the program account and resets it into an uninitialized state.
*/

/* https://github.com/anza-xyz/agave/blob/v2.2.6/programs/loader-v4/src/lib.rs#L30 */
#define LOADER_V4_DEFAULT_COMPUTE_UNITS (2000UL)

/* https://github.com/anza-xyz/solana-sdk/blob/loader-v4-interface%40v2.2.1/loader-v4-interface/src/lib.rs#L11 */
#define LOADER_V4_DEPLOYMENT_COOLDOWN_IN_SLOTS (1UL)

/* https://github.com/anza-xyz/solana-sdk/blob/loader-v4-interface%40v2.2.1/loader-v4-interface/src/state.rs#L31-L36 */
#define LOADER_V4_PROGRAM_DATA_OFFSET (48UL)

/* Serization / deserialization done for the loader v4 state is done using a `std::mem::transmute()` instead of using
   the standard bincode deserialization. The key difference of doing this is that state deserialization does not fail
   if the `status` enum within the state is invalid (Retracted, Deployed, Finalized). To stay conformant with their semantics,
   we represent `status` as a ulong (intentionally instead of a uint because Agave uses `repr(u64)`) and use type punning
   to decode and encode data between the program account and the state object. It also keeps the type size
   consistent with Agave's for safe transmute operations.

   https://github.com/anza-xyz/solana-sdk/blob/loader-v4-interface%40v2.2.1/loader-v4-interface/src/state.rs#L3-L13 */
#define FD_LOADER_V4_STATUS_ENUM_RETRACTED (0UL)
#define FD_LOADER_V4_STATUS_ENUM_DELOYED   (1UL)
#define FD_LOADER_V4_STATUS_ENUM_FINALIZED (2UL)

/* fd_loader_v4_state_t is the transmute-compatible representation of
   `solana_loader_v4_interface::state::LoaderV4State`.  Wire format is
   a fixed 48-byte `repr(C)` layout that is read and written via
   `FD_LOAD` / `FD_STORE` rather than bincode (matches Agave's
   `unsafe { std::mem::transmute(...) }`).  The explicit `ulong status`
   intentionally mirrors Agave's `repr(u64)` so that invalid discriminants
   round-trip rather than causing a decode error.

   https://github.com/anza-xyz/agave/blob/v2.1.4/sdk/program/src/loader_v4.rs#L33-L43 */

struct fd_loader_v4_state {
  ulong       slot;
  fd_pubkey_t authority_address_or_next_version;
  ulong       status;
};
typedef struct fd_loader_v4_state fd_loader_v4_state_t;

/* This MUST hold true for safety and conformance. */
FD_STATIC_ASSERT( sizeof(fd_loader_v4_state_t)==LOADER_V4_PROGRAM_DATA_OFFSET, loader_v4 );

/* fd_loader_v4_state_encode writes the 48-byte `repr(C)` representation
   of `state` into `buf`.  Returns 0 on success, -1 if `bufsz<48`.  On
   success `*out_sz` is set to 48. */

static inline int
fd_loader_v4_state_encode( fd_loader_v4_state_t const * state,
                           uchar *                      buf,
                           ulong                        bufsz,
                           ulong *                      out_sz ) {
  if( FD_UNLIKELY( bufsz<sizeof(fd_loader_v4_state_t) ) ) return -1;
  FD_STORE( ulong,       buf,      state->slot );
  fd_memcpy( buf+8UL, state->authority_address_or_next_version.key, 32UL );
  FD_STORE( ulong,       buf+40UL, state->status );
  *out_sz = sizeof(fd_loader_v4_state_t);
  return 0;
}

/* LoaderV4Instruction wire format (u32 discriminant).
   https://github.com/anza-xyz/solana-sdk/blob/loader-v4-interface%40v2.2.1/loader-v4-interface/src/instruction.rs */

#define FD_LOADER_V4_INSTR_WRITE              (0U)
#define FD_LOADER_V4_INSTR_COPY               (1U)
#define FD_LOADER_V4_INSTR_SET_PROGRAM_LENGTH (2U)
#define FD_LOADER_V4_INSTR_DEPLOY             (3U)
#define FD_LOADER_V4_INSTR_RETRACT            (4U)
#define FD_LOADER_V4_INSTR_TRANSFER_AUTHORITY (5U)
#define FD_LOADER_V4_INSTR_FINALIZE           (6U)

/* Symbols mirroring the (now-removed) generated bincode enum so existing
   switch labels and struct initializers keep working unchanged. */

enum {
  fd_loader_v4_program_instruction_enum_write                = FD_LOADER_V4_INSTR_WRITE,
  fd_loader_v4_program_instruction_enum_copy                 = FD_LOADER_V4_INSTR_COPY,
  fd_loader_v4_program_instruction_enum_set_program_length   = FD_LOADER_V4_INSTR_SET_PROGRAM_LENGTH,
  fd_loader_v4_program_instruction_enum_deploy               = FD_LOADER_V4_INSTR_DEPLOY,
  fd_loader_v4_program_instruction_enum_retract              = FD_LOADER_V4_INSTR_RETRACT,
  fd_loader_v4_program_instruction_enum_transfer_authority   = FD_LOADER_V4_INSTR_TRANSFER_AUTHORITY,
  fd_loader_v4_program_instruction_enum_finalize             = FD_LOADER_V4_INSTR_FINALIZE
};

/* Per-variant payload structs.

   The `write` variant uses zero-copy for its `bytes` field: after a
   successful decode `bytes` points directly into the caller-owned
   instruction buffer, and the caller must keep that buffer alive for the
   lifetime of the decoded struct. */

struct fd_loader_v4_program_instruction_write {
  uint          offset;
  uchar const * bytes;
  ulong         bytes_len;
};
typedef struct fd_loader_v4_program_instruction_write fd_loader_v4_program_instruction_write_t;

struct fd_loader_v4_program_instruction_copy {
  uint destination_offset;
  uint source_offset;
  uint length;
};
typedef struct fd_loader_v4_program_instruction_copy fd_loader_v4_program_instruction_copy_t;

struct fd_loader_v4_program_instruction_set_program_length {
  uint new_size;
};
typedef struct fd_loader_v4_program_instruction_set_program_length fd_loader_v4_program_instruction_set_program_length_t;

union fd_loader_v4_program_instruction_inner {
  fd_loader_v4_program_instruction_write_t              write;
  fd_loader_v4_program_instruction_copy_t               copy;
  fd_loader_v4_program_instruction_set_program_length_t set_program_length;
};
typedef union fd_loader_v4_program_instruction_inner fd_loader_v4_program_instruction_inner_t;

struct fd_loader_v4_program_instruction {
  uint                                     discriminant;
  fd_loader_v4_program_instruction_inner_t inner;
};
typedef struct fd_loader_v4_program_instruction fd_loader_v4_program_instruction_t;

/* fd_loader_v4_program_instruction_decode parses a bincode-encoded
   LoaderV4Instruction from [data, data+data_sz).  Variable-length fields
   (`write.bytes`) point directly into `data`, so callers must keep that
   buffer alive.  Trailing bytes beyond the parsed region are accepted
   (matches Agave's `bincode::deserialize` with the default
   `allow_trailing_bytes()` option).  Returns 0 on success, -1 on
   malformed input (short buffer or unknown discriminant). */

static inline int
fd_loader_v4_program_instruction_decode( fd_loader_v4_program_instruction_t * out,
                                         uchar const *                        data,
                                         ulong                                data_sz ) {
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

  case FD_LOADER_V4_INSTR_WRITE: {
    fd_loader_v4_program_instruction_write_t * w = &out->inner.write;
    CHECK_LEFT( 4UL );  w->offset    = FD_LOAD( uint,  CURSOR ); INC( 4UL );
    CHECK_LEFT( 8UL );  w->bytes_len = FD_LOAD( ulong, CURSOR ); INC( 8UL );
    CHECK_LEFT( w->bytes_len );
    w->bytes = w->bytes_len ? CURSOR : NULL;
    INC( w->bytes_len );
    return 0;
  }

  case FD_LOADER_V4_INSTR_COPY: {
    fd_loader_v4_program_instruction_copy_t * c = &out->inner.copy;
    CHECK_LEFT( 12UL );
    c->destination_offset = FD_LOAD( uint, CURSOR ); INC( 4UL );
    c->source_offset      = FD_LOAD( uint, CURSOR ); INC( 4UL );
    c->length             = FD_LOAD( uint, CURSOR ); INC( 4UL );
    return 0;
  }

  case FD_LOADER_V4_INSTR_SET_PROGRAM_LENGTH: {
    fd_loader_v4_program_instruction_set_program_length_t * s = &out->inner.set_program_length;
    CHECK_LEFT( 4UL );
    s->new_size = FD_LOAD( uint, CURSOR ); INC( 4UL );
    return 0;
  }

  case FD_LOADER_V4_INSTR_DEPLOY:
  case FD_LOADER_V4_INSTR_RETRACT:
  case FD_LOADER_V4_INSTR_TRANSFER_AUTHORITY:
  case FD_LOADER_V4_INSTR_FINALIZE:
    return 0;

  default: return -1;
  }

# undef CHECK
# undef CHECK_LEFT
# undef INC
# undef CURSOR
}

/* fd_loader_v4_program_instruction_encode serializes a
   LoaderV4Instruction into [buf, buf+bufsz).  On success stores the
   number of bytes written to *out_sz and returns 0.  Returns -1 on
   short buffer or unknown discriminant. */

static inline int
fd_loader_v4_program_instruction_encode( fd_loader_v4_program_instruction_t const * in,
                                         uchar *                                    buf,
                                         ulong                                      bufsz,
                                         ulong *                                    out_sz ) {
  uchar * const _payload    = buf;
  ulong const   _payload_sz = bufsz;
  ulong         _i          = 0UL;

# define CHECK_LEFT( n ) { if( FD_UNLIKELY( (n)>(_payload_sz-_i) ) ) { return -1; } }
# define INC( n )        (_i += (ulong)(n))
# define CURSOR          (_payload+_i)

  CHECK_LEFT( 4UL ); FD_STORE( uint, CURSOR, in->discriminant ); INC( 4UL );

  switch( in->discriminant ) {

  case FD_LOADER_V4_INSTR_WRITE: {
    fd_loader_v4_program_instruction_write_t const * w = &in->inner.write;
    CHECK_LEFT( 4UL );  FD_STORE( uint,  CURSOR, w->offset    ); INC( 4UL );
    CHECK_LEFT( 8UL );  FD_STORE( ulong, CURSOR, w->bytes_len ); INC( 8UL );
    if( w->bytes_len ) {
      CHECK_LEFT( w->bytes_len );
      fd_memcpy( CURSOR, w->bytes, w->bytes_len );
      INC( w->bytes_len );
    }
    break;
  }

  case FD_LOADER_V4_INSTR_COPY: {
    fd_loader_v4_program_instruction_copy_t const * c = &in->inner.copy;
    CHECK_LEFT( 12UL );
    FD_STORE( uint, CURSOR, c->destination_offset ); INC( 4UL );
    FD_STORE( uint, CURSOR, c->source_offset      ); INC( 4UL );
    FD_STORE( uint, CURSOR, c->length             ); INC( 4UL );
    break;
  }

  case FD_LOADER_V4_INSTR_SET_PROGRAM_LENGTH: {
    fd_loader_v4_program_instruction_set_program_length_t const * s = &in->inner.set_program_length;
    CHECK_LEFT( 4UL );
    FD_STORE( uint, CURSOR, s->new_size ); INC( 4UL );
    break;
  }

  case FD_LOADER_V4_INSTR_DEPLOY:
  case FD_LOADER_V4_INSTR_RETRACT:
  case FD_LOADER_V4_INSTR_TRANSFER_AUTHORITY:
  case FD_LOADER_V4_INSTR_FINALIZE:
    break;

  default: return -1;
  }

  *out_sz = _i;

# undef CHECK_LEFT
# undef INC
# undef CURSOR

  return 0;
}

/* fd_loader_v4_program_instruction_size returns the bincode-exact wire
   size of a LoaderV4Instruction.  Returns 0 for unknown discriminants
   (mirrors Agave's bincode serializer which would refuse to serialize
   them). */

static inline ulong
fd_loader_v4_program_instruction_size( fd_loader_v4_program_instruction_t const * in ) {
  switch( in->discriminant ) {
    case FD_LOADER_V4_INSTR_WRITE:              return 4UL + 4UL + 8UL + in->inner.write.bytes_len;
    case FD_LOADER_V4_INSTR_COPY:               return 4UL + 12UL;
    case FD_LOADER_V4_INSTR_SET_PROGRAM_LENGTH: return 4UL + 4UL;
    case FD_LOADER_V4_INSTR_DEPLOY:
    case FD_LOADER_V4_INSTR_RETRACT:
    case FD_LOADER_V4_INSTR_TRANSFER_AUTHORITY:
    case FD_LOADER_V4_INSTR_FINALIZE:           return 4UL;
    default:                                    return 0UL;
  }
}

FD_PROTOTYPES_BEGIN

FD_FN_PURE uchar
fd_loader_v4_status_is_deployed( fd_loader_v4_state_t const * state );

FD_FN_PURE uchar
fd_loader_v4_status_is_retracted( fd_loader_v4_state_t const * state );

FD_FN_PURE uchar
fd_loader_v4_status_is_finalized( fd_loader_v4_state_t const * state );

fd_loader_v4_state_t const *
fd_loader_v4_get_state( void const * data,
                        ulong        data_sz,
                        int *        err );

int
fd_loader_v4_program_execute( fd_exec_instr_ctx_t * instr_ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_loader_v4_program_h */
