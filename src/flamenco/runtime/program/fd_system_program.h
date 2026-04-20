#ifndef HEADER_fd_src_flamenco_runtime_program_fd_system_program_h
#define HEADER_fd_src_flamenco_runtime_program_fd_system_program_h

/* fd_system_program.h provides hand-written types and zero-copy
   parsers for Solana's SystemInstruction enum, plus entrypoints for
   the system program.

   The decoder produces pointers into the caller-owned instruction
   buffer for variable-length fields (seeds).  Callers must keep the
   instruction buffer alive for the lifetime of the decoded struct.

   https://github.com/anza-xyz/solana-sdk/blob/system-interface%40v3.0.0/system-interface/src/instruction.rs#L92-L299 */

#include "../../fd_flamenco_base.h"
#include "../../types/fd_types.h"
#include "../../../ballet/utf8/fd_utf8.h"

/* Custom error types */

#define FD_SYSTEM_PROGRAM_ERR_ACCT_ALREADY_IN_USE              (0)  /* SystemError::AccountAlreadyInUse */
#define FD_SYSTEM_PROGRAM_ERR_RESULT_WITH_NEGATIVE_LAMPORTS    (1)  /* SystemError::ResultWithNegativeLamports */
#define FD_SYSTEM_PROGRAM_ERR_INVALID_PROGRAM_ID               (2)  /* SystemError::InvalidProgramId */
#define FD_SYSTEM_PROGRAM_ERR_INVALID_ACCT_DATA_LEN            (3)  /* SystemError::InvalidAccountDataLength */
#define FD_SYSTEM_PROGRAM_ERR_MAX_SEED_LEN_EXCEEDED            (4)  /* SystemError::MaxSeedLengthExceeded */
#define FD_SYSTEM_PROGRAM_ERR_ADDR_WITH_SEED_MISMATCH          (5)  /* SystemError::AddressWithSeedMismatch */
#define FD_SYSTEM_PROGRAM_ERR_NONCE_NO_RECENT_BLOCKHASHES      (6)  /* SystemError::NonceNoRecentBlockhashes */
#define FD_SYSTEM_PROGRAM_ERR_NONCE_BLOCKHASH_NOT_EXPIRED      (7)  /* SystemError::NonceBlockhashNotExpired */
#define FD_SYSTEM_PROGRAM_ERR_NONCE_UNEXPECTED_BLOCKHASH_VALUE (8)  /* SystemError::NonceUnexpectedBlockhashValue */

#define FD_SYSTEM_PROGRAM_NONCE_DLEN (80UL)

/* https://github.com/anza-xyz/solana-sdk/blob/nonce-account%40v2.2.1/nonce-account/src/lib.rs#L49-L53 */
#define FD_SYSTEM_PROGRAM_NONCE_ACCOUNT_KIND_UNKNOWN (-1)
#define FD_SYSTEM_PROGRAM_NONCE_ACCOUNT_KIND_SYSTEM  (0)
#define FD_SYSTEM_PROGRAM_NONCE_ACCOUNT_KIND_NONCE   (1)

/* SystemInstruction discriminants (wire-format u32 values). */

#define FD_SYSTEM_PROGRAM_INSTR_CREATE_ACCOUNT               (0U)
#define FD_SYSTEM_PROGRAM_INSTR_ASSIGN                       (1U)
#define FD_SYSTEM_PROGRAM_INSTR_TRANSFER                     (2U)
#define FD_SYSTEM_PROGRAM_INSTR_CREATE_ACCOUNT_WITH_SEED     (3U)
#define FD_SYSTEM_PROGRAM_INSTR_ADVANCE_NONCE_ACCOUNT        (4U)
#define FD_SYSTEM_PROGRAM_INSTR_WITHDRAW_NONCE_ACCOUNT       (5U)
#define FD_SYSTEM_PROGRAM_INSTR_INITIALIZE_NONCE_ACCOUNT     (6U)
#define FD_SYSTEM_PROGRAM_INSTR_AUTHORIZE_NONCE_ACCOUNT      (7U)
#define FD_SYSTEM_PROGRAM_INSTR_ALLOCATE                     (8U)
#define FD_SYSTEM_PROGRAM_INSTR_ALLOCATE_WITH_SEED           (9U)
#define FD_SYSTEM_PROGRAM_INSTR_ASSIGN_WITH_SEED             (10U)
#define FD_SYSTEM_PROGRAM_INSTR_TRANSFER_WITH_SEED           (11U)
#define FD_SYSTEM_PROGRAM_INSTR_UPGRADE_NONCE_ACCOUNT        (12U)
#define FD_SYSTEM_PROGRAM_INSTR_CREATE_ACCOUNT_ALLOW_PREFUND (13U)

/* Per-variant structs. */

struct create_account {
  ulong       lamports;
  ulong       space;
  fd_pubkey_t owner;
};
typedef struct create_account create_account_t;

struct create_account_with_seed {
  fd_pubkey_t   base;
  uchar const * seed; /* points into caller-owned instr_data */
  ulong         seed_len;
  ulong         lamports;
  ulong         space;
  fd_pubkey_t   owner;
};
typedef struct create_account_with_seed create_account_with_seed_t;

struct allocate_with_seed {
  fd_pubkey_t   base;
  uchar const * seed;
  ulong         seed_len;
  ulong         space;
  fd_pubkey_t   owner;
};
typedef struct allocate_with_seed allocate_with_seed_t;

struct assign_with_seed {
  fd_pubkey_t   base;
  uchar const * seed;
  ulong         seed_len;
  fd_pubkey_t   owner;
};
typedef struct assign_with_seed assign_with_seed_t;

struct transfer_with_seed {
  ulong         lamports;
  uchar const * from_seed;
  ulong         from_seed_len;
  fd_pubkey_t   from_owner;
};
typedef struct transfer_with_seed transfer_with_seed_t;

/* Discriminated union. */

union fd_system_program_instruction_inner {
  create_account_t           create_account;
  fd_pubkey_t                assign;
  ulong                      transfer;
  create_account_with_seed_t create_account_with_seed;
  ulong                      withdraw_nonce_account;
  fd_pubkey_t                initialize_nonce_account;
  fd_pubkey_t                authorize_nonce_account;
  ulong                      allocate;
  allocate_with_seed_t       allocate_with_seed;
  assign_with_seed_t         assign_with_seed;
  transfer_with_seed_t       transfer_with_seed;
  create_account_t           create_account_allow_prefund;
};
typedef union fd_system_program_instruction_inner fd_system_program_instruction_inner_t;

struct fd_system_program_instruction {
  uint                                  discriminant;
  fd_system_program_instruction_inner_t inner;
};
typedef struct fd_system_program_instruction fd_system_program_instruction_t;

/* fd_system_program_instruction_decode reads a bincode-encoded
   SystemInstruction from [data, data+data_sz).  Variable-length seed
   fields in the output point directly into `data`, so the caller must
   keep that buffer alive.  Returns 0 on success, -1 on decode error. */

static inline int
fd_system_program_instruction_decode( fd_system_program_instruction_t * out,
                                      uchar const *                     data,
                                      ulong                             data_sz ) {
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

  case FD_SYSTEM_PROGRAM_INSTR_CREATE_ACCOUNT:
  case FD_SYSTEM_PROGRAM_INSTR_CREATE_ACCOUNT_ALLOW_PREFUND: {
    create_account_t * ca =
        (disc==FD_SYSTEM_PROGRAM_INSTR_CREATE_ACCOUNT)
          ? &out->inner.create_account
          : &out->inner.create_account_allow_prefund;
    CHECK_LEFT( 48UL );
    ca->lamports = FD_LOAD( ulong, CURSOR ); INC( 8UL );
    ca->space    = FD_LOAD( ulong, CURSOR ); INC( 8UL );
    fd_memcpy( ca->owner.key, CURSOR, 32UL ); INC( 32UL );
    return 0;
  }

  case FD_SYSTEM_PROGRAM_INSTR_ASSIGN: {
    CHECK_LEFT( 32UL );
    fd_memcpy( out->inner.assign.key, CURSOR, 32UL ); INC( 32UL );
    return 0;
  }

  case FD_SYSTEM_PROGRAM_INSTR_TRANSFER: {
    CHECK_LEFT( 8UL );
    out->inner.transfer = FD_LOAD( ulong, CURSOR ); INC( 8UL );
    return 0;
  }

  case FD_SYSTEM_PROGRAM_INSTR_CREATE_ACCOUNT_WITH_SEED: {
    create_account_with_seed_t * cs = &out->inner.create_account_with_seed;
    CHECK_LEFT( 32UL ); fd_memcpy( cs->base.key, CURSOR, 32UL ); INC( 32UL );
    CHECK_LEFT( 8UL );  cs->seed_len = FD_LOAD( ulong, CURSOR ); INC( 8UL );
    CHECK_LEFT( cs->seed_len );
    if( cs->seed_len ) {
      CHECK( fd_utf8_verify( (char const *)CURSOR, cs->seed_len ) );
    }
    cs->seed = CURSOR; INC( cs->seed_len );
    CHECK_LEFT( 48UL );
    cs->lamports = FD_LOAD( ulong, CURSOR ); INC( 8UL );
    cs->space    = FD_LOAD( ulong, CURSOR ); INC( 8UL );
    fd_memcpy( cs->owner.key, CURSOR, 32UL ); INC( 32UL );
    return 0;
  }

  case FD_SYSTEM_PROGRAM_INSTR_ADVANCE_NONCE_ACCOUNT: {
    return 0;
  }

  case FD_SYSTEM_PROGRAM_INSTR_WITHDRAW_NONCE_ACCOUNT: {
    CHECK_LEFT( 8UL );
    out->inner.withdraw_nonce_account = FD_LOAD( ulong, CURSOR ); INC( 8UL );
    return 0;
  }

  case FD_SYSTEM_PROGRAM_INSTR_INITIALIZE_NONCE_ACCOUNT: {
    CHECK_LEFT( 32UL );
    fd_memcpy( out->inner.initialize_nonce_account.key, CURSOR, 32UL ); INC( 32UL );
    return 0;
  }

  case FD_SYSTEM_PROGRAM_INSTR_AUTHORIZE_NONCE_ACCOUNT: {
    CHECK_LEFT( 32UL );
    fd_memcpy( out->inner.authorize_nonce_account.key, CURSOR, 32UL ); INC( 32UL );
    return 0;
  }

  case FD_SYSTEM_PROGRAM_INSTR_ALLOCATE: {
    CHECK_LEFT( 8UL );
    out->inner.allocate = FD_LOAD( ulong, CURSOR ); INC( 8UL );
    return 0;
  }

  case FD_SYSTEM_PROGRAM_INSTR_ALLOCATE_WITH_SEED: {
    allocate_with_seed_t * as_ = &out->inner.allocate_with_seed;
    CHECK_LEFT( 32UL ); fd_memcpy( as_->base.key, CURSOR, 32UL ); INC( 32UL );
    CHECK_LEFT( 8UL );  as_->seed_len = FD_LOAD( ulong, CURSOR ); INC( 8UL );
    CHECK_LEFT( as_->seed_len );
    if( as_->seed_len ) {
      CHECK( fd_utf8_verify( (char const *)CURSOR, as_->seed_len ) );
    }
    as_->seed = CURSOR; INC( as_->seed_len );
    CHECK_LEFT( 40UL );
    as_->space = FD_LOAD( ulong, CURSOR ); INC( 8UL );
    fd_memcpy( as_->owner.key, CURSOR, 32UL ); INC( 32UL );
    return 0;
  }

  case FD_SYSTEM_PROGRAM_INSTR_ASSIGN_WITH_SEED: {
    assign_with_seed_t * aw = &out->inner.assign_with_seed;
    CHECK_LEFT( 32UL ); fd_memcpy( aw->base.key, CURSOR, 32UL ); INC( 32UL );
    CHECK_LEFT( 8UL );  aw->seed_len = FD_LOAD( ulong, CURSOR ); INC( 8UL );
    CHECK_LEFT( aw->seed_len );
    if( aw->seed_len ) {
      CHECK( fd_utf8_verify( (char const *)CURSOR, aw->seed_len ) );
    }
    aw->seed = CURSOR; INC( aw->seed_len );
    CHECK_LEFT( 32UL );
    fd_memcpy( aw->owner.key, CURSOR, 32UL ); INC( 32UL );
    return 0;
  }

  case FD_SYSTEM_PROGRAM_INSTR_TRANSFER_WITH_SEED: {
    transfer_with_seed_t * tw = &out->inner.transfer_with_seed;
    CHECK_LEFT( 8UL );  tw->lamports      = FD_LOAD( ulong, CURSOR ); INC( 8UL );
    CHECK_LEFT( 8UL );  tw->from_seed_len = FD_LOAD( ulong, CURSOR ); INC( 8UL );
    CHECK_LEFT( tw->from_seed_len );
    if( tw->from_seed_len ) {
      CHECK( fd_utf8_verify( (char const *)CURSOR, tw->from_seed_len ) );
    }
    tw->from_seed = CURSOR; INC( tw->from_seed_len );
    CHECK_LEFT( 32UL );
    fd_memcpy( tw->from_owner.key, CURSOR, 32UL ); INC( 32UL );
    return 0;
  }

  case FD_SYSTEM_PROGRAM_INSTR_UPGRADE_NONCE_ACCOUNT: {
    return 0;
  }

  default: return -1;
  }

# undef CHECK
# undef CHECK_LEFT
# undef INC
# undef CURSOR
}

/* fd_system_program_instruction_encode writes a bincode-encoded
   SystemInstruction into [buf, buf+bufsz).  On success stores the
   number of bytes written to *out_sz and returns 0.  Returns -1 on
   short buffer. */

static inline int
fd_system_program_instruction_encode( fd_system_program_instruction_t const * in,
                                      uchar *                                 buf,
                                      ulong                                   bufsz,
                                      ulong *                                 out_sz ) {
  uchar * const _payload    = buf;
  ulong const   _payload_sz = bufsz;
  ulong         _i          = 0UL;

# define CHECK_LEFT( n ) { if( FD_UNLIKELY( (n)>(_payload_sz-_i) ) ) { return -1; } }
# define INC( n )        (_i += (ulong)(n))
# define CURSOR          (_payload+_i)

  CHECK_LEFT( 4UL ); FD_STORE( uint, CURSOR, in->discriminant ); INC( 4UL );

  switch( in->discriminant ) {

  case FD_SYSTEM_PROGRAM_INSTR_CREATE_ACCOUNT:
  case FD_SYSTEM_PROGRAM_INSTR_CREATE_ACCOUNT_ALLOW_PREFUND: {
    create_account_t const * ca =
        (in->discriminant==FD_SYSTEM_PROGRAM_INSTR_CREATE_ACCOUNT)
          ? &in->inner.create_account
          : &in->inner.create_account_allow_prefund;
    CHECK_LEFT( 48UL );
    FD_STORE( ulong, CURSOR, ca->lamports ); INC( 8UL );
    FD_STORE( ulong, CURSOR, ca->space ); INC( 8UL );
    fd_memcpy( CURSOR, ca->owner.key, 32UL ); INC( 32UL );
    break;
  }

  case FD_SYSTEM_PROGRAM_INSTR_ASSIGN: {
    CHECK_LEFT( 32UL );
    fd_memcpy( CURSOR, in->inner.assign.key, 32UL ); INC( 32UL );
    break;
  }

  case FD_SYSTEM_PROGRAM_INSTR_TRANSFER: {
    CHECK_LEFT( 8UL );
    FD_STORE( ulong, CURSOR, in->inner.transfer ); INC( 8UL );
    break;
  }

  case FD_SYSTEM_PROGRAM_INSTR_CREATE_ACCOUNT_WITH_SEED: {
    create_account_with_seed_t const * cs = &in->inner.create_account_with_seed;
    CHECK_LEFT( 32UL ); fd_memcpy( CURSOR, cs->base.key, 32UL ); INC( 32UL );
    CHECK_LEFT( 8UL );  FD_STORE( ulong, CURSOR, cs->seed_len ); INC( 8UL );
    if( cs->seed_len ) {
      CHECK_LEFT( cs->seed_len ); fd_memcpy( CURSOR, cs->seed, cs->seed_len ); INC( cs->seed_len );
    }
    CHECK_LEFT( 48UL );
    FD_STORE( ulong, CURSOR, cs->lamports ); INC( 8UL );
    FD_STORE( ulong, CURSOR, cs->space ); INC( 8UL );
    fd_memcpy( CURSOR, cs->owner.key, 32UL ); INC( 32UL );
    break;
  }

  case FD_SYSTEM_PROGRAM_INSTR_ADVANCE_NONCE_ACCOUNT: break;

  case FD_SYSTEM_PROGRAM_INSTR_WITHDRAW_NONCE_ACCOUNT: {
    CHECK_LEFT( 8UL );
    FD_STORE( ulong, CURSOR, in->inner.withdraw_nonce_account ); INC( 8UL );
    break;
  }

  case FD_SYSTEM_PROGRAM_INSTR_INITIALIZE_NONCE_ACCOUNT: {
    CHECK_LEFT( 32UL );
    fd_memcpy( CURSOR, in->inner.initialize_nonce_account.key, 32UL ); INC( 32UL );
    break;
  }

  case FD_SYSTEM_PROGRAM_INSTR_AUTHORIZE_NONCE_ACCOUNT: {
    CHECK_LEFT( 32UL );
    fd_memcpy( CURSOR, in->inner.authorize_nonce_account.key, 32UL ); INC( 32UL );
    break;
  }

  case FD_SYSTEM_PROGRAM_INSTR_ALLOCATE: {
    CHECK_LEFT( 8UL );
    FD_STORE( ulong, CURSOR, in->inner.allocate ); INC( 8UL );
    break;
  }

  case FD_SYSTEM_PROGRAM_INSTR_ALLOCATE_WITH_SEED: {
    allocate_with_seed_t const * as_ = &in->inner.allocate_with_seed;
    CHECK_LEFT( 32UL ); fd_memcpy( CURSOR, as_->base.key, 32UL ); INC( 32UL );
    CHECK_LEFT( 8UL );  FD_STORE( ulong, CURSOR, as_->seed_len ); INC( 8UL );
    if( as_->seed_len ) {
      CHECK_LEFT( as_->seed_len ); fd_memcpy( CURSOR, as_->seed, as_->seed_len ); INC( as_->seed_len );
    }
    CHECK_LEFT( 40UL );
    FD_STORE( ulong, CURSOR, as_->space ); INC( 8UL );
    fd_memcpy( CURSOR, as_->owner.key, 32UL ); INC( 32UL );
    break;
  }

  case FD_SYSTEM_PROGRAM_INSTR_ASSIGN_WITH_SEED: {
    assign_with_seed_t const * aw = &in->inner.assign_with_seed;
    CHECK_LEFT( 32UL ); fd_memcpy( CURSOR, aw->base.key, 32UL ); INC( 32UL );
    CHECK_LEFT( 8UL );  FD_STORE( ulong, CURSOR, aw->seed_len ); INC( 8UL );
    if( aw->seed_len ) {
      CHECK_LEFT( aw->seed_len ); fd_memcpy( CURSOR, aw->seed, aw->seed_len ); INC( aw->seed_len );
    }
    CHECK_LEFT( 32UL );
    fd_memcpy( CURSOR, aw->owner.key, 32UL ); INC( 32UL );
    break;
  }

  case FD_SYSTEM_PROGRAM_INSTR_TRANSFER_WITH_SEED: {
    transfer_with_seed_t const * tw = &in->inner.transfer_with_seed;
    CHECK_LEFT( 8UL );  FD_STORE( ulong, CURSOR, tw->lamports ); INC( 8UL );
    CHECK_LEFT( 8UL );  FD_STORE( ulong, CURSOR, tw->from_seed_len ); INC( 8UL );
    if( tw->from_seed_len ) {
      CHECK_LEFT( tw->from_seed_len ); fd_memcpy( CURSOR, tw->from_seed, tw->from_seed_len ); INC( tw->from_seed_len );
    }
    CHECK_LEFT( 32UL );
    fd_memcpy( CURSOR, tw->from_owner.key, 32UL ); INC( 32UL );
    break;
  }

  case FD_SYSTEM_PROGRAM_INSTR_UPGRADE_NONCE_ACCOUNT: break;

  default: return -1;
  }

  *out_sz = _i;

# undef CHECK_LEFT
# undef INC
# undef CURSOR

  return 0;
}

FD_PROTOTYPES_BEGIN

/* fd_system_program_execute is the entrypoint for the system program */

int fd_system_program_execute( fd_exec_instr_ctx_t * ctx );

/* System program instruction handlers */

int fd_system_program_exec_create_account              ( fd_exec_instr_ctx_t * ctx, create_account_t const *           data     );
int fd_system_program_exec_assign                      ( fd_exec_instr_ctx_t * ctx, fd_pubkey_t const *                owner    );
int fd_system_program_exec_transfer                    ( fd_exec_instr_ctx_t * ctx, ulong                              lamports );
int fd_system_program_exec_create_account_with_seed    ( fd_exec_instr_ctx_t * ctx, create_account_with_seed_t const * data     );
int fd_system_program_exec_advance_nonce_account       ( fd_exec_instr_ctx_t * ctx                                              );
int fd_system_program_exec_withdraw_nonce_account      ( fd_exec_instr_ctx_t * ctx, ulong                              lamports );
int fd_system_program_exec_initialize_nonce_account    ( fd_exec_instr_ctx_t * ctx, fd_pubkey_t const *                pubkey   );
int fd_system_program_exec_authorize_nonce_account     ( fd_exec_instr_ctx_t * ctx, fd_pubkey_t const *                pubkey   );
int fd_system_program_exec_allocate                    ( fd_exec_instr_ctx_t * ctx, ulong                              space    );
int fd_system_program_exec_allocate_with_seed          ( fd_exec_instr_ctx_t * ctx, allocate_with_seed_t const *       data     );
int fd_system_program_exec_assign_with_seed            ( fd_exec_instr_ctx_t * ctx, assign_with_seed_t const *         data     );
int fd_system_program_exec_transfer_with_seed          ( fd_exec_instr_ctx_t * ctx, transfer_with_seed_t const *       data     );
int fd_system_program_exec_upgrade_nonce_account       ( fd_exec_instr_ctx_t * ctx                                              );
int fd_system_program_exec_create_account_allow_prefund( fd_exec_instr_ctx_t * ctx, create_account_t const *           data     );

/* User APIs */

/* fd_check_transaction_age returns 0 if the transactions age is valid,
   returns non-zero otherwise. This is determined by the age of the
   blockhash provided in the transaction message or by the validity of
   the nonce provided in the transaction. */

int
fd_check_transaction_age( fd_runtime_t *      runtime,
                          fd_bank_t *         bank,
                          fd_txn_in_t const * txn_in,
                          fd_txn_out_t *      txn_out );

/* `fd_get_system_account_kind()` determines whether an account is
   a normal system program account or a nonce account. Returns:
   - FD_SYSTEM_PROGRAM_NONCE_ACCOUNT_KIND_SYSTEM if the account is a
     normal system program account
   - FD_SYSTEM_PROGRAM_NONCE_ACCOUNT_KIND_NONCE if the account is a
     nonce account
   - FD_SYSTEM_PROGRAM_NONCE_ACCOUNT_KIND_UNKNOWN otherwise
   https://github.com/anza-xyz/solana-sdk/blob/nonce-account%40v2.2.1/nonce-account/src/lib.rs#L55-L71 */

int
fd_get_system_account_kind( fd_account_meta_t const * meta );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_system_program_h */
