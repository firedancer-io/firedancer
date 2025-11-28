#ifndef HEADER_fd_src_flamenco_fd_flamenco_base_h
#define HEADER_fd_src_flamenco_fd_flamenco_base_h

#include "../ballet/base58/fd_base58.h"
#include "types/fd_cast.h"

#define FD_DEFAULT_SLOTS_PER_EPOCH   ( 432000UL )
#define FD_DEFAULT_SHREDS_PER_EPOCH  ( ( 1 << 15UL ) * FD_DEFAULT_SLOTS_PER_EPOCH )
#define FD_SLOT_NULL                 ( ULONG_MAX )
#define FD_SHRED_IDX_NULL            ( UINT_MAX )

#if FD_HAS_ALLOCA

/* FD_BASE58_ENC_{32,64}_ALLOCA is a shorthand for fd_base58_encode_{32,64},
   including defining a temp buffer.  With additional support for passing
   NULL.  Useful for printf-like functions.
   Example:

    fd_pubkey_t pk = ... ;
    printf("%s", FD_BASE58_ENC_32_ALLOCA( pk ) );

   The temp buffer is allocated on the stack and therefore invalidated
   when the function this is used in returns.  NULL will result in
   "<NULL>".
   Do NOT use this marco in a long loop or a recursive function.
   */

static inline char *
fd_base58_enc_32_fmt( char *        out,
                      uchar const * in ) {
  if( FD_UNLIKELY( !in ) ) {
    strcpy( out, "<NULL>");
  } else {
    fd_base58_encode_32( in, NULL, out );
  }
  return out;
}

#define FD_BASE58_ENC_32_ALLOCA( x ) __extension__({                   \
  char * _out = fd_alloca_check( 1UL, FD_BASE58_ENCODED_32_SZ );       \
  fd_base58_enc_32_fmt( _out, (uchar const *)(x) );                    \
})

static inline char *
fd_base58_enc_64_fmt( char *        out,
                      uchar const * in ) {
  if( FD_UNLIKELY( !in ) ) {
    strcpy( out, "<NULL>");
  } else {
    fd_base58_encode_64( in, NULL, out );
  }
  return out;
}

#define FD_BASE58_ENC_64_ALLOCA( x ) __extension__({                   \
  char * _out = fd_alloca_check( 1UL, FD_BASE58_ENCODED_64_SZ );       \
  fd_base58_enc_64_fmt( _out, (uchar const *)(x) );                    \
})

#endif /* FD_HAS_ALLOCA */

/* Forward declarations */

struct fd_bank;
typedef struct fd_bank fd_bank_t;

struct fd_banks;
typedef struct fd_banks fd_banks_t;

struct fd_exec_instr_ctx;
typedef struct fd_exec_instr_ctx fd_exec_instr_ctx_t;

struct fd_acc_mgr;
typedef struct fd_acc_mgr fd_acc_mgr_t;

struct fd_capture_ctx;
typedef struct fd_capture_ctx fd_capture_ctx_t;

struct fd_borrowed_account;
typedef struct fd_borrowed_account fd_borrowed_account_t;

struct fd_txn_account;
typedef struct fd_txn_account fd_txn_account_t;

struct fd_exec_accounts;
typedef struct fd_exec_accounts fd_exec_accounts_t;

union fd_features;
typedef union fd_features fd_features_t;

struct fd_progcache;
typedef struct fd_progcache fd_progcache_t;

union fd_runtime_stack;
typedef union fd_runtime_stack fd_runtime_stack_t;

struct fd_runtime;
typedef struct fd_runtime fd_runtime_t;

struct fd_txn_in;
typedef struct fd_txn_in fd_txn_in_t;

struct fd_txn_out;
typedef struct fd_txn_out fd_txn_out_t;

struct fd_log_collector;
typedef struct fd_log_collector fd_log_collector_t;

struct fd_account_meta {
  uchar owner[32];
  ulong lamports;
  ulong slot;
  uint  dlen;
  uchar executable;
  uchar padding[3];
};
typedef struct fd_account_meta fd_account_meta_t;

FD_PROTOTYPES_BEGIN

/* fd_acct_addr_cstr converts the given Solana address into a base58-
   encoded cstr.  Returns cstr.  On return cstr contains a string with
   length in [32,44] (excluding NULL terminator). */

static inline char *
fd_acct_addr_cstr( char        cstr[ FD_BASE58_ENCODED_32_SZ ],
                   uchar const addr[ 32 ] ) {
  return fd_base58_encode_32( addr, NULL, cstr );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_fd_flamenco_base_h */
