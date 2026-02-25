#include "fd_precompiles.h"
#include "../fd_bank.h"
#include "../fd_executor_err.h"
#include "../../../ballet/keccak256/fd_keccak256.h"
#include "../../../ballet/ed25519/fd_ed25519.h"
#include "../../../ballet/secp256k1/fd_secp256k1.h"
#include "../../../ballet/secp256r1/fd_secp256r1.h"
#include "../fd_system_ids.h"
#include "../fd_system_ids_pp.h"

/* Docs:
   https://docs.solana.com/developing/runtime-facilities/programs#ed25519-program
   https://docs.solana.com/developing/runtime-facilities/programs#secp256k1-program */

/* There are 3 precompiles and 2 ways to serialize data.
   The most recent one seems are ed25519 and secp256r1 with 2 bytes per instruction,
   that works better with JS sdk even though it consumes a few bytes. */
struct __attribute__((packed)) fd_precompile_sig_offsets {
  ushort sig_offset;
  ushort sig_instr_idx;
  ushort pubkey_offset;
  ushort pubkey_instr_idx;
  ushort msg_offset;
  ushort msg_data_sz;
  ushort msg_instr_idx;
};
typedef struct fd_precompile_sig_offsets fd_ed25519_signature_offsets_t;
typedef struct fd_precompile_sig_offsets fd_secp256r1_signature_offsets_t;

struct __attribute__((packed)) fd_precompile_one_byte_idx_sig_offsets {
  ushort sig_offset;
  uchar  sig_instr_idx;
  ushort pubkey_offset;
  uchar  pubkey_instr_idx;
  ushort msg_offset;
  ushort msg_data_sz;
  uchar  msg_instr_idx;
};
typedef struct fd_precompile_one_byte_idx_sig_offsets fd_secp256k1_signature_offsets_t;

/*
  Common
*/

#define SIGNATURE_SERIALIZED_SIZE         (64UL)
#define SIGNATURE_OFFSETS_SERIALIZED_SIZE (14UL)
#define SIGNATURE_OFFSETS_START            (2UL)
#define DATA_START (SIGNATURE_OFFSETS_SERIALIZED_SIZE + SIGNATURE_OFFSETS_START)

/*
  Custom
*/

#define ED25519_PUBKEY_SERIALIZED_SIZE              (32UL)

#define SECP256R1_PUBKEY_SERIALIZED_SIZE            (33UL)

#define SECP256K1_PUBKEY_SERIALIZED_SIZE            (20UL)
#define SECP256K1_SIGNATURE_OFFSETS_SERIALIZED_SIZE (11UL)
#define SECP256K1_SIGNATURE_OFFSETS_START            (1UL)
#define SECP256K1_DATA_START (SECP256K1_SIGNATURE_OFFSETS_SERIALIZED_SIZE + SECP256K1_SIGNATURE_OFFSETS_START)

FD_STATIC_ASSERT( sizeof( fd_ed25519_signature_offsets_t )==SIGNATURE_OFFSETS_SERIALIZED_SIZE, fd_ballet );
FD_STATIC_ASSERT( sizeof( fd_secp256k1_signature_offsets_t )==SECP256K1_SIGNATURE_OFFSETS_SERIALIZED_SIZE, fd_ballet );

/*
  Common code
*/

/* fd_precompile_get_instr_data fetches data across instructions.
   In Agave, the 2 precompiles have slightly different behavior:
   1. Ed25519 has 16-bit instr index vs Secp256k1 has 8-bit
   2. Ed25519 accepts instr index==0xFFFF as a special value to indicate
      the current instruction, Secp256k1 doesn't have this feature
   3. Ed25519 always return InvalidDataOffsets, while Secp256k1 can
      return InvalidDataOffsets or InvalidSignature
   All these differences are completely useless, so we unify the logic.
   We handle the special case of index==0xFFFF as in Ed25519.
   We handle errors as in Secp256k1. */
static inline int
fd_precompile_get_instr_data( fd_exec_instr_ctx_t * ctx,
                              ushort                index,
                              ushort                offset,
                              ushort                sz,
                              uchar const **        res ) {
  uchar const * data;
  ulong         data_sz;
  /* The special value index==USHORT_MAX means current instruction.
     This feature has been introduced for ed25519, but not for secp256k1 where
     index is 1-byte only.
     So, fortunately, we can use the same function.
     https://github.com/anza-xyz/agave/blob/v1.18.12/sdk/src/ed25519_instruction.rs#L161-L163
     https://github.com/anza-xyz/agave/blob/v1.18.12/sdk/src/secp256k1_instruction.rs#L1018 */
  if( index==USHORT_MAX ) {

    /* Use current instruction data */
    data    = ctx->instr->data;
    data_sz = ctx->instr->data_sz;

  } else {

    if( FD_UNLIKELY( index>=TXN( ctx->txn_in->txn )->instr_cnt ) )
      return FD_EXECUTOR_PRECOMPILE_ERR_DATA_OFFSET;

    fd_txn_t const *       txn     = TXN( ctx->txn_in->txn );
    uchar const *          payload = ctx->txn_in->txn->payload;
    fd_txn_instr_t const * instr   = &txn->instr[ index ];

    data    = fd_txn_get_instr_data( instr, payload );
    data_sz = instr->data_sz;

  }

  if( FD_UNLIKELY( (ulong)offset+(ulong)sz > data_sz ) )  /* (offset+sz) in [0,2^17) */
    return FD_EXECUTOR_PRECOMPILE_ERR_SIGNATURE;

  *res = data + offset;
  return 0;
}

/*
  Ed25519
*/

int
fd_precompile_ed25519_verify( fd_exec_instr_ctx_t * ctx ) {

  uchar const * data    = ctx->instr->data;
  ulong         data_sz = ctx->instr->data_sz;

  /* https://github.com/anza-xyz/agave/blob/v1.18.12/sdk/src/ed25519_instruction.rs#L90-L96
     note: this part is really silly and in fact in leaves out the edge case [0, 0].

     Our implementation does the following:
     1. assert that there's enough data to deser 1+ fd_ed25519_sig_offsets
        (in particular, data[0] is accessible)
        - in the unlikely case, check for the Agave edge case
     2. if data[0]==0 return
     3. compute and check expected size */
  if( FD_UNLIKELY( data_sz < DATA_START ) ) {
    if( FD_UNLIKELY( data_sz == 2 && data[0] == 0 ) ) {
      return FD_EXECUTOR_INSTR_SUCCESS;
    }
    ctx->txn_out->err.custom_err = FD_EXECUTOR_PRECOMPILE_ERR_INSTR_DATA_SIZE;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  ulong sig_cnt = data[0];
  if( FD_UNLIKELY( sig_cnt==0 ) ) {
    ctx->txn_out->err.custom_err = FD_EXECUTOR_PRECOMPILE_ERR_INSTR_DATA_SIZE;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* https://github.com/anza-xyz/agave/blob/v1.18.12/sdk/src/ed25519_instruction.rs#L97-L103 */
  ulong expected_data_size = sig_cnt * SIGNATURE_OFFSETS_SERIALIZED_SIZE + SIGNATURE_OFFSETS_START;
  if( FD_UNLIKELY( data_sz < expected_data_size ) ) {
    ctx->txn_out->err.custom_err = FD_EXECUTOR_PRECOMPILE_ERR_INSTR_DATA_SIZE;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  ulong off = SIGNATURE_OFFSETS_START;
  for( ulong i = 0; i < sig_cnt; ++i ) {
    fd_ed25519_signature_offsets_t const * sigoffs = (const fd_ed25519_signature_offsets_t *) (data + off);
    off += SIGNATURE_OFFSETS_SERIALIZED_SIZE;

    /* https://github.com/anza-xyz/agave/blob/v1.18.12/sdk/src/ed25519_instruction.rs#L110-L112 */
    // ???

    /* https://github.com/anza-xyz/agave/blob/v1.18.12/sdk/src/ed25519_instruction.rs#L114-L121 */
    uchar const * sig = NULL;
    int err = fd_precompile_get_instr_data( ctx,
                                            sigoffs->sig_instr_idx,
                                            sigoffs->sig_offset,
                                            SIGNATURE_SERIALIZED_SIZE,
                                            &sig );
    if( FD_UNLIKELY( err ) ) {
      ctx->txn_out->err.custom_err = (uint)err;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }

    /* https://github.com/anza-xyz/agave/blob/v1.18.12/sdk/src/ed25519_instruction.rs#L123-L124
       Note: we parse the signature as part of fd_ed25519_verify.
       Because of this, the return error code might be different from Agave in some edge cases. */

    /* https://github.com/anza-xyz/agave/blob/v1.18.12/sdk/src/ed25519_instruction.rs#L126-L133 */
    uchar const * pubkey = NULL;
    err = fd_precompile_get_instr_data( ctx,
                                        sigoffs->pubkey_instr_idx,
                                        sigoffs->pubkey_offset,
                                        ED25519_PUBKEY_SERIALIZED_SIZE,
                                        &pubkey );
    if( FD_UNLIKELY( err ) ) {
      ctx->txn_out->err.custom_err = (uint)err;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }

    /* https://github.com/anza-xyz/agave/blob/v1.18.12/sdk/src/ed25519_instruction.rs#L135-L136
       Note: we parse the public key as part of fd_ed25519_verify.
       Because of this, the return error code might be different from Agave in some edge cases. */

    /* https://github.com/anza-xyz/agave/blob/v1.18.12/sdk/src/ed25519_instruction.rs#L138-L145 */
    uchar const * msg = NULL;
    ushort msg_sz = sigoffs->msg_data_sz;
    err = fd_precompile_get_instr_data( ctx,
                                        sigoffs->msg_instr_idx,
                                        sigoffs->msg_offset,
                                        msg_sz,
                                        &msg );
    if( FD_UNLIKELY( err ) ) {
      ctx->txn_out->err.custom_err = (uint)err;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }

    /* https://github.com/anza-xyz/agave/blob/v1.18.12/sdk/src/ed25519_instruction.rs#L147-L149 */
    fd_sha512_t sha[1];
    if( FD_UNLIKELY( fd_ed25519_verify( msg, msg_sz, sig, pubkey, sha )!=FD_ED25519_SUCCESS ) ) {
      ctx->txn_out->err.custom_err = FD_EXECUTOR_PRECOMPILE_ERR_SIGNATURE;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}

#if FD_HAS_S2NBIGNUM

/*
  Secp256K1
*/

int
fd_precompile_secp256k1_verify( fd_exec_instr_ctx_t * ctx ) {

  uchar const * data    = ctx->instr->data;
  ulong         data_sz = ctx->instr->data_sz;

  /* https://github.com/anza-xyz/agave/blob/v1.18.12/sdk/src/secp256k1_instruction.rs#L934-L947
     see comment in ed25519, here the special case is [0] instead of [0, 0] */
  if( FD_UNLIKELY( data_sz < SECP256K1_DATA_START ) ) {
    if( FD_UNLIKELY( data_sz == 1 && data[0] == 0 ) ) {
      return FD_EXECUTOR_INSTR_SUCCESS;
    }
    ctx->txn_out->err.custom_err = FD_EXECUTOR_PRECOMPILE_ERR_INSTR_DATA_SIZE;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/sdk/src/secp256k1_instruction.rs#L938-L947 */
  ulong sig_cnt = data[0];
  if( FD_UNLIKELY( sig_cnt==0 && data_sz>1 ) ) {
    ctx->txn_out->err.custom_err = FD_EXECUTOR_PRECOMPILE_ERR_INSTR_DATA_SIZE;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* https://github.com/anza-xyz/agave/blob/v1.18.12/sdk/src/secp256k1_instruction.rs#L948-L953 */
  ulong expected_data_size = sig_cnt * SECP256K1_SIGNATURE_OFFSETS_SERIALIZED_SIZE + SECP256K1_SIGNATURE_OFFSETS_START;
  if( FD_UNLIKELY( data_sz < expected_data_size ) ) {
    ctx->txn_out->err.custom_err = FD_EXECUTOR_PRECOMPILE_ERR_INSTR_DATA_SIZE;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  ulong off = SECP256K1_SIGNATURE_OFFSETS_START;
  for( ulong i = 0; i < sig_cnt; ++i ) {
    fd_secp256k1_signature_offsets_t const * sigoffs = (const fd_secp256k1_signature_offsets_t *) (data + off);
    off += SECP256K1_SIGNATURE_OFFSETS_SERIALIZED_SIZE;

    /* https://github.com/anza-xyz/agave/blob/v1.18.12/sdk/src/secp256k1_instruction.rs#L960-L961 */
    // ???

    /* https://github.com/anza-xyz/agave/blob/v1.18.12/sdk/src/secp256k1_instruction.rs#L963-L973
       Note: for whatever reason, Agave returns InvalidInstructionDataSize instead of InvalidDataOffsets.
       We just return the err as is. */
    uchar const * sig = NULL;
    int err = fd_precompile_get_instr_data( ctx,
                                            sigoffs->sig_instr_idx,
                                            sigoffs->sig_offset,
                                            SIGNATURE_SERIALIZED_SIZE + 1, /* extra byte is recovery id */
                                            &sig );
    if( FD_UNLIKELY( err ) ) {
      ctx->txn_out->err.custom_err = (uint)err;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }

    /* https://github.com/anza-xyz/agave/blob/v1.18.12/sdk/src/secp256k1_instruction.rs#L975-L981
       Note: we parse the signature and recovery id as part of fd_secp256k1_recover.
       Because of this, the return error code might be different from Agave in some edge cases. */
    int recovery_id = (int)sig[SIGNATURE_SERIALIZED_SIZE]; /* extra byte is recovery id */

    /* https://github.com/anza-xyz/agave/blob/v1.18.12/sdk/src/secp256k1_instruction.rs#L983-L989 */
    uchar const * eth_address = NULL;
    err = fd_precompile_get_instr_data( ctx,
                                        sigoffs->pubkey_instr_idx,
                                        sigoffs->pubkey_offset,
                                        SECP256K1_PUBKEY_SERIALIZED_SIZE,
                                        &eth_address );
    if( FD_UNLIKELY( err ) ) {
      ctx->txn_out->err.custom_err = (uint)err;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }

    /* https://github.com/anza-xyz/agave/blob/v1.18.12/sdk/src/secp256k1_instruction.rs#L991-L997 */
    uchar const * msg = NULL;
    ushort msg_sz = sigoffs->msg_data_sz;
    err = fd_precompile_get_instr_data( ctx,
                                        sigoffs->msg_instr_idx,
                                        sigoffs->msg_offset,
                                        msg_sz,
                                        &msg );
    if( FD_UNLIKELY( err ) ) {
      ctx->txn_out->err.custom_err = (uint)err;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }

    /* https://github.com/anza-xyz/agave/blob/v1.18.12/sdk/src/secp256k1_instruction.rs#L999-L1001 */
    uchar msg_hash[ FD_KECCAK256_HASH_SZ ];
    fd_keccak256_hash( msg, msg_sz, msg_hash );

    /* https://github.com/anza-xyz/agave/blob/v1.18.12/sdk/src/secp256k1_instruction.rs#L1003-L1008 */
    uchar pubkey[64];
    if ( FD_UNLIKELY( fd_secp256k1_recover( pubkey, msg_hash, sig, recovery_id ) == NULL ) ) {
      ctx->txn_out->err.custom_err = FD_EXECUTOR_PRECOMPILE_ERR_SIGNATURE;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }

    /* https://github.com/anza-xyz/agave/blob/v1.18.12/sdk/src/secp256k1_instruction.rs#L1009-L1013 */
    uchar pubkey_hash[ FD_KECCAK256_HASH_SZ ];
    fd_keccak256_hash( pubkey, 64, pubkey_hash );

    if( FD_UNLIKELY( memcmp( eth_address, pubkey_hash+(FD_KECCAK256_HASH_SZ-SECP256K1_PUBKEY_SERIALIZED_SIZE), SECP256K1_PUBKEY_SERIALIZED_SIZE ) ) ) {
      ctx->txn_out->err.custom_err = FD_EXECUTOR_PRECOMPILE_ERR_SIGNATURE;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/*
  Secp256r1
*/

int
fd_precompile_secp256r1_verify( fd_exec_instr_ctx_t * ctx ) {
  if( FD_UNLIKELY( !FD_FEATURE_ACTIVE_BANK( ctx->bank, enable_secp256r1_precompile ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
  }

  uchar const * data    = ctx->instr->data;
  ulong         data_sz = ctx->instr->data_sz;

  /* ... */
  if( FD_UNLIKELY( data_sz < DATA_START ) ) {
    ctx->txn_out->err.custom_err = FD_EXECUTOR_PRECOMPILE_ERR_INSTR_DATA_SIZE;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  ulong sig_cnt = data[0];
  if( FD_UNLIKELY( sig_cnt==0UL ) ) {
    ctx->txn_out->err.custom_err = FD_EXECUTOR_PRECOMPILE_ERR_INSTR_DATA_SIZE;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.3.1/precompiles/src/secp256r1.rs#L30 */
  if( FD_UNLIKELY( sig_cnt>8UL ) ) {
    ctx->txn_out->err.custom_err = FD_EXECUTOR_PRECOMPILE_ERR_INSTR_DATA_SIZE;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* ... */
  ulong expected_data_size = sig_cnt * SIGNATURE_OFFSETS_SERIALIZED_SIZE + SIGNATURE_OFFSETS_START;
  if( FD_UNLIKELY( data_sz < expected_data_size ) ) {
    ctx->txn_out->err.custom_err = FD_EXECUTOR_PRECOMPILE_ERR_INSTR_DATA_SIZE;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  ulong off = SIGNATURE_OFFSETS_START;
  for( ulong i = 0; i < sig_cnt; ++i ) {
    fd_secp256r1_signature_offsets_t const * sigoffs = (const fd_secp256r1_signature_offsets_t *) (data + off);
    off += SIGNATURE_OFFSETS_SERIALIZED_SIZE;

    /* ... */
    uchar const * sig = NULL;
    int err = fd_precompile_get_instr_data( ctx,
                                            sigoffs->sig_instr_idx,
                                            sigoffs->sig_offset,
                                            SIGNATURE_SERIALIZED_SIZE,
                                            &sig );
    if( FD_UNLIKELY( err ) ) {
      ctx->txn_out->err.custom_err = (uint)err;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }

    /* ... */
    uchar const * pubkey = NULL;
    err = fd_precompile_get_instr_data( ctx,
                                        sigoffs->pubkey_instr_idx,
                                        sigoffs->pubkey_offset,
                                        SECP256R1_PUBKEY_SERIALIZED_SIZE,
                                        &pubkey );
    if( FD_UNLIKELY( err ) ) {
      ctx->txn_out->err.custom_err = (uint)err;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }

    /* ... */
    uchar const * msg = NULL;
    ushort msg_sz = sigoffs->msg_data_sz;
    err = fd_precompile_get_instr_data( ctx,
                                        sigoffs->msg_instr_idx,
                                        sigoffs->msg_offset,
                                        msg_sz,
                                        &msg );
    if( FD_UNLIKELY( err ) ) {
      ctx->txn_out->err.custom_err = (uint)err;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }

    /* ... */
    fd_sha256_t sha[1];
    if( FD_UNLIKELY( fd_secp256r1_verify( msg, msg_sz, sig, pubkey, sha )!=FD_SECP256R1_SUCCESS ) ) {
      ctx->txn_out->err.custom_err = FD_EXECUTOR_PRECOMPILE_ERR_SIGNATURE;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}

static const fd_precompile_program_t precompiles[] = {
    { &fd_solana_secp256r1_program_id,          offsetof(fd_features_t, enable_secp256r1_precompile), fd_precompile_secp256r1_verify },
    { &fd_solana_keccak_secp_256k_program_id,   NO_ENABLE_FEATURE_ID,                                 fd_precompile_secp256k1_verify },
    { &fd_solana_ed25519_sig_verify_program_id, NO_ENABLE_FEATURE_ID,                                 fd_precompile_ed25519_verify   },
    {0}
};

fd_precompile_program_t const *
fd_precompiles( void ) {
  return precompiles;
}

#define MAP_PERFECT_NAME fd_native_precompile_program_fn_lookup_tbl
#define MAP_PERFECT_LG_TBL_SZ 2
#define MAP_PERFECT_T fd_native_prog_info_t
#define MAP_PERFECT_HASH_C 63546U
#define MAP_PERFECT_KEY key.uc
#define MAP_PERFECT_KEY_T fd_pubkey_t const *
#define MAP_PERFECT_ZERO_KEY  (0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0)
#define MAP_PERFECT_COMPLEX_KEY 1
#define MAP_PERFECT_KEYS_EQUAL(k1,k2) (!memcmp( (k1), (k2), 32UL ))

#define PERFECT_HASH( u ) (((MAP_PERFECT_HASH_C*(u))>>30)&0x3U)

#define MAP_PERFECT_HASH_PP( a00,a01,a02,a03,a04,a05,a06,a07,a08,a09,a10,a11,a12,a13,a14,a15, \
                             a16,a17,a18,a19,a20,a21,a22,a23,a24,a25,a26,a27,a28,a29,a30,a31) \
                                          PERFECT_HASH( (a00 | (a01<<8)) )
#define MAP_PERFECT_HASH_R( ptr ) PERFECT_HASH( fd_uint_load_2( (uchar const *)ptr ) )

#define MAP_PERFECT_0 ( ED25519_SV_PROG_ID  ), .fn = fd_precompile_ed25519_verify
#define MAP_PERFECT_1 ( KECCAK_SECP_PROG_ID ), .fn = fd_precompile_secp256k1_verify
#define MAP_PERFECT_2 ( SECP256R1_PROG_ID   ), .fn = fd_precompile_secp256r1_verify

#include "../../../util/tmpl/fd_map_perfect.c"
#undef PERFECT_HASH

fd_exec_instr_fn_t
fd_executor_lookup_native_precompile_program( fd_pubkey_t const * pubkey ) {
  const fd_native_prog_info_t null_function = {0};
  return fd_native_precompile_program_fn_lookup_tbl_query( pubkey, &null_function )->fn;
}

#else /* !FD_HAS_S2NBIGNUM */

fd_precompile_program_t const *
fd_precompiles( void ) {
  FD_LOG_ERR(( "This build does not include s2n-bignum, which is required to run a validator.\n"
               "To install s2n-bignum, re-run ./deps.sh, make distclean, and make -j" ));
  return NULL;
}

fd_exec_instr_fn_t
fd_executor_lookup_native_precompile_program( fd_pubkey_t const * pubkey ) {
  (void)pubkey;
  FD_LOG_ERR(( "This build does not include s2n-bignum, which is required to run a validator.\n"
               "To install s2n-bignum, re-run ./deps.sh, make distclean, and make -j" ));
  return NULL;
}

#endif /* FD_HAS_S2NBIGNUM */
