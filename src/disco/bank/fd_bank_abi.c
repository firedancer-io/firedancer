
#include "fd_bank_abi.h"
#include "../../flamenco/runtime/fd_system_ids_pp.h"

#define ABI_ALIGN( x ) __attribute__((packed)) __attribute__((aligned(x)))

#define MAP_PERFECT_NAME      fd_bank_abi_builtin_keys_and_sysvars_tbl
#define MAP_PERFECT_LG_TBL_SZ 5
#define MAP_PERFECT_T         fd_acct_addr_t
#define MAP_PERFECT_HASH_C    1402126759U
#define MAP_PERFECT_KEY       b
#define MAP_PERFECT_KEY_T     fd_acct_addr_t const *
#define MAP_PERFECT_ZERO_KEY  (0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0)
#define MAP_PERFECT_COMPLEX_KEY 1
#define MAP_PERFECT_KEYS_EQUAL(k1,k2) (!memcmp( (k1), (k2), 32UL ))

#define PERFECT_HASH( u ) (((MAP_PERFECT_HASH_C*(u))>>27)&0x1FU)

#define MAP_PERFECT_HASH_PP( a00,a01,a02,a03,a04,a05,a06,a07,a08,a09,a10,a11,a12,a13,a14,a15, \
                             a16,a17,a18,a19,a20,a21,a22,a23,a24,a25,a26,a27,a28,a29,a30,a31) \
                                          PERFECT_HASH( (a08 | (a09<<8) | (a10<<16) | (a11<<24)) )
#define MAP_PERFECT_HASH_R( ptr ) PERFECT_HASH( fd_uint_load_4( (uchar const *)ptr->b + 8UL ) )

/* This list is exactly what Lab's is_builtin_key_or_sysvar checks. */
/* Sysvars */
#define MAP_PERFECT_0  ( SYSVAR_CLOCK_ID          ),
#define MAP_PERFECT_1  ( SYSVAR_EPOCH_SCHED_ID    ),
#define MAP_PERFECT_2  ( SYSVAR_FEES_ID           ),
#define MAP_PERFECT_3  ( SYSVAR_RECENT_BLKHASH_ID ),
#define MAP_PERFECT_4  ( SYSVAR_RENT_ID           ),
#define MAP_PERFECT_5  ( SYSVAR_REWARDS_ID        ),
#define MAP_PERFECT_6  ( SYSVAR_SLOT_HASHES_ID    ),
#define MAP_PERFECT_7  ( SYSVAR_SLOT_HIST_ID      ),
#define MAP_PERFECT_8  ( SYSVAR_STAKE_HIST_ID     ),
#define MAP_PERFECT_9  ( SYSVAR_INSTRUCTIONS_ID   ),
#define MAP_PERFECT_10 ( SYSVAR_EPOCH_REWARDS_ID  ),
#define MAP_PERFECT_11 ( SYSVAR_LAST_RESTART_ID   ),
/* Programs */
#define MAP_PERFECT_12 ( CONFIG_PROG_ID           ),
#define MAP_PERFECT_13 ( FEATURE_ID               ),
#define MAP_PERFECT_14 ( NATIVE_LOADER_ID         ),
#define MAP_PERFECT_15 ( STAKE_PROG_ID            ),
#define MAP_PERFECT_16 ( STAKE_CONFIG_PROG_ID     ),
#define MAP_PERFECT_17 ( VOTE_PROG_ID             ),
#define MAP_PERFECT_18 ( SYS_PROG_ID              ),
#define MAP_PERFECT_19 ( BPF_LOADER_1_PROG_ID     ),
#define MAP_PERFECT_20 ( BPF_LOADER_2_PROG_ID     ),
#define MAP_PERFECT_21 ( BPF_UPGRADEABLE_PROG_ID  ),

#include "../../util/tmpl/fd_map_perfect.c"

typedef struct ABI_ALIGN(1UL) {
  uchar key[ 32UL ];
} sanitized_txn_abi_pubkey_t;

FD_STATIC_ASSERT( sizeof(sanitized_txn_abi_pubkey_t) == 32UL, "messed up size" );
FD_STATIC_ASSERT( alignof(sanitized_txn_abi_pubkey_t) == 1UL, "messed up size" );

typedef struct ABI_ALIGN(1UL) {
  uchar signature[ 64UL ];
} sanitized_txn_abi_signature_t;

FD_STATIC_ASSERT( sizeof(sanitized_txn_abi_signature_t) == 64UL, "messed up size" );
FD_STATIC_ASSERT( alignof(sanitized_txn_abi_signature_t) == 1UL, "messed up size" );

typedef struct ABI_ALIGN(8UL) {
  uchar * accounts;
  ulong   accounts_cap;
  ulong   accounts_cnt;

  uchar * data;
  ulong   data_cap;
  ulong   data_cnt;

  uchar program_id_index;
} sanitized_txn_abi_compiled_instruction_t;

FD_STATIC_ASSERT( sizeof(sanitized_txn_abi_compiled_instruction_t) == 56UL, "messed up size" );
FD_STATIC_ASSERT( alignof(sanitized_txn_abi_compiled_instruction_t) == 8UL, "messed up size" );

typedef struct ABI_ALIGN(1UL) {
  uchar num_required_signatures;
  uchar num_readonly_signed_accounts;
  uchar num_readonly_unsigned_accounts;
} sanitized_txn_abi_message_header_t;

FD_STATIC_ASSERT( sizeof(sanitized_txn_abi_message_header_t) == 3UL, "messed up size" );
FD_STATIC_ASSERT( alignof(sanitized_txn_abi_message_header_t) == 1UL, "messed up size" );

typedef struct ABI_ALIGN(8UL) {
  sanitized_txn_abi_pubkey_t * account_keys;
  ulong account_keys_cap;
  ulong account_keys_cnt;

  sanitized_txn_abi_compiled_instruction_t * instructions;
  ulong instructions_cap;
  ulong instructions_cnt;

  uchar recent_blockhash[ 32 ];

  sanitized_txn_abi_message_header_t header;
} sanitized_txn_abi_legacy_message0_t;

FD_STATIC_ASSERT( sizeof(sanitized_txn_abi_legacy_message0_t) == 88UL, "messed up size" );
FD_STATIC_ASSERT( alignof(sanitized_txn_abi_legacy_message0_t) == 8UL, "messed up size" );

typedef struct ABI_ALIGN(8UL) {
  uchar * is_writable_account_cache;
  ulong   is_writable_account_cache_cap;
  ulong   is_writable_account_cache_cnt;

  union __attribute__((__packed__)) __attribute__((aligned(8UL))) {
    struct __attribute__((__packed__)) __attribute__((aligned(8UL))) {
      ulong tag; /* Niche tag encoding.  Value 0 is borrowed, nonzero is owned. */
      sanitized_txn_abi_legacy_message0_t * borrowed;
    };

    struct __attribute__((__packed__)) __attribute__((aligned(8UL))) {
      sanitized_txn_abi_legacy_message0_t owned;
    };
  } message;
} sanitized_txn_abi_legacy_message1_t;

FD_STATIC_ASSERT( sizeof(sanitized_txn_abi_legacy_message1_t) == 112UL, "messed up size" );
FD_STATIC_ASSERT( alignof(sanitized_txn_abi_legacy_message1_t) == 8UL, "messed up size" );

typedef struct ABI_ALIGN(8UL) {
  uchar * writable_indexes;
  ulong   writable_indexes_cap;
  ulong   writable_indexes_cnt;

  uchar * readonly_indexes;
  ulong   readonly_indexes_cap;
  ulong   readonly_indexes_cnt;

  uchar account_key[ 32 ];
} sanitized_txn_abi_v0_message_address_table_lookup_t;

FD_STATIC_ASSERT( sizeof(sanitized_txn_abi_v0_message_address_table_lookup_t) == 80UL, "messed up size" );
FD_STATIC_ASSERT( alignof(sanitized_txn_abi_v0_message_address_table_lookup_t) == 8UL, "messed up size" );

typedef struct ABI_ALIGN(8UL) {
  sanitized_txn_abi_pubkey_t * account_keys;
  ulong                        account_keys_cap;
  ulong                        account_keys_cnt;

  sanitized_txn_abi_compiled_instruction_t * instructions;
  ulong                                      instructions_cap;
  ulong                                      instructions_cnt;

  sanitized_txn_abi_v0_message_address_table_lookup_t * address_table_lookups;
  ulong                                                 address_table_lookups_cap;
  ulong                                                 address_table_lookups_cnt;

  uchar recent_blockhash[ 32 ];

  sanitized_txn_abi_message_header_t header;
} sanitized_txn_abi_v0_message_t;

FD_STATIC_ASSERT( sizeof(sanitized_txn_abi_v0_message_t) == 112UL, "messed up size" );
FD_STATIC_ASSERT( alignof(sanitized_txn_abi_v0_message_t) == 8UL, "messed up size" );

typedef struct ABI_ALIGN(8UL) {
  sanitized_txn_abi_pubkey_t * writable;
  ulong                        writable_cap;
  ulong                        writable_cnt;

  sanitized_txn_abi_pubkey_t * readable;
  ulong                        readable_cap;
  ulong                        readable_cnt;
} sanitized_txn_abi_v0_loaded_addresses_t;

FD_STATIC_ASSERT( sizeof(sanitized_txn_abi_v0_loaded_addresses_t) == 48UL, "messed up size" );
FD_STATIC_ASSERT( alignof(sanitized_txn_abi_v0_loaded_addresses_t) == 8UL, "messed up size" );

typedef struct ABI_ALIGN(8UL) {
  uchar * is_writable_account_cache;
  ulong   is_writable_account_cache_cap;
  ulong   is_writable_account_cache_cnt;

  union __attribute__((__packed__)) __attribute__((aligned(8UL))) {
    struct __attribute__((__packed__)) __attribute__((aligned(8UL))) {
      ulong tag; /* Niche tag encoding.  Value 0 is borrowed, nonzero is owned. */
      sanitized_txn_abi_v0_message_t * borrowed;
    };

    struct __attribute__((__packed__)) __attribute__((aligned(8UL))) {
      sanitized_txn_abi_v0_message_t owned;
    };
  } message;

  union __attribute__((__packed__)) __attribute__((aligned(8UL))) {
    struct __attribute__((__packed__)) __attribute__((aligned(8UL))) {
      ulong tag; /* Niche tag encoding.  Value 0 is borrowed, nonzero is owned. */
      sanitized_txn_abi_v0_loaded_addresses_t * borrowed;
    };

    struct __attribute__((__packed__)) __attribute__((aligned(8UL))) {
      sanitized_txn_abi_v0_loaded_addresses_t owned;
    };
  } loaded_addresses;
} sanitized_txn_abi_v0_loaded_msg_t;

FD_STATIC_ASSERT( sizeof(sanitized_txn_abi_v0_loaded_msg_t) == 184UL, "messed up size" );
FD_STATIC_ASSERT( alignof(sanitized_txn_abi_v0_loaded_msg_t) == 8UL, "messed up size" );

typedef union ABI_ALIGN(8UL) {
  struct ABI_ALIGN(8UL) {
    ulong tag; /* Niche tag encoding.  Value 0 is legacy, nonzero is v0. */
    sanitized_txn_abi_legacy_message1_t legacy;
  };

  sanitized_txn_abi_v0_loaded_msg_t v0; /* No tag. First field is always non-NULL, so rustc can disciminate from legacy. */
} sanitized_txn_abi_message_t;

FD_STATIC_ASSERT( sizeof(sanitized_txn_abi_message_t) == 184UL, "messed up size" );
FD_STATIC_ASSERT( alignof(sanitized_txn_abi_message_t) == 8UL, "messed up size" );

FD_STATIC_ASSERT( offsetof(sanitized_txn_abi_message_t, v0) == 0UL, "messed up size" );
FD_STATIC_ASSERT( offsetof(sanitized_txn_abi_message_t, legacy) == 8UL, "messed up size" );

struct ABI_ALIGN(8UL) fd_bank_abi_txn_private {
  sanitized_txn_abi_signature_t * signatures;
  ulong                           signatures_cap;
  ulong                           signatures_cnt;

  sanitized_txn_abi_message_t message;

  uchar message_hash[ 32 ];
  uchar is_simple_vote_tx;
};

FD_STATIC_ASSERT( sizeof(struct fd_bank_abi_txn_private) == 248UL, "messed up size" );
FD_STATIC_ASSERT( alignof(struct fd_bank_abi_txn_private) == 8UL, "messed up size" );

FD_STATIC_ASSERT( offsetof(struct fd_bank_abi_txn_private, signatures) == 0UL, "messed up size" );
FD_STATIC_ASSERT( offsetof(struct fd_bank_abi_txn_private, message) == 24UL, "messed up size" );
FD_STATIC_ASSERT( offsetof(struct fd_bank_abi_txn_private, message_hash) == 208UL, "messed up size" );
FD_STATIC_ASSERT( offsetof(struct fd_bank_abi_txn_private, is_simple_vote_tx) == 240UL, "messed up size" );

extern int
fd_ext_bank_sanitized_txn_load_addresess( void const * bank,
                                          void *       address_table_lookups,
                                          ulong        address_table_lookups_cnt,
                                          void *       out_sidecar );

static int
is_key_called_as_program( fd_txn_t * txn, ushort key_index ) {
  for( ushort i=0; i<txn->instr_cnt; i++ ) {
    fd_txn_instr_t * instr = &txn->instr[ i ];
    if( FD_UNLIKELY( instr->program_id==key_index ) ) return 1;
  }
  return 0;
}

static const uchar BPF_UPGRADEABLE_PROG_ID1[32] = { BPF_UPGRADEABLE_PROG_ID };

static int
is_upgradeable_loader_present( fd_txn_t * txn, uchar * payload, sanitized_txn_abi_pubkey_t * loaded_addresses ) {
  for( ushort i=0; i<txn->acct_addr_cnt; i++ ) {
    if( FD_UNLIKELY( !memcmp( payload + txn->acct_addr_off + i*32UL, BPF_UPGRADEABLE_PROG_ID1, 32UL ) ) ) return 1;
  }
  for( ushort i=0; i<txn->addr_table_adtl_cnt; i++ ) {
    if( FD_UNLIKELY( !memcmp( loaded_addresses + i, BPF_UPGRADEABLE_PROG_ID1, 32UL ) ) ) return 1;
  }
  return 0;
}

int
fd_bank_abi_txn_init( fd_bank_abi_txn_t * out_txn,
                      uchar *             out_sidecar,
                      void const *        bank,
                      fd_blake3_t *       blake3,
                      uchar *             payload,
                      ulong               payload_sz,
                      fd_txn_t *          txn,
                      int                 is_simple_vote ) {
  out_txn->signatures_cnt = txn->signature_cnt;
  out_txn->signatures_cap = txn->signature_cnt;
  out_txn->signatures     = (void*)(payload + txn->signature_off);

  fd_blake3_init( blake3 );
  fd_blake3_append( blake3, "solana-tx-message-v1", 20UL );
  fd_blake3_append( blake3, payload + txn->message_off, payload_sz - txn->message_off );
  fd_blake3_fini( blake3, out_txn->message_hash );

  out_txn->is_simple_vote_tx = !!is_simple_vote;

  if( FD_LIKELY( txn->transaction_version==FD_TXN_VLEGACY ) ) {
    sanitized_txn_abi_legacy_message1_t * legacy = &out_txn->message.legacy;
    sanitized_txn_abi_legacy_message0_t * message = &legacy->message.owned;

    out_txn->message.tag = 0UL;

    legacy->is_writable_account_cache_cnt = txn->acct_addr_cnt;
    legacy->is_writable_account_cache_cap = txn->acct_addr_cnt;
    legacy->is_writable_account_cache     = out_sidecar;
    int _is_upgradeable_loader_present = is_upgradeable_loader_present( txn, payload, NULL );
    for( ushort i=0; i<txn->acct_addr_cnt; i++ ) {
      int is_writable = fd_txn_is_writable( txn, i ) &&
                        /* Solana Labs does this check, but we don't need to here because pack
                           rejects these transactions before they make it to the bank.

                           !fd_bank_abi_builtin_keys_and_sysvars_tbl_contains( (const fd_acct_addr_t*)(payload + txn->acct_addr_off + i*32UL) ) */
                        (!is_key_called_as_program( txn, i ) || _is_upgradeable_loader_present);
      legacy->is_writable_account_cache[ i ] = !!is_writable;
    }
    out_sidecar += txn->acct_addr_cnt;
    out_sidecar = (void*)fd_ulong_align_up( (ulong)out_sidecar, 8UL );

    message->account_keys_cnt = txn->acct_addr_cnt;
    message->account_keys_cap = txn->acct_addr_cnt;
    message->account_keys     = (void*)(payload + txn->acct_addr_off);

    message->instructions_cnt = txn->instr_cnt;
    message->instructions_cap = txn->instr_cnt;
    message->instructions     = (void*)out_sidecar;
    for( ulong i=0; i<txn->instr_cnt; i++ ) {
      fd_txn_instr_t * instr = &txn->instr[ i ];
      sanitized_txn_abi_compiled_instruction_t * out_instr = &message->instructions[ i ];

      out_instr->accounts_cnt = instr->acct_cnt;
      out_instr->accounts_cap = instr->acct_cnt;
      out_instr->accounts     = payload + instr->acct_off;

      out_instr->data_cnt = instr->data_sz;
      out_instr->data_cap = instr->data_sz;
      out_instr->data     = payload + instr->data_off;

      out_instr->program_id_index = instr->program_id;
    }
    out_sidecar += txn->instr_cnt*sizeof(sanitized_txn_abi_compiled_instruction_t);

    fd_memcpy( message->recent_blockhash, payload + txn->recent_blockhash_off, 32UL );
    message->header.num_required_signatures        = txn->signature_cnt;
    message->header.num_readonly_signed_accounts   = txn->readonly_signed_cnt;
    message->header.num_readonly_unsigned_accounts = txn->readonly_unsigned_cnt;
    return FD_BANK_ABI_TXN_INIT_SUCCESS;
  } else if( FD_LIKELY( txn->transaction_version==FD_TXN_V0 ) ){
    sanitized_txn_abi_v0_loaded_msg_t * v0 = &out_txn->message.v0;
    sanitized_txn_abi_v0_loaded_addresses_t * loaded_addresses = &v0->loaded_addresses.owned;
    sanitized_txn_abi_v0_message_t * message = &v0->message.owned;

    int result = fd_ext_bank_sanitized_txn_load_addresess( bank, (void*)v0->message.owned.address_table_lookups, txn->addr_table_lookup_cnt, out_sidecar );
    if( FD_UNLIKELY( result!=FD_BANK_ABI_TXN_INIT_SUCCESS ) ) return result;

    ulong lut_writable_acct_cnt = fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_WRITABLE_ALT );
    loaded_addresses->writable_cnt = lut_writable_acct_cnt;
    loaded_addresses->writable_cap = lut_writable_acct_cnt;
    loaded_addresses->writable     = (sanitized_txn_abi_pubkey_t*)out_sidecar;
    out_sidecar += 32UL*lut_writable_acct_cnt;

    ulong lut_readonly_acct_cnt = fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_READONLY_ALT );
    loaded_addresses->readable_cnt = lut_readonly_acct_cnt;
    loaded_addresses->readable_cap = lut_readonly_acct_cnt;
    loaded_addresses->readable     = (sanitized_txn_abi_pubkey_t*)out_sidecar;
    out_sidecar += 32UL*lut_readonly_acct_cnt;

    ulong total_acct_cnt = fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_ALL );
    v0->is_writable_account_cache_cnt = total_acct_cnt;
    v0->is_writable_account_cache_cap = total_acct_cnt;
    v0->is_writable_account_cache     = out_sidecar;

    /* This looks like it will be an OOB read because we are passing
       just the writable account hashes, but the readable ones are
       immediately after them in memory, so it's ok. */
    int _is_upgradeable_loader_present = is_upgradeable_loader_present( txn, payload, loaded_addresses->writable );
    for( ushort i=0; i<txn->acct_addr_cnt; i++ ) {
      int is_writable = fd_txn_is_writable( txn, i ) &&
                        /* Solana Labs does this check, but we don't need to here because pack
                           rejects these transactions before they make it to the bank.

                           !fd_bank_abi_builtin_keys_and_sysvars_tbl_contains( (const fd_acct_addr_t*)(payload + txn->acct_addr_off + i*32UL) ) */
                        (!is_key_called_as_program( txn, i ) || _is_upgradeable_loader_present);
      v0->is_writable_account_cache[ i ] = !!is_writable;
    }
    for( ushort i=0; i<txn->addr_table_adtl_writable_cnt; i++ ) {
      /* We do need to check is_builtin_key_or_sysvar here, because pack
         has not yet loaded the address LUT accounts, so it doesn't
         reject these yet. */
      int is_writable = !fd_bank_abi_builtin_keys_and_sysvars_tbl_contains( (const fd_acct_addr_t*)(loaded_addresses->writable + i) ) &&
                        (!is_key_called_as_program( txn, (ushort)(txn->acct_addr_cnt+i) ) || _is_upgradeable_loader_present);
      v0->is_writable_account_cache[ txn->acct_addr_cnt+i ] = !!is_writable;
    }
    for( ushort i=0; i<txn->addr_table_adtl_cnt-txn->addr_table_adtl_writable_cnt; i++ ) {
      v0->is_writable_account_cache[ txn->acct_addr_cnt+txn->addr_table_adtl_writable_cnt+i ] = 0;
    }

    out_sidecar += txn->acct_addr_cnt + txn->addr_table_adtl_cnt;
    out_sidecar = (void*)fd_ulong_align_up( (ulong)out_sidecar, 8UL );

    message->account_keys_cnt = txn->acct_addr_cnt;
    message->account_keys_cap = txn->acct_addr_cnt;
    message->account_keys     = (void*)(payload + txn->acct_addr_off);

    message->instructions_cnt = txn->instr_cnt;
    message->instructions_cap = txn->instr_cnt;
    message->instructions     = (void*)out_sidecar;
    for( ulong i=0; i<txn->instr_cnt; i++ ) {
      fd_txn_instr_t * instr = &txn->instr[ i ];
      sanitized_txn_abi_compiled_instruction_t * out_instr = &message->instructions[ i ];

      out_instr->accounts_cnt = instr->acct_cnt;
      out_instr->accounts_cap = instr->acct_cnt;
      out_instr->accounts     = payload + instr->acct_off;

      out_instr->data_cnt = instr->data_sz;
      out_instr->data_cap = instr->data_sz;
      out_instr->data     = payload + instr->data_off;

      out_instr->program_id_index = instr->program_id;
    }
    out_sidecar += txn->instr_cnt*sizeof(sanitized_txn_abi_compiled_instruction_t);

    fd_memcpy( message->recent_blockhash, payload + txn->recent_blockhash_off, 32UL );
    message->header.num_required_signatures        = txn->signature_cnt;
    message->header.num_readonly_signed_accounts   = txn->readonly_signed_cnt;
    message->header.num_readonly_unsigned_accounts = txn->readonly_unsigned_cnt;

    message->address_table_lookups_cnt = txn->addr_table_lookup_cnt;
    message->address_table_lookups_cap = txn->addr_table_lookup_cnt;
    message->address_table_lookups     = (void*)out_sidecar;
    for( ulong i=0; i<txn->addr_table_lookup_cnt; i++ ) {
      fd_txn_acct_addr_lut_t * lookup = fd_txn_get_address_tables( txn ) + i;
      sanitized_txn_abi_v0_message_address_table_lookup_t * out_lookup = &message->address_table_lookups[ i ];

      out_lookup->writable_indexes_cnt = lookup->writable_cnt;
      out_lookup->writable_indexes_cap = lookup->writable_cnt;
      out_lookup->writable_indexes     = payload + lookup->writable_off;

      out_lookup->readonly_indexes_cnt = lookup->readonly_cnt;
      out_lookup->readonly_indexes_cap = lookup->readonly_cnt;
      out_lookup->readonly_indexes     = payload + lookup->readonly_off;

      fd_memcpy( out_lookup->account_key, payload + lookup->addr_off, 32UL );
    }
    out_sidecar += txn->addr_table_lookup_cnt*sizeof(sanitized_txn_abi_v0_message_address_table_lookup_t);

    return FD_BANK_ABI_TXN_INIT_SUCCESS;
  } else {
    /* A program abort case, unknown transaction version should never make it here. */
    FD_LOG_ERR(( "unknown transaction version %u", txn->transaction_version ));
  }
}
