
#include "fd_bank_abi.h"
#include "../../flamenco/runtime/fd_system_ids_pp.h"
#include "../../flamenco/runtime/fd_system_ids.h"
#include "../../flamenco/types/fd_types.h"
#include "../../disco/pack/fd_pack_unwritable.h"
#include "../../disco/pack/fd_compute_budget_program.h"

#define ABI_ALIGN( x ) __attribute__((packed)) __attribute__((aligned(x)))

/* Lots of these types contain Rust structs with vectors in them.  The
   capacity field of Rust Vec<> objects is declared with
      type Cap = core::num::niche_types::UsizeNoHighBit;
   The compiler takes advantage of this to use that high bit in
   discriminating between members of Rust structs. */
#define ABI_HIGH_BIT 9223372036854775808UL
FD_STATIC_ASSERT( ABI_HIGH_BIT==0x8000000000000000UL, bank_abi_tag );

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
  ulong   accounts_cap;
  uchar * accounts;
  ulong   accounts_cnt;

  ulong   data_cap;
  uchar * data;
  ulong   data_cnt;

  uchar program_id_index;
} sanitized_txn_abi_compiled_instruction_t;

FD_STATIC_ASSERT( sizeof(sanitized_txn_abi_compiled_instruction_t) == 56UL, bank_abi );
FD_STATIC_ASSERT( alignof(sanitized_txn_abi_compiled_instruction_t) == 8UL, bank_abi );
FD_STATIC_ASSERT( offsetof(sanitized_txn_abi_compiled_instruction_t, accounts_cap)==0, bank_abi );
FD_STATIC_ASSERT( offsetof(sanitized_txn_abi_compiled_instruction_t, data_cap)==24, bank_abi );
FD_STATIC_ASSERT( offsetof(sanitized_txn_abi_compiled_instruction_t, program_id_index)==48, bank_abi );

typedef struct ABI_ALIGN(1UL) {
  uchar num_required_signatures;
  uchar num_readonly_signed_accounts;
  uchar num_readonly_unsigned_accounts;
} sanitized_txn_abi_message_header_t;

FD_STATIC_ASSERT( sizeof(sanitized_txn_abi_message_header_t) == 3UL, "messed up size" );
FD_STATIC_ASSERT( alignof(sanitized_txn_abi_message_header_t) == 1UL, "messed up size" );

typedef struct ABI_ALIGN(8UL) {
  ulong account_keys_cap;
  sanitized_txn_abi_pubkey_t * account_keys;
  ulong account_keys_cnt;

  ulong instructions_cap;
  sanitized_txn_abi_compiled_instruction_t * instructions;
  ulong instructions_cnt;

  uchar recent_blockhash[ 32 ];

  sanitized_txn_abi_message_header_t header;
} sanitized_txn_abi_legacy_message0_t;

FD_STATIC_ASSERT( offsetof(sanitized_txn_abi_legacy_message0_t, account_keys_cap)==0, bank_abi );
FD_STATIC_ASSERT( offsetof(sanitized_txn_abi_legacy_message0_t, instructions_cap)==24, bank_abi );
FD_STATIC_ASSERT( offsetof(sanitized_txn_abi_legacy_message0_t, recent_blockhash)==48, bank_abi );
FD_STATIC_ASSERT( offsetof(sanitized_txn_abi_legacy_message0_t, header)==80, bank_abi );
FD_STATIC_ASSERT( sizeof(sanitized_txn_abi_legacy_message0_t) == 88UL, bank_abi );
FD_STATIC_ASSERT( alignof(sanitized_txn_abi_legacy_message0_t) == 8UL, bank_abi );

typedef struct ABI_ALIGN(8UL) {
  ulong   is_writable_account_cache_cap;
  uchar * is_writable_account_cache;
  ulong   is_writable_account_cache_cnt;

  union ABI_ALIGN(8UL) {
    ulong discr;

    /* when discr==ABI_HIGH_BIT */
    struct ABI_ALIGN(8UL) {
      uchar _padding[8];
      sanitized_txn_abi_legacy_message0_t * borrowed;
    };

    /* else */
    sanitized_txn_abi_legacy_message0_t owned;
  } message;
} sanitized_txn_abi_legacy_message1_t;

FD_STATIC_ASSERT( offsetof(sanitized_txn_abi_legacy_message1_t, message)==24UL, bank_abi );
FD_STATIC_ASSERT( sizeof(sanitized_txn_abi_legacy_message1_t) == 112UL, bank_abi );
FD_STATIC_ASSERT( alignof(sanitized_txn_abi_legacy_message1_t) == 8UL, bank_abi );

typedef struct ABI_ALIGN(8UL) {
  ulong   writable_indexes_cap;
  uchar * writable_indexes;
  ulong   writable_indexes_cnt;

  ulong   readonly_indexes_cap;
  uchar * readonly_indexes;
  ulong   readonly_indexes_cnt;

  uchar account_key[ 32 ];
} sanitized_txn_abi_v0_message_address_table_lookup_t;

FD_STATIC_ASSERT( sizeof(sanitized_txn_abi_v0_message_address_table_lookup_t) == 80UL, "messed up size" );
FD_STATIC_ASSERT( alignof(sanitized_txn_abi_v0_message_address_table_lookup_t) == 8UL, "messed up size" );

typedef struct ABI_ALIGN(8UL) {
  ulong                        account_keys_cap;
  sanitized_txn_abi_pubkey_t * account_keys;
  ulong                        account_keys_cnt;

  ulong                                      instructions_cap;
  sanitized_txn_abi_compiled_instruction_t * instructions;
  ulong                                      instructions_cnt;

  ulong                                                 address_table_lookups_cap;
  sanitized_txn_abi_v0_message_address_table_lookup_t * address_table_lookups;
  ulong                                                 address_table_lookups_cnt;

  uchar recent_blockhash[ 32 ];

  sanitized_txn_abi_message_header_t header;
} sanitized_txn_abi_v0_message_t;

FD_STATIC_ASSERT( sizeof(sanitized_txn_abi_v0_message_t) == 112UL, "messed up size" );
FD_STATIC_ASSERT( alignof(sanitized_txn_abi_v0_message_t) == 8UL, "messed up size" );

typedef struct ABI_ALIGN(8UL) {
  ulong                        writable_cap;
  sanitized_txn_abi_pubkey_t * writable;
  ulong                        writable_cnt;

  ulong                        readable_cap;
  sanitized_txn_abi_pubkey_t * readable;
  ulong                        readable_cnt;
} sanitized_txn_abi_v0_loaded_addresses_t;

FD_STATIC_ASSERT( sizeof(sanitized_txn_abi_v0_loaded_addresses_t) == 48UL, "messed up size" );
FD_STATIC_ASSERT( alignof(sanitized_txn_abi_v0_loaded_addresses_t) == 8UL, "messed up size" );

typedef struct ABI_ALIGN(8UL) {
  ulong   is_writable_account_cache_cap;
  uchar * is_writable_account_cache;
  ulong   is_writable_account_cache_cnt;

  union __attribute__((__packed__)) __attribute__((aligned(8UL))) {
    ulong discr;

    /* when discr==ABI_HIGH_BIT */
    struct __attribute__((__packed__)) __attribute__((aligned(8UL))) {
      uchar _padding[8];
      sanitized_txn_abi_v0_message_t * borrowed;
    };

    /* else */
    struct __attribute__((__packed__)) __attribute__((aligned(8UL))) {
      sanitized_txn_abi_v0_message_t owned;
    };
  } message;

  union __attribute__((__packed__)) __attribute__((aligned(8UL))) {
    ulong discr;

    /* when discr==ABI_HIGH_BIT */
    struct __attribute__((__packed__)) __attribute__((aligned(8UL))) {
      uchar _padding[8];
      sanitized_txn_abi_v0_loaded_addresses_t * borrowed;
    };

    /* else */
    struct __attribute__((__packed__)) __attribute__((aligned(8UL))) {
      sanitized_txn_abi_v0_loaded_addresses_t owned;
    };
  } loaded_addresses;
} sanitized_txn_abi_v0_loaded_msg_t;

FD_STATIC_ASSERT( offsetof(sanitized_txn_abi_v0_loaded_msg_t, is_writable_account_cache_cap)==0, bank_abi );
FD_STATIC_ASSERT( offsetof(sanitized_txn_abi_v0_loaded_msg_t, message)==24, bank_abi );
FD_STATIC_ASSERT( offsetof(sanitized_txn_abi_v0_loaded_msg_t, loaded_addresses)==136, bank_abi );
FD_STATIC_ASSERT( sizeof(sanitized_txn_abi_v0_loaded_msg_t)==184UL, bank_abi );
FD_STATIC_ASSERT( alignof(sanitized_txn_abi_v0_loaded_msg_t)==8UL, bank_abi );

typedef union ABI_ALIGN(8UL) {
  ulong discr;

  /* when discr==ABI_HIGH_BIT */
  struct ABI_ALIGN(8UL) {
    uchar _padding[8];
    sanitized_txn_abi_legacy_message1_t legacy;
  };

  /* else */
  /* No tag. Rust Vec's cap field (the first field in v0) is
     core::num::niche_types::UsizeNoHighBit, so this is never ambiguous. */
  sanitized_txn_abi_v0_loaded_msg_t v0;
} sanitized_txn_abi_message_t;

FD_STATIC_ASSERT( sizeof (sanitized_txn_abi_message_t) == 184UL, bank_abi );
FD_STATIC_ASSERT( alignof(sanitized_txn_abi_message_t) == 8UL,   bank_abi );


typedef union {
  ulong discr;
  /* When discr==1 */
  struct {
    uchar _padding[8];
    uchar _0;
    ulong _1;
  };
  /* when discr==0 */
  /* None */
} option_u8_u64_t;
FD_STATIC_ASSERT( sizeof (option_u8_u64_t)==24UL, bank_abi );
FD_STATIC_ASSERT( alignof(option_u8_u64_t)==8UL,  bank_abi );


typedef union {
  uint discr;
  /* When discr==1 */
  struct {
    uchar _padding[4];
    uchar _0;
    uint  _1;
  };
  /* when discr==0 */
  /* None */
} option_u8_u32_t;
FD_STATIC_ASSERT( sizeof (option_u8_u32_t)==12UL, bank_abi );
FD_STATIC_ASSERT( alignof(option_u8_u32_t)==4UL, bank_abi );



struct ABI_ALIGN(8UL) fd_bank_abi_txn_private {
  struct ABI_ALIGN(8UL) {
    struct ABI_ALIGN(8UL) {
      option_u8_u64_t requested_compute_unit_price;
      option_u8_u32_t requested_compute_unit_limit;
      option_u8_u32_t requested_heap_size;
      option_u8_u32_t requested_loaded_accounts_data_size_limit;

      ushort num_non_compute_budget_instructions;
      ushort num_non_migratable_builtin_instructions;
      ushort num_non_builtin_instructions;
    } compute_budget_instruction_details;

    uchar _message_hash[ 32 ]; /* with the same value as message_hash */

    struct ABI_ALIGN(8UL) {
      ulong num_transaction_signatures;
      ulong num_secp256k1_instruction_signatures;
      ulong num_ed25519_instruction_signatures;
      ulong num_secp256r1_instruction_signatures;
    }; /* TransactionSignatureDetails */

    ushort instruction_data_len;
    uchar  is_simple_vote_transaction; /* same as is_simple_vote_tx */
  }; /* parts of the TransactionMeta */

  struct ABI_ALIGN(8UL) {
    ulong                           signatures_cap;
    sanitized_txn_abi_signature_t * signatures;
    ulong                           signatures_cnt;

    sanitized_txn_abi_message_t message;

    uchar message_hash[ 32 ];
    uchar is_simple_vote_tx;
  }; /* parts of the SanitizedTransaction */
};

FD_STATIC_ASSERT( sizeof (struct fd_bank_abi_txn_private)==FD_BANK_ABI_TXN_FOOTPRINT, bank_abi );
FD_STATIC_ASSERT( sizeof (struct fd_bank_abi_txn_private)==392UL, bank_abi );
FD_STATIC_ASSERT( alignof(struct fd_bank_abi_txn_private)==8UL,   bank_abi );

FD_STATIC_ASSERT( offsetof(struct fd_bank_abi_txn_private, signatures_cap )==144UL, bank_abi );

FD_STATIC_ASSERT( offsetof( struct fd_bank_abi_txn_private, compute_budget_instruction_details.requested_compute_unit_price)==0, bank_abi );
FD_STATIC_ASSERT( offsetof( struct fd_bank_abi_txn_private, compute_budget_instruction_details.requested_compute_unit_limit)==24, bank_abi );
FD_STATIC_ASSERT( offsetof( struct fd_bank_abi_txn_private, compute_budget_instruction_details.requested_heap_size)==36, bank_abi );
FD_STATIC_ASSERT( offsetof( struct fd_bank_abi_txn_private, compute_budget_instruction_details.requested_loaded_accounts_data_size_limit)==48, bank_abi );
FD_STATIC_ASSERT( offsetof( struct fd_bank_abi_txn_private, compute_budget_instruction_details.num_non_compute_budget_instructions)==60, bank_abi );
FD_STATIC_ASSERT( offsetof( struct fd_bank_abi_txn_private, compute_budget_instruction_details.num_non_migratable_builtin_instructions)==62, bank_abi );
FD_STATIC_ASSERT( offsetof( struct fd_bank_abi_txn_private, compute_budget_instruction_details.num_non_builtin_instructions)==64, bank_abi );
FD_STATIC_ASSERT( offsetof( struct fd_bank_abi_txn_private, is_simple_vote_tx)==0x180, bank_abi );
FD_STATIC_ASSERT( offsetof( struct fd_bank_abi_txn_private, is_simple_vote_transaction)==0x8a, bank_abi );

FD_STATIC_ASSERT( offsetof( struct fd_bank_abi_txn_private, message)          -offsetof(struct fd_bank_abi_txn_private, signatures_cap)==24, bank_abi );
FD_STATIC_ASSERT( offsetof( struct fd_bank_abi_txn_private, message_hash)     -offsetof(struct fd_bank_abi_txn_private, signatures_cap)==208, bank_abi );
FD_STATIC_ASSERT( offsetof( struct fd_bank_abi_txn_private, is_simple_vote_tx)-offsetof(struct fd_bank_abi_txn_private, signatures_cap)==240, bank_abi );

static int
is_key_called_as_program( fd_txn_t const * txn,
                          ushort           key_index ) {
  for( ushort i=0; i<txn->instr_cnt; i++ ) {
    fd_txn_instr_t const * instr = &txn->instr[ i ];
    if( FD_UNLIKELY( instr->program_id==key_index ) ) return 1;
  }
  return 0;
}

static const uchar BPF_UPGRADEABLE_PROG_ID1[32] = { BPF_UPGRADEABLE_PROG_ID };

static int
is_upgradeable_loader_present( fd_txn_t const *                   txn,
                               uchar const *                      payload,
                               sanitized_txn_abi_pubkey_t const * loaded_addresses ) {
  for( ushort i=0; i<txn->acct_addr_cnt; i++ ) {
    if( FD_UNLIKELY( !memcmp( payload + txn->acct_addr_off + i*32UL, BPF_UPGRADEABLE_PROG_ID1, 32UL ) ) ) return 1;
  }
  for( ushort i=0; i<txn->addr_table_adtl_cnt; i++ ) {
    if( FD_UNLIKELY( !memcmp( loaded_addresses + i, BPF_UPGRADEABLE_PROG_ID1, 32UL ) ) ) return 1;
  }
  return 0;
}

extern int
fd_ext_bank_load_account( void const *  bank,
                          int           fixed_root,
                          uchar const * addr,
                          uchar *       owner,
                          uchar *       data,
                          ulong *       data_sz );

int
fd_bank_abi_resolve_address_lookup_tables( void const *     bank,
                                           int              fixed_root,
                                           ulong            slot,
                                           fd_txn_t const * txn,
                                           uchar const *    payload,
                                           fd_acct_addr_t * out_lut_accts ) {
  ulong writable_idx = 0UL;
  ulong readable_idx = 0UL;
  for( ulong i=0UL; i<txn->addr_table_lookup_cnt; i++ ) {
    fd_txn_acct_addr_lut_t const * lut = &fd_txn_get_address_tables_const( txn )[ i ];
    uchar const * addr = payload + lut->addr_off;

    uchar owner[ 32UL ];
    uchar data[ 1UL+56UL+256UL*32UL ];
    ulong data_sz = sizeof(data);
    int result = fd_ext_bank_load_account( bank, fixed_root, addr, owner, data, &data_sz );
    if( FD_UNLIKELY( result ) ) return FD_BANK_ABI_TXN_INIT_ERR_ACCOUNT_NOT_FOUND;

    result = memcmp( owner, fd_solana_address_lookup_table_program_id.key, 32UL );
    if( FD_UNLIKELY( result ) ) return FD_BANK_ABI_TXN_INIT_ERR_INVALID_ACCOUNT_OWNER;

    if( FD_UNLIKELY( (data_sz<56UL) | (data_sz>(56UL+256UL*32UL)) ) ) return FD_BANK_ABI_TXN_INIT_ERR_INVALID_ACCOUNT_DATA;

    fd_bincode_decode_ctx_t bincode = {
      .data    = data,
      .dataend = data+data_sz,
    };

    ulong total_sz = 0UL;
    result = fd_address_lookup_table_state_decode_footprint( &bincode, &total_sz );
    if( FD_UNLIKELY( result!=FD_BINCODE_SUCCESS ) ) return FD_BANK_ABI_TXN_INIT_ERR_INVALID_ACCOUNT_DATA;

    fd_address_lookup_table_state_t table[1];
    fd_address_lookup_table_state_decode( table, &bincode );

    result = fd_address_lookup_table_state_is_lookup_table( table );
    if( FD_UNLIKELY( !result ) ) return FD_BANK_ABI_TXN_INIT_ERR_ACCOUNT_UNINITIALIZED;

    if( FD_UNLIKELY( (data_sz-56UL)%32UL ) ) return FD_BANK_ABI_TXN_INIT_ERR_INVALID_ACCOUNT_DATA;

    ulong addresses_len = (data_sz-56UL)/32UL;
    fd_acct_addr_t const * addresses = fd_type_pun_const( data+56UL );

    /* This logic is not currently very precise... an ALUT is allowed if
       the deactivation slot is no longer present in the slot hashes
       sysvar, which means that the slot was more than 512 *unskipped*
       slots prior.  In the current case, we are just throwing out a
       fraction of transactions that could actually still be valid
       (those deactivated between 512 and 512*(1+skip_rate) slots ago. */

    ulong deactivation_slot = table->inner.lookup_table.meta.deactivation_slot;
    if( FD_UNLIKELY( deactivation_slot!=ULONG_MAX && (deactivation_slot+512UL)<slot ) ) return FD_BANK_ABI_TXN_INIT_ERR_ACCOUNT_NOT_FOUND;

    ulong active_addresses_len = fd_ulong_if( slot>table->inner.lookup_table.meta.last_extended_slot,
                                              addresses_len,
                                              table->inner.lookup_table.meta.last_extended_slot_start_index );
    for( ulong j=0UL; j<lut->writable_cnt; j++ ) {
      uchar idx = payload[ lut->writable_off+j ];
      if( FD_UNLIKELY( idx>=active_addresses_len ) ) return FD_BANK_ABI_TXN_INIT_ERR_INVALID_LOOKUP_INDEX;
      out_lut_accts[ writable_idx++ ] = addresses[ idx ];
    }
    for( ulong j=0UL; j<lut->readonly_cnt; j++ ) {
      uchar idx = payload[ lut->readonly_off+j ];
      if( FD_UNLIKELY( idx>=active_addresses_len ) ) return FD_BANK_ABI_TXN_INIT_ERR_INVALID_LOOKUP_INDEX;
      out_lut_accts[ txn->addr_table_adtl_writable_cnt+readable_idx++ ] = addresses[ idx ];
    }
  }

  return FD_BANK_ABI_TXN_INIT_SUCCESS;
}

#define CATEGORY_NON_BUILTIN   0
#define CATEGORY_NON_MIGRATABLE 1
#define CATEGORY_MIGRATING(x)  (2+(x)) /* Unused in v3.1.0 - kept for future migrations */
typedef struct {
  uchar b[FD_TXN_ACCT_ADDR_SZ];
  int   category;
} fd_bank_abi_prog_map_t;

#define MAP_PERFECT_NAME      prog_map
#define MAP_PERFECT_LG_TBL_SZ 4
#define MAP_PERFECT_T         fd_bank_abi_prog_map_t
#define MAP_PERFECT_KEY       b
#define MAP_PERFECT_KEY_T     fd_acct_addr_t const *
#define MAP_PERFECT_ZERO_KEY  (0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0)
#define MAP_PERFECT_COMPLEX_KEY 1
#define MAP_PERFECT_KEYS_EQUAL(k1,k2) (!memcmp( (k1), (k2), 32UL ))

#define PERFECT_HASH( u ) ((((3776U*(u))>>28)-1U)&0xFU)

#define MAP_PERFECT_HASH_PP( a00,a01,a02,a03,a04,a05,a06,a07,a08,a09,a10,a11,a12,a13,a14,a15, \
                             a16,a17,a18,a19,a20,a21,a22,a23,a24,a25,a26,a27,a28,a29,a30,a31) \
                                          PERFECT_HASH( (a08 | (a09<<8) | (a10<<16) | (a11<<24)) )
#define MAP_PERFECT_HASH_R( ptr ) PERFECT_HASH( fd_uint_load_4( (uchar const *)ptr->b + 8UL ) )

#define MAP_PERFECT_0  ( KECCAK_SECP_PROG_ID     ), .category=CATEGORY_NON_MIGRATABLE
#define MAP_PERFECT_1  ( ED25519_SV_PROG_ID      ), .category=CATEGORY_NON_MIGRATABLE
#define MAP_PERFECT_2  ( SECP256R1_PROG_ID       ), .category=CATEGORY_NON_BUILTIN /* strange, but true */
#define MAP_PERFECT_3  ( VOTE_PROG_ID            ), .category=CATEGORY_NON_MIGRATABLE
#define MAP_PERFECT_4  ( SYS_PROG_ID             ), .category=CATEGORY_NON_MIGRATABLE
#define MAP_PERFECT_5  ( COMPUTE_BUDGET_PROG_ID  ), .category=CATEGORY_NON_MIGRATABLE
#define MAP_PERFECT_6  ( BPF_UPGRADEABLE_PROG_ID ), .category=CATEGORY_NON_MIGRATABLE
#define MAP_PERFECT_7  ( BPF_LOADER_1_PROG_ID    ), .category=CATEGORY_NON_MIGRATABLE
#define MAP_PERFECT_8  ( BPF_LOADER_2_PROG_ID    ), .category=CATEGORY_NON_MIGRATABLE
#define MAP_PERFECT_9  ( LOADER_V4_PROG_ID       ), .category=CATEGORY_NON_MIGRATABLE


#include "../../util/tmpl/fd_map_perfect.c"

/* Redefine it so we can use it below */
#define MAP_PERFECT_HASH_PP( a00,a01,a02,a03,a04,a05,a06,a07,a08,a09,a10,a11,a12,a13,a14,a15, \
                             a16,a17,a18,a19,a20,a21,a22,a23,a24,a25,a26,a27,a28,a29,a30,a31) \
                                          PERFECT_HASH( ((uint)a08 | ((uint)a09<<8) | ((uint)a10<<16) | ((uint)a11<<24)) )
#define HASH( x ) MAP_PERFECT_HASH_PP( x )

FD_STATIC_ASSERT( HASH( KECCAK_SECP_PROG_ID )<3, precompile_table );
FD_STATIC_ASSERT( HASH( ED25519_SV_PROG_ID  )<3, precompile_table );
FD_STATIC_ASSERT( HASH( SECP256R1_PROG_ID   )<3, precompile_table );

int
fd_bank_abi_txn_init( fd_bank_abi_txn_t * out_txn,
                      uchar *             out_sidecar,
                      void const *        bank,
                      ulong               slot,
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
  memcpy( out_txn->_message_hash, out_txn->message_hash, 32UL );

  out_txn->is_simple_vote_tx          = !!is_simple_vote;
  out_txn->is_simple_vote_transaction = !!is_simple_vote;


  ulong sig_counters[4] = { 0UL };
  ulong instr_cnt[3] = { 0UL }; /* [0]=non-builtin, [1]=non-migratable, [2]=migrating (unused in v3.1.0) */

  fd_compute_budget_program_state_t cbp_state[1];
  fd_compute_budget_program_init( cbp_state );

  ulong instr_data_sz = 0UL;
  fd_acct_addr_t const * addr_base = fd_txn_get_acct_addrs( txn, payload );
  const fd_bank_abi_prog_map_t non_builtin[1] = { { .category = CATEGORY_NON_BUILTIN } };
  for( ulong i=0UL; i<txn->instr_cnt; i++ ) {
    ulong prog_id_idx = (ulong)txn->instr[i].program_id;
    fd_acct_addr_t const * prog_id = addr_base + prog_id_idx;

    /* Lookup prog_id in hash table.  If it's a miss, it'll return
       UINT_MAX which gets clamped to 3.  Otherwise, it'll be 0, 1, or
       2. */
    uint hash_or_def = prog_map_hash_or_default( prog_id );
    sig_counters[ fd_uint_min( 3UL, hash_or_def ) ] +=
      (txn->instr[i].data_sz>0) ? (ulong)payload[ txn->instr[i].data_off ] : 0UL;

    instr_cnt[ prog_map_query( prog_id, non_builtin )->category ]++;
    instr_data_sz += txn->instr[i].data_sz;

    if( FD_UNLIKELY( hash_or_def==HASH( COMPUTE_BUDGET_PROG_ID ) ) ) {
      fd_compute_budget_program_parse( payload+txn->instr[i].data_off, txn->instr[i].data_sz, cbp_state );
    }
  }
  out_txn->instruction_data_len       = (ushort)instr_data_sz; /* fd_txn_parse ensures this is less than MTU, so the cast is safe */
  out_txn->num_transaction_signatures = fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_SIGNER );
  out_txn->num_secp256k1_instruction_signatures = sig_counters[ HASH( KECCAK_SECP_PROG_ID ) ];
  out_txn->num_ed25519_instruction_signatures   = sig_counters[ HASH( ED25519_SV_PROG_ID  ) ];
  out_txn->num_secp256r1_instruction_signatures = sig_counters[ HASH( SECP256R1_PROG_ID   ) ];

  out_txn->compute_budget_instruction_details.num_non_compute_budget_instructions     = (ushort)(txn->instr_cnt - cbp_state->compute_budget_instr_cnt);
  out_txn->compute_budget_instruction_details.num_non_migratable_builtin_instructions = (ushort)instr_cnt[ CATEGORY_NON_MIGRATABLE ];
  out_txn->compute_budget_instruction_details.num_non_builtin_instructions            = (ushort)instr_cnt[ CATEGORY_NON_BUILTIN   ];
  /* The instruction index doesn't matter */
#define CBP_TO_TUPLE_OPTION( out, flag, val0, val1 )                                                                      \
  do {                                                                                                                    \
    out_txn->compute_budget_instruction_details.out.discr = !!(cbp_state->flags & FD_COMPUTE_BUDGET_PROGRAM_FLAG_ ## flag); \
    out_txn->compute_budget_instruction_details.out._0    = (val0);                                                         \
    out_txn->compute_budget_instruction_details.out._1    = (val1);                                                         \
  } while( 0 )

  CBP_TO_TUPLE_OPTION( requested_compute_unit_price,              SET_FEE,            0, cbp_state->micro_lamports_per_cu );
  CBP_TO_TUPLE_OPTION( requested_compute_unit_limit,              SET_CU,             0, cbp_state->compute_units         );
  CBP_TO_TUPLE_OPTION( requested_heap_size,                       SET_HEAP,           0, cbp_state->heap_size             );
  CBP_TO_TUPLE_OPTION( requested_loaded_accounts_data_size_limit, SET_LOADED_DATA_SZ, 0, cbp_state->loaded_acct_data_sz   );
#undef CBP_TO_TUPLE_OPTION

  if( FD_LIKELY( txn->transaction_version==FD_TXN_VLEGACY ) ) {
    sanitized_txn_abi_legacy_message1_t * legacy = &out_txn->message.legacy;
    sanitized_txn_abi_legacy_message0_t * message = &legacy->message.owned;

    out_txn->message.discr = ABI_HIGH_BIT;

    legacy->is_writable_account_cache_cnt = txn->acct_addr_cnt;
    legacy->is_writable_account_cache_cap = txn->acct_addr_cnt;
    legacy->is_writable_account_cache     = out_sidecar;
    int _is_upgradeable_loader_present = is_upgradeable_loader_present( txn, payload, NULL );
    for( ushort i=0; i<txn->acct_addr_cnt; i++ ) {
      int is_writable = fd_txn_is_writable( txn, i ) &&
                        /* Agave does this check, but we don't need to here because pack
                           rejects these transactions before they make it to the bank.

                           !fd_pack_unwritable_contains( (const fd_acct_addr_t*)(payload + txn->acct_addr_off + i*32UL) ) */
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

    int result = fd_bank_abi_resolve_address_lookup_tables( bank, 1, slot, txn, payload, (fd_acct_addr_t*)out_sidecar );
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
                        /* Agave does this check, but we don't need to here because pack
                           rejects these transactions before they make it to the bank.

                           !fd_pack_unwritable_contains( (const fd_acct_addr_t*)(payload + txn->acct_addr_off + i*32UL) ) */
                        (!is_key_called_as_program( txn, i ) || _is_upgradeable_loader_present);
      v0->is_writable_account_cache[ i ] = !!is_writable;
    }
    for( ushort i=0; i<txn->addr_table_adtl_writable_cnt; i++ ) {
      /* We do need to check is_builtin_key_or_sysvar here, because pack
         has not yet loaded the address LUT accounts, so it doesn't
         reject these yet. */
      int is_writable = !fd_pack_unwritable_contains( (const fd_acct_addr_t*)(loaded_addresses->writable + i) ) &&
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
      fd_txn_acct_addr_lut_t const * lookup = fd_txn_get_address_tables_const( txn ) + i;
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

fd_acct_addr_t const *
fd_bank_abi_get_lookup_addresses( fd_bank_abi_txn_t const * txn ) {
  return txn->message.discr==ABI_HIGH_BIT ? NULL :
    (fd_acct_addr_t const *) txn->message.v0.loaded_addresses.owned.writable;
}
