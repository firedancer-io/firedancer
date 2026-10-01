/* test_txn_meta builds commit records by hand and checks what the meta
   module makes of them: the fields of fd_txn_meta_t, the bincode
   encoding of the transaction error, and the protobuf encodings of the
   transaction, its meta and the two update messages a Dragon's Mouth
   subscriber receives.

   The expected error bytes are written out with the variant arithmetic
   that produced them.  The expected message bytes of the first fixture
   are what a protobuf encoder produces for the same message. */

#include "fd_txn_meta.h"
#include "../log_collector/fd_log_collector_base.h"
#include "../../discof/dragon/proto/geyser.pb.h"

/* The field numbers this module writes, against the protobuf
   definitions the Dragon's Mouth service carries them in.  A
   regenerated proto that renumbers a field breaks the build here. */

#define TAG_EQ(ours,theirs) FD_STATIC_ASSERT( (ours)==(theirs), dragon_proto_field_number )

TAG_EQ( FD_TXN_META_F_HDR_NUM_REQUIRED_SIGNATURES,   solana_storage_ConfirmedBlock_MessageHeader_num_required_signatures_tag        );
TAG_EQ( FD_TXN_META_F_HDR_NUM_READONLY_SIGNED,       solana_storage_ConfirmedBlock_MessageHeader_num_readonly_signed_accounts_tag   );
TAG_EQ( FD_TXN_META_F_HDR_NUM_READONLY_UNSIGNED,     solana_storage_ConfirmedBlock_MessageHeader_num_readonly_unsigned_accounts_tag );

TAG_EQ( FD_TXN_META_F_MSG_HEADER,                    solana_storage_ConfirmedBlock_Message_header_tag                );
TAG_EQ( FD_TXN_META_F_MSG_ACCOUNT_KEYS,              solana_storage_ConfirmedBlock_Message_account_keys_tag          );
TAG_EQ( FD_TXN_META_F_MSG_RECENT_BLOCKHASH,          solana_storage_ConfirmedBlock_Message_recent_blockhash_tag       );
TAG_EQ( FD_TXN_META_F_MSG_INSTRUCTIONS,              solana_storage_ConfirmedBlock_Message_instructions_tag           );
TAG_EQ( FD_TXN_META_F_MSG_VERSIONED,                 solana_storage_ConfirmedBlock_Message_versioned_tag              );
TAG_EQ( FD_TXN_META_F_MSG_ADDRESS_TABLE_LOOKUPS,     solana_storage_ConfirmedBlock_Message_address_table_lookups_tag  );
TAG_EQ( FD_TXN_META_F_MSG_CONFIG,                    solana_storage_ConfirmedBlock_Message_config_tag                 );

TAG_EQ( FD_TXN_META_F_TXN_SIGNATURES,                solana_storage_ConfirmedBlock_Transaction_signatures_tag         );
TAG_EQ( FD_TXN_META_F_TXN_MESSAGE,                   solana_storage_ConfirmedBlock_Transaction_message_tag            );

TAG_EQ( FD_TXN_META_F_CI_PROGRAM_ID_INDEX,           solana_storage_ConfirmedBlock_CompiledInstruction_program_id_index_tag );
TAG_EQ( FD_TXN_META_F_CI_ACCOUNTS,                   solana_storage_ConfirmedBlock_CompiledInstruction_accounts_tag   );
TAG_EQ( FD_TXN_META_F_CI_DATA,                       solana_storage_ConfirmedBlock_CompiledInstruction_data_tag       );

TAG_EQ( FD_TXN_META_F_LUT_ACCOUNT_KEY,               solana_storage_ConfirmedBlock_MessageAddressTableLookup_account_key_tag      );
TAG_EQ( FD_TXN_META_F_LUT_WRITABLE_INDEXES,          solana_storage_ConfirmedBlock_MessageAddressTableLookup_writable_indexes_tag );
TAG_EQ( FD_TXN_META_F_LUT_READONLY_INDEXES,          solana_storage_ConfirmedBlock_MessageAddressTableLookup_readonly_indexes_tag );

TAG_EQ( FD_TXN_META_F_CFG_PRIORITY_FEE,              solana_storage_ConfirmedBlock_TransactionConfig_priority_fee_tag                    );
TAG_EQ( FD_TXN_META_F_CFG_COMPUTE_UNIT_LIMIT,        solana_storage_ConfirmedBlock_TransactionConfig_compute_unit_limit_tag              );
TAG_EQ( FD_TXN_META_F_CFG_LOADED_ACCOUNTS_DATA_SIZE, solana_storage_ConfirmedBlock_TransactionConfig_loaded_accounts_data_size_limit_tag );
TAG_EQ( FD_TXN_META_F_CFG_HEAP_SIZE,                 solana_storage_ConfirmedBlock_TransactionConfig_heap_size_tag                       );

TAG_EQ( FD_TXN_META_F_ERR_ERR,                       solana_storage_ConfirmedBlock_TransactionError_err_tag           );

TAG_EQ( FD_TXN_META_F_II_INDEX,                      solana_storage_ConfirmedBlock_InnerInstructions_index_tag        );
TAG_EQ( FD_TXN_META_F_II_INSTRUCTIONS,               solana_storage_ConfirmedBlock_InnerInstructions_instructions_tag );

TAG_EQ( FD_TXN_META_F_IN_PROGRAM_ID_INDEX,           solana_storage_ConfirmedBlock_InnerInstruction_program_id_index_tag );
TAG_EQ( FD_TXN_META_F_IN_ACCOUNTS,                   solana_storage_ConfirmedBlock_InnerInstruction_accounts_tag      );
TAG_EQ( FD_TXN_META_F_IN_DATA,                       solana_storage_ConfirmedBlock_InnerInstruction_data_tag          );
TAG_EQ( FD_TXN_META_F_IN_STACK_HEIGHT,               solana_storage_ConfirmedBlock_InnerInstruction_stack_height_tag  );

TAG_EQ( FD_TXN_META_F_RD_PROGRAM_ID,                 solana_storage_ConfirmedBlock_ReturnData_program_id_tag          );
TAG_EQ( FD_TXN_META_F_RD_DATA,                       solana_storage_ConfirmedBlock_ReturnData_data_tag                );

TAG_EQ( FD_TXN_META_F_META_ERR,                      solana_storage_ConfirmedBlock_TransactionStatusMeta_err_tag                       );
TAG_EQ( FD_TXN_META_F_META_FEE,                      solana_storage_ConfirmedBlock_TransactionStatusMeta_fee_tag                       );
TAG_EQ( FD_TXN_META_F_META_PRE_BALANCES,             solana_storage_ConfirmedBlock_TransactionStatusMeta_pre_balances_tag              );
TAG_EQ( FD_TXN_META_F_META_POST_BALANCES,            solana_storage_ConfirmedBlock_TransactionStatusMeta_post_balances_tag             );
TAG_EQ( FD_TXN_META_F_META_INNER_INSTRUCTIONS,       solana_storage_ConfirmedBlock_TransactionStatusMeta_inner_instructions_tag        );
TAG_EQ( FD_TXN_META_F_META_LOG_MESSAGES,             solana_storage_ConfirmedBlock_TransactionStatusMeta_log_messages_tag              );
TAG_EQ( FD_TXN_META_F_META_INNER_INSTRUCTIONS_NONE,  solana_storage_ConfirmedBlock_TransactionStatusMeta_inner_instructions_none_tag   );
TAG_EQ( FD_TXN_META_F_META_LOG_MESSAGES_NONE,        solana_storage_ConfirmedBlock_TransactionStatusMeta_log_messages_none_tag         );
TAG_EQ( FD_TXN_META_F_META_LOADED_WRITABLE,          solana_storage_ConfirmedBlock_TransactionStatusMeta_loaded_writable_addresses_tag );
TAG_EQ( FD_TXN_META_F_META_LOADED_READONLY,          solana_storage_ConfirmedBlock_TransactionStatusMeta_loaded_readonly_addresses_tag );
TAG_EQ( FD_TXN_META_F_META_RETURN_DATA,              solana_storage_ConfirmedBlock_TransactionStatusMeta_return_data_tag               );
TAG_EQ( FD_TXN_META_F_META_RETURN_DATA_NONE,         solana_storage_ConfirmedBlock_TransactionStatusMeta_return_data_none_tag          );
TAG_EQ( FD_TXN_META_F_META_COMPUTE_UNITS_CONSUMED,   solana_storage_ConfirmedBlock_TransactionStatusMeta_compute_units_consumed_tag    );
TAG_EQ( FD_TXN_META_F_META_COST_UNITS,               solana_storage_ConfirmedBlock_TransactionStatusMeta_cost_units_tag                );

/* The token balances and rewards this module leaves empty are fields
   of their own, which nothing here writes. */
TAG_EQ( 7U,  solana_storage_ConfirmedBlock_TransactionStatusMeta_pre_token_balances_tag  );
TAG_EQ( 8U,  solana_storage_ConfirmedBlock_TransactionStatusMeta_post_token_balances_tag );
TAG_EQ( 9U,  solana_storage_ConfirmedBlock_TransactionStatusMeta_rewards_tag             );

TAG_EQ( FD_TXN_META_F_INFO_SIGNATURE,   geyser_SubscribeUpdateTransactionInfo_signature_tag   );
TAG_EQ( FD_TXN_META_F_INFO_IS_VOTE,     geyser_SubscribeUpdateTransactionInfo_is_vote_tag     );
TAG_EQ( FD_TXN_META_F_INFO_TRANSACTION, geyser_SubscribeUpdateTransactionInfo_transaction_tag );
TAG_EQ( FD_TXN_META_F_INFO_META,        geyser_SubscribeUpdateTransactionInfo_meta_tag        );
TAG_EQ( FD_TXN_META_F_INFO_INDEX,       geyser_SubscribeUpdateTransactionInfo_index_tag       );

TAG_EQ( FD_TXN_META_F_UPDATE_TRANSACTION, geyser_SubscribeUpdateTransaction_transaction_tag );
TAG_EQ( FD_TXN_META_F_UPDATE_SLOT,        geyser_SubscribeUpdateTransaction_slot_tag        );
TAG_EQ( FD_TXN_META_F_UPDATE_BANK_ID,     geyser_SubscribeUpdateTransaction_bank_id_tag     );

TAG_EQ( FD_TXN_META_F_STATUS_SLOT,      geyser_SubscribeUpdateTransactionStatus_slot_tag      );
TAG_EQ( FD_TXN_META_F_STATUS_SIGNATURE, geyser_SubscribeUpdateTransactionStatus_signature_tag );
TAG_EQ( FD_TXN_META_F_STATUS_IS_VOTE,   geyser_SubscribeUpdateTransactionStatus_is_vote_tag   );
TAG_EQ( FD_TXN_META_F_STATUS_INDEX,     geyser_SubscribeUpdateTransactionStatus_index_tag     );
TAG_EQ( FD_TXN_META_F_STATUS_ERR,       geyser_SubscribeUpdateTransactionStatus_err_tag       );
TAG_EQ( FD_TXN_META_F_STATUS_BANK_ID,   geyser_SubscribeUpdateTransactionStatus_bank_id_tag   );

#undef TAG_EQ

/* Payload building ***************************************************/

struct pl {
  uchar buf[ FD_TXN_MTU ];
  ulong sz;
};

typedef struct pl pl_t;

static void
pl_u8( pl_t * pl,
       uint   v ) {
  FD_TEST( pl->sz<sizeof(pl->buf) );
  pl->buf[ pl->sz++ ] = (uchar)v;
}

static void
pl_u32( pl_t * pl,
        uint   v ) {
  pl_u8( pl, v ); pl_u8( pl, v>>8 ); pl_u8( pl, v>>16 ); pl_u8( pl, v>>24 );
}

static void
pl_u64( pl_t * pl,
        ulong  v ) {
  pl_u32( pl, (uint)v ); pl_u32( pl, (uint)(v>>32) );
}

static void
pl_fill( pl_t * pl,
         uint   byte,
         ulong  cnt ) {
  for( ulong i=0UL; i<cnt; i++ ) pl_u8( pl, byte );
}

static void
pl_raw( pl_t *        pl,
        uchar const * data,
        ulong         data_sz ) {
  for( ulong i=0UL; i<data_sz; i++ ) pl_u8( pl, data[ i ] );
}

/* One instruction of a payload under construction. */

struct pl_instr {
  uint  program_id;
  ulong acct_cnt;
  uchar accts[ 8 ];
  ulong data_sz;
  uchar data[ 8 ];
};

typedef struct pl_instr pl_instr_t;

/* pl_legacy writes a legacy or V0 transaction.  A V0 one carries the
   version prefix and one address table lookup selecting lut_w writable
   and lut_r readonly addresses. */

static void
pl_legacy( pl_t *             pl,
           int                v0,
           uint               key_cnt,
           pl_instr_t const * instr,
           ulong              instr_cnt,
           ulong              lut_w,
           ulong              lut_r ) {
  pl->sz = 0UL;
  pl_u8  ( pl, 1U );            /* one signature */
  pl_fill( pl, 0x11U, 64UL );
  if( v0 ) pl_u8( pl, 0x80U );  /* version 0 */
  pl_u8  ( pl, 1U );            /* signers */
  pl_u8  ( pl, 0U );            /* readonly signers */
  pl_u8  ( pl, 1U );            /* readonly non signers */
  pl_u8  ( pl, key_cnt );
  for( uint i=0U; i<key_cnt; i++ ) pl_fill( pl, 0x20U+i, 32UL );
  pl_fill( pl, 0x30U, 32UL );   /* recent blockhash */
  pl_u8  ( pl, (uint)instr_cnt );
  for( ulong i=0UL; i<instr_cnt; i++ ) {
    pl_u8 ( pl, instr[ i ].program_id );
    pl_u8 ( pl, (uint)instr[ i ].acct_cnt );
    pl_raw( pl, instr[ i ].accts, instr[ i ].acct_cnt );
    pl_u8 ( pl, (uint)instr[ i ].data_sz );
    pl_raw( pl, instr[ i ].data, instr[ i ].data_sz );
  }
  if( v0 ) {
    pl_u8  ( pl, 1U );          /* one lookup */
    pl_fill( pl, 0x40U, 32UL ); /* table address */
    pl_u8  ( pl, (uint)lut_w );
    for( ulong i=0UL; i<lut_w; i++ ) pl_u8( pl, (uint)(7UL+i) );
    pl_u8  ( pl, (uint)lut_r );
    for( ulong i=0UL; i<lut_r; i++ ) pl_u8( pl, (uint)(9UL+i) );
  }
}

/* pl_v1 writes a V1 transaction with the given config mask and
   values.  The signatures of a V1 transaction sit at the end. */

static void
pl_v1( pl_t *             pl,
       uint               config_mask,
       ulong              priority_fee,
       uint               cu_limit,
       uint               loaded_sz,
       uint               heap_sz,
       uint               key_cnt,
       pl_instr_t const * instr,
       ulong              instr_cnt ) {
  pl->sz = 0UL;
  pl_u8  ( pl, 0x80U | FD_TXN_V1 ); /* the high bit marks a V1 transaction */
  pl_u8  ( pl, 1U );            /* one signature */
  pl_u8  ( pl, 0U );            /* readonly signers */
  pl_u8  ( pl, 1U );            /* readonly non signers */
  pl_u32 ( pl, config_mask );
  pl_fill( pl, 0x30U, 32UL );   /* lifetime specifier */
  pl_u8  ( pl, (uint)instr_cnt );
  pl_u8  ( pl, key_cnt );
  for( uint i=0U; i<key_cnt; i++ ) pl_fill( pl, 0x20U+i, 32UL );
  if( config_mask & 1U   ) pl_u64( pl, priority_fee );
  if( config_mask & 4U   ) pl_u32( pl, cu_limit     );
  if( config_mask & 8U   ) pl_u32( pl, loaded_sz    );
  if( config_mask & 16U  ) pl_u32( pl, heap_sz      );
  for( ulong i=0UL; i<instr_cnt; i++ ) {
    pl_u8( pl, instr[ i ].program_id );
    pl_u8( pl, (uint)instr[ i ].acct_cnt );
    pl_u8( pl, (uint)instr[ i ].data_sz );
    pl_u8( pl, 0U );
  }
  for( ulong i=0UL; i<instr_cnt; i++ ) {
    pl_raw( pl, instr[ i ].accts, instr[ i ].acct_cnt );
    pl_raw( pl, instr[ i ].data,  instr[ i ].data_sz  );
  }
  pl_fill( pl, 0x11U, 64UL );
}

/* Record building ****************************************************/

/* A commit record as a set of buffers.  A record on the wire is one
   contiguous block, but the meta module only ever sees it through the
   parts view, which is what the ingest side hands it. */

struct rec {
  fd_event_internal_commit_t         ev[1];
  uchar                              keys[ 8 ][ 32 ];
  ulong                              pre [ 8 ];
  ulong                              post[ 8 ];
  uchar                              writable[ 8 ];
  uchar                              logs[ 512 ];
  fd_event_internal_commit_trace_t   trace[ 8 ];
  uchar                              trace_accts[ 32 ];
  uchar                              trace_data[ 64 ];
  uchar                              return_data[ 32 ];
  pl_t                               payload[1];
  fd_event_internal_commit_parts_t   parts[1];
};

typedef struct rec rec_t;

static void
rec_init( rec_t * rec ) {
  fd_memset( rec, 0, sizeof(rec_t) );

  rec->ev->bank_seq             = 7UL;
  rec->ev->slot                 = 100UL;
  rec->ev->index_in_slot        = 2UL;
  rec->ev->commit_index_in_slot = 2UL;
  rec->ev->exec_err_idx         = UINT_MAX;
  rec->ev->custom_err           = UINT_MAX;
  rec->ev->rent_err_account_idx = UINT_MAX;

  fd_memset( rec->ev->signature, 0x11, 64UL );

  rec->parts->prefix        = rec->ev;
  rec->parts->payload       = rec->payload->buf;
  rec->parts->keys          = (uchar const (*)[ 32UL ])rec->keys;
  rec->parts->pre_lamports  = rec->pre;
  rec->parts->post_lamports = rec->post;
  rec->parts->is_writable   = rec->writable;
  rec->parts->logs          = rec->logs;
  rec->parts->trace         = rec->trace;
  rec->parts->trace_accts   = rec->trace_accts;
  rec->parts->trace_data    = rec->trace_data;
  rec->parts->return_data   = rec->return_data;
  rec->parts->touched       = NULL;
}

/* rec_keys copies the payload's addresses into the record's key list
   and appends the addresses a lookup table would have loaded, the
   writable ones first, which is the order the runtime reports them
   in. */

static void
rec_keys( rec_t * rec,
          ulong   static_cnt,
          ulong   loaded_w,
          ulong   loaded_r ) {
  for( ulong i=0UL; i<static_cnt; i++ ) fd_memset( rec->keys[ i ], (int)(0x20UL+i), 32UL );
  for( ulong i=0UL; i<loaded_w+loaded_r; i++ ) fd_memset( rec->keys[ static_cnt+i ], (int)(0x50UL+i), 32UL );

  ulong cnt = static_cnt+loaded_w+loaded_r;
  rec->ev->acct_addr_cnt     = (uint)static_cnt;
  rec->ev->adtl_writable_cnt = (uint)loaded_w;
  rec->ev->keys_cnt          = cnt;
  rec->ev->pre_lamports_cnt  = cnt;
  rec->ev->post_lamports_cnt = cnt;
  rec->ev->is_writable_cnt   = cnt;
  for( ulong i=0UL; i<cnt; i++ ) {
    rec->pre     [ i ] = 10UL*(i+1UL);
    rec->post    [ i ] = 10UL*(i+1UL)-1UL;
    rec->writable[ i ] = (uchar)( i<static_cnt-1UL );
  }
}

/* rec_log appends one message to the record's log buffer in the
   collector's serialization: the tag of the repeated string field the
   messages go on the wire as, then the length, then the bytes. */

static void
rec_log( rec_t *      rec,
         char const * msg ) {
  ulong len = strlen( msg );
  ulong o   = rec->ev->logs_cnt;
  FD_TEST( len<0x80UL );
  FD_TEST( o+2UL+len<=sizeof(rec->logs) );
  rec->logs[ o++ ] = FD_LOG_COLLECTOR_PROTO_TAG;
  rec->logs[ o++ ] = (uchar)len;
  fd_memcpy( rec->logs+o, msg, len );
  rec->ev->logs_cnt = o+len;
}

/* rec_instr appends one entry to the instruction trace, with its own
   data packed the way the producer packs it, at an eight byte
   boundary. */

static void
rec_instr( rec_t *       rec,
           uint          program_id_idx,
           uint          stack_height,
           uchar const * accts,
           ulong         acct_cnt,
           uchar const * data,
           ulong         data_sz ) {
  ulong i = rec->ev->trace_cnt;
  FD_TEST( i<8UL );

  fd_event_internal_commit_trace_t * t = rec->trace + i;
  t->program_id_idx = program_id_idx;
  t->stack_height   = stack_height;
  t->acct_cnt       = (uint)acct_cnt;
  t->acct_off       = (uint)rec->ev->trace_accts_cnt;
  t->data_off       = (uint)rec->ev->trace_data_cnt;
  t->data_sz        = (uint)data_sz;

  FD_TEST( rec->ev->trace_accts_cnt+acct_cnt<=sizeof(rec->trace_accts) );
  fd_memcpy( rec->trace_accts+rec->ev->trace_accts_cnt, accts, acct_cnt );
  rec->ev->trace_accts_cnt += acct_cnt;

  ulong pad = fd_ulong_align_up( data_sz, 8UL );
  FD_TEST( rec->ev->trace_data_cnt+pad<=sizeof(rec->trace_data) );
  fd_memcpy( rec->trace_data+rec->ev->trace_data_cnt, data, data_sz );
  rec->ev->trace_data_cnt += pad;

  rec->ev->trace_cnt = i+1UL;
}

/* Protobuf reading ***************************************************/

/* pb_valid walks a message and returns 1 if every field parses and
   ends inside it. */

static int
pb_valid( uchar const * buf,
          ulong         sz ) {
  ulong o = 0UL;
  while( o<sz ) {
    ulong key = 0UL;
    uint  shift = 0U;
    for(;;) {
      if( o>=sz || shift>63U ) return 0;
      uchar c = buf[ o++ ];
      key |= ( (ulong)( c & 0x7F ) )<<shift;
      shift += 7U;
      if( !( c & 0x80 ) ) break;
    }
    ulong wire = key & 7UL;
    if( !( key>>3 ) ) return 0;

    if( wire==0UL ) {
      for(;;) {
        if( o>=sz ) return 0;
        if( !( buf[ o++ ] & 0x80 ) ) break;
      }
    } else if( wire==2UL ) {
      ulong len = 0UL;
      shift = 0U;
      for(;;) {
        if( o>=sz || shift>63U ) return 0;
        uchar c = buf[ o++ ];
        len |= ( (ulong)( c & 0x7F ) )<<shift;
        shift += 7U;
        if( !( c & 0x80 ) ) break;
      }
      if( len>sz-o ) return 0;
      o += len;
    } else if( wire==5UL ) {
      if( 4UL>sz-o ) return 0;
      o += 4UL;
    } else if( wire==1UL ) {
      if( 8UL>sz-o ) return 0;
      o += 8UL;
    } else return 0;
  }
  return 1;
}

/* pb_field finds the idx-th occurrence of a field.  For a varint it
   writes the value to *val; for a length delimited field it points
   *body at the body and writes its size to *body_sz.  Returns 1 if the
   field was found. */

static int
pb_field( uchar const *  buf,
          ulong          sz,
          uint           field,
          ulong          idx,
          ulong *        val,
          uchar const ** body,
          ulong *        body_sz ) {
  ulong o    = 0UL;
  ulong seen = 0UL;
  while( o<sz ) {
    ulong key   = 0UL;
    uint  shift = 0U;
    for(;;) {
      FD_TEST( o<sz );
      uchar c = buf[ o++ ];
      key |= ( (ulong)( c & 0x7F ) )<<shift;
      shift += 7U;
      if( !( c & 0x80 ) ) break;
    }
    ulong wire = key & 7UL;
    uint  f    = (uint)( key>>3 );

    ulong v   = 0UL;
    uchar const * b = NULL;
    ulong bsz = 0UL;

    if( wire==0UL ) {
      shift = 0U;
      for(;;) {
        FD_TEST( o<sz );
        uchar c = buf[ o++ ];
        v |= ( (ulong)( c & 0x7F ) )<<shift;
        shift += 7U;
        if( !( c & 0x80 ) ) break;
      }
    } else if( wire==2UL ) {
      shift = 0U;
      for(;;) {
        FD_TEST( o<sz );
        uchar c = buf[ o++ ];
        bsz |= ( (ulong)( c & 0x7F ) )<<shift;
        shift += 7U;
        if( !( c & 0x80 ) ) break;
      }
      FD_TEST( bsz<=sz-o );
      b  = buf+o;
      o += bsz;
    } else FD_TEST( 0 );

    if( f==field ) {
      if( seen==idx ) {
        if( val     ) *val     = v;
        if( body    ) *body    = b;
        if( body_sz ) *body_sz = bsz;
        return 1;
      }
      seen++;
    }
  }
  return 0;
}

static ulong
pb_varint_of( uchar const * buf,
              ulong         sz,
              uint          field ) {
  ulong val = 0UL;
  FD_TEST( pb_field( buf, sz, field, 0UL, &val, NULL, NULL ) );
  return val;
}

static uchar const *
pb_sub_of( uchar const * buf,
           ulong         sz,
           uint          field,
           ulong         idx,
           ulong *       sub_sz ) {
  uchar const * body = NULL;
  FD_TEST( pb_field( buf, sz, field, idx, NULL, &body, sub_sz ) );
  return body;
}

static ulong
pb_cnt_of( uchar const * buf,
           ulong         sz,
           uint          field ) {
  ulong cnt = 0UL;
  while( pb_field( buf, sz, field, cnt, NULL, NULL, NULL ) ) cnt++;
  return cnt;
}

/* Fixtures ***********************************************************/

static fd_txn_meta_scratch_t scratch[1];
static uchar                 enc[ FD_TXN_META_UPDATE_SZ_MAX ];

/* A legacy transaction that succeeded, with logs, a return value, and
   one top level instruction that invoked two nested ones. */

static void
fixture_success( rec_t *         rec,
                 fd_txn_meta_t * meta ) {
  pl_instr_t instr[1] = {{ .program_id = 2U, .acct_cnt = 2UL, .accts = { 0, 1 },
                           .data_sz = 3UL, .data = { 0xAA, 0xBB, 0xCC } }};

  rec_init( rec );
  pl_legacy( rec->payload, 0, 3U, instr, 1UL, 0UL, 0UL );
  rec->ev->payload_cnt = rec->payload->sz;
  rec_keys( rec, 3UL, 0UL, 0UL );

  rec->ev->execution_fee          = 5000UL;
  rec->ev->priority_fee           = 1000UL;
  rec->ev->compute_unit_limit     = 200000UL;
  rec->ev->compute_units_consumed = 4321UL;
  rec->ev->cost_units             = 1234UL;

  rec_log( rec, "Program log: hello" );
  rec_log( rec, "Program log: bye"   );

  uchar top_accts[ 2 ] = { 0, 1 };
  uchar cpi_accts[ 1 ] = { 0 };
  uchar top_data [ 3 ] = { 0xAA, 0xBB, 0xCC };
  uchar cpi_data [ 2 ] = { 0xDD, 0xEE };
  uchar cpi2_data[ 1 ] = { 0xFF };
  rec_instr( rec, 2U, 1U, top_accts, 2UL, top_data,  3UL );
  rec_instr( rec, 1U, 2U, cpi_accts, 1UL, cpi_data,  2UL );
  rec_instr( rec, 1U, 3U, cpi_accts, 1UL, cpi2_data, 1UL );

  rec->ev->return_data_cnt = 2UL;
  rec->return_data[ 0 ]    = 0x01;
  rec->return_data[ 1 ]    = 0x02;
  fd_memset( rec->ev->return_data_program_id, 0x22, 32UL );

  FD_TEST( !fd_txn_meta_from_commit( meta, scratch, rec->parts ) );
}

static void
test_success( void ) {
  rec_t         rec[1];
  fd_txn_meta_t meta[1];
  fixture_success( rec, meta );

  FD_TEST( meta->txn->transaction_version==FD_TXN_VLEGACY );
  FD_TEST( meta->err.kind==FD_TXN_META_ERR_NONE );
  FD_TEST( meta->fee==6000UL );
  FD_TEST( meta->balance_cnt==3UL );
  FD_TEST( meta->pre_balances[ 0 ]==10UL && meta->post_balances[ 0 ]==9UL );
  FD_TEST( meta->key_cnt==3UL && meta->static_key_cnt==3UL );
  FD_TEST( !meta->loaded_writable_cnt && !meta->loaded_readonly_cnt );
  FD_TEST( meta->compute_units_consumed==4321UL );
  FD_TEST( meta->cost_units==1234UL );
  FD_TEST( !meta->inner_none && !meta->logs_none && !meta->return_data_none );
  FD_TEST( meta->logs.cnt==2UL );
  FD_TEST( meta->return_data_sz==2UL );

  /* The two nested instructions belong to the first top level
     instruction, and the top level instruction itself is not one of
     them. */
  FD_TEST( meta->inner_cnt==1UL );
  FD_TEST( meta->inner[ 0 ].index==0U );
  FD_TEST( meta->inner[ 0 ].instr_cnt==2UL );
  FD_TEST( meta->inner[ 0 ].instr[ 0 ].stack_height==2U );
  FD_TEST( meta->inner[ 0 ].instr[ 0 ].program_id_idx==1U );
  FD_TEST( meta->inner[ 0 ].instr[ 0 ].data_sz==2UL );
  FD_TEST( meta->inner[ 0 ].instr[ 0 ].data[ 0 ]==0xDD );
  FD_TEST( meta->inner[ 0 ].instr[ 1 ].stack_height==3U );
  FD_TEST( meta->inner[ 0 ].instr[ 1 ].data_sz==1UL );
  FD_TEST( meta->inner[ 0 ].instr[ 1 ].data[ 0 ]==0xFF );

  /* The log messages come back out of the collector's serialization. */
  ulong         off = 0UL;
  ulong         msg_sz;
  uchar const * msg = fd_txn_meta_log_next( &meta->logs, &off, &msg_sz );
  FD_TEST( msg && msg_sz==18UL && !memcmp( msg, "Program log: hello", 18UL ) );
  msg = fd_txn_meta_log_next( &meta->logs, &off, &msg_sz );
  FD_TEST( msg && msg_sz==16UL && !memcmp( msg, "Program log: bye", 16UL ) );
  FD_TEST( !fd_txn_meta_log_next( &meta->logs, &off, &msg_sz ) );

  /* The transaction as the wire carries it. */
  ulong sz = fd_txn_meta_encode_transaction( meta, enc, sizeof(enc) );
  FD_TEST( sz!=ULONG_MAX && pb_valid( enc, sz ) );
  FD_TEST( pb_cnt_of( enc, sz, 1U )==1UL ); /* one signature */

  ulong         msg_sz2;
  uchar const * message = pb_sub_of( enc, sz, 2U, 0UL, &msg_sz2 );
  FD_TEST( pb_valid( message, msg_sz2 ) );
  ulong         hdr_sz;
  uchar const * hdr = pb_sub_of( message, msg_sz2, 1U, 0UL, &hdr_sz );
  FD_TEST( pb_varint_of( hdr, hdr_sz, 1U )==1UL ); /* required signatures */
  FD_TEST( pb_varint_of( hdr, hdr_sz, 3U )==1UL ); /* readonly unsigned */
  FD_TEST( pb_cnt_of( message, msg_sz2, 2U )==3UL ); /* account keys */
  FD_TEST( pb_cnt_of( message, msg_sz2, 4U )==1UL ); /* instructions */
  FD_TEST( !pb_field( message, msg_sz2, 5U, 0UL, NULL, NULL, NULL ) ); /* not versioned */
  FD_TEST( !pb_field( message, msg_sz2, 6U, 0UL, NULL, NULL, NULL ) ); /* no lookups */
  FD_TEST( !pb_field( message, msg_sz2, 7U, 0UL, NULL, NULL, NULL ) ); /* no inline config */

  ulong         instr_sz;
  uchar const * instr = pb_sub_of( message, msg_sz2, 4U, 0UL, &instr_sz );
  FD_TEST( pb_varint_of( instr, instr_sz, 1U )==2UL );
  ulong         accts_sz;
  uchar const * accts = pb_sub_of( instr, instr_sz, 2U, 0UL, &accts_sz );
  FD_TEST( accts_sz==2UL && accts[ 0 ]==0 && accts[ 1 ]==1 );
  ulong         data_sz;
  uchar const * data = pb_sub_of( instr, instr_sz, 3U, 0UL, &data_sz );
  FD_TEST( data_sz==3UL && data[ 0 ]==0xAA );

  /* The meta as the wire carries it. */
  sz = fd_txn_meta_encode_meta( meta, enc, sizeof(enc) );
  FD_TEST( sz!=ULONG_MAX && pb_valid( enc, sz ) );
  FD_TEST( !pb_field( enc, sz, 1U, 0UL, NULL, NULL, NULL ) ); /* no error */
  FD_TEST( pb_varint_of( enc, sz, 2U )==6000UL );             /* fee */
  ulong         bal_sz;
  uchar const * bal = pb_sub_of( enc, sz, 3U, 0UL, &bal_sz );
  FD_TEST( bal_sz==3UL && bal[ 0 ]==10 && bal[ 1 ]==20 && bal[ 2 ]==30 );
  bal = pb_sub_of( enc, sz, 4U, 0UL, &bal_sz );
  FD_TEST( bal_sz==3UL && bal[ 0 ]==9 && bal[ 1 ]==19 && bal[ 2 ]==29 );

  ulong         inner_sz;
  uchar const * inner = pb_sub_of( enc, sz, 5U, 0UL, &inner_sz );
  FD_TEST( !pb_field( inner, inner_sz, 1U, 0UL, NULL, NULL, NULL ) ); /* index 0 */
  FD_TEST( pb_cnt_of( inner, inner_sz, 2U )==2UL );
  ulong         in0_sz;
  uchar const * in0 = pb_sub_of( inner, inner_sz, 2U, 0UL, &in0_sz );
  FD_TEST( pb_varint_of( in0, in0_sz, 1U )==1UL ); /* program */
  FD_TEST( pb_varint_of( in0, in0_sz, 4U )==2UL ); /* stack height */

  FD_TEST( pb_cnt_of( enc, sz, 6U )==2UL );                    /* log messages */
  FD_TEST( !pb_field( enc, sz, 10U, 0UL, NULL, NULL, NULL ) ); /* inner instructions present */
  FD_TEST( !pb_field( enc, sz, 11U, 0UL, NULL, NULL, NULL ) ); /* logs present */
  FD_TEST( !pb_field( enc, sz, 12U, 0UL, NULL, NULL, NULL ) ); /* no loaded addresses */
  FD_TEST( !pb_field( enc, sz, 15U, 0UL, NULL, NULL, NULL ) ); /* return data present */
  ulong         ret_sz;
  uchar const * ret = pb_sub_of( enc, sz, 14U, 0UL, &ret_sz );
  uchar const * ret_data = pb_sub_of( ret, ret_sz, 2U, 0UL, &data_sz );
  FD_TEST( data_sz==2UL && ret_data[ 0 ]==0x01 );
  FD_TEST( pb_varint_of( enc, sz, 16U )==4321UL );
  FD_TEST( pb_varint_of( enc, sz, 17U )==1234UL );

  /* The update messages. */
  sz = fd_txn_meta_encode_txn_update( meta, enc, sizeof(enc) );
  FD_TEST( sz!=ULONG_MAX && pb_valid( enc, sz ) );
  FD_TEST( pb_varint_of( enc, sz, 2U )==100UL ); /* slot */
  FD_TEST( pb_varint_of( enc, sz, 3U )==7UL );   /* bank id */
  ulong         info_sz;
  uchar const * info = pb_sub_of( enc, sz, 1U, 0UL, &info_sz );
  FD_TEST( pb_valid( info, info_sz ) );
  uchar const * sig = pb_sub_of( info, info_sz, 1U, 0UL, &data_sz );
  FD_TEST( data_sz==64UL && sig[ 0 ]==0x11 );
  FD_TEST( !pb_field( info, info_sz, 2U, 0UL, NULL, NULL, NULL ) ); /* not a vote */
  FD_TEST( pb_varint_of( info, info_sz, 5U )==2UL );                /* index in slot */

  sz = fd_txn_meta_encode_txn_status( meta, enc, sizeof(enc) );
  FD_TEST( sz!=ULONG_MAX && pb_valid( enc, sz ) );
  FD_TEST( pb_varint_of( enc, sz, 1U )==100UL );
  FD_TEST( pb_varint_of( enc, sz, 4U )==2UL );
  FD_TEST( pb_varint_of( enc, sz, 6U )==7UL );
  FD_TEST( !pb_field( enc, sz, 3U, 0UL, NULL, NULL, NULL ) ); /* not a vote */
  FD_TEST( !pb_field( enc, sz, 5U, 0UL, NULL, NULL, NULL ) ); /* no error */
}

/* The bytes a protobuf encoder produces for the first fixture's
   SubscribeUpdateTransaction, for the exact message the test above
   builds. */

static uchar const success_update[] = {
#include "test_txn_meta_success.inc"
};

static void
test_success_bytes( void ) {
  rec_t         rec[1];
  fd_txn_meta_t meta[1];
  fixture_success( rec, meta );

  ulong sz = fd_txn_meta_encode_txn_update( meta, enc, sizeof(enc) );
  FD_TEST( sz==sizeof(success_update) );
  FD_TEST( !memcmp( enc, success_update, sz ) );
}

/* A transaction whose third instruction failed with a program's own
   error code. */

static void
test_custom_err( void ) {
  rec_t         rec[1];
  fd_txn_meta_t meta[1];
  pl_instr_t    instr[1] = {{ .program_id = 2U, .acct_cnt = 1UL, .accts = { 0 },
                              .data_sz = 1UL, .data = { 0x01 } }};

  rec_init( rec );
  pl_legacy( rec->payload, 0, 3U, instr, 1UL, 0UL, 0UL );
  rec->ev->payload_cnt = rec->payload->sz;
  rec_keys( rec, 3UL, 0UL, 0UL );

  rec->ev->txn_err       = -9L;  /* instruction error */
  rec->ev->exec_err      = -26L; /* custom */
  rec->ev->exec_err_idx  = 2U;
  rec->ev->custom_err    = 42U;
  rec->ev->execution_fee = 5000UL;

  FD_TEST( !fd_txn_meta_from_commit( meta, scratch, rec->parts ) );
  FD_TEST( meta->err.kind==FD_TXN_META_ERR_INSTR );
  FD_TEST( meta->err.instr_idx==2U && meta->err.custom==42U );

  /* InstructionError is variant 8 of agave's TransactionError, which is
     Firedancer's -9 as -(8+1); Custom is variant 25 of
     InstructionError, which is -26 as -(25+1).  The encoding is the u32
     variant, the u8 instruction index, the u32 instruction variant and
     the u32 code. */
  uchar err[ FD_TXN_META_ERR_SZ_MAX ];
  ulong err_sz = fd_txn_meta_err_encode( &meta->err, err );
  uchar const expected[] = { 8,0,0,0, 2, 25,0,0,0, 42,0,0,0 };
  FD_TEST( err_sz==sizeof(expected) );
  FD_TEST( !memcmp( err, expected, err_sz ) );

  ulong sz = fd_txn_meta_encode_meta( meta, enc, sizeof(enc) );
  FD_TEST( sz!=ULONG_MAX && pb_valid( enc, sz ) );
  ulong         terr_sz;
  uchar const * terr = pb_sub_of( enc, sz, 1U, 0UL, &terr_sz );
  ulong         bytes_sz;
  uchar const * bytes = pb_sub_of( terr, terr_sz, 1U, 0UL, &bytes_sz );
  FD_TEST( bytes_sz==sizeof(expected) && !memcmp( bytes, expected, bytes_sz ) );

  /* The lightweight status message carries the same error. */
  sz = fd_txn_meta_encode_txn_status( meta, enc, sizeof(enc) );
  FD_TEST( sz!=ULONG_MAX && pb_valid( enc, sz ) );
  terr  = pb_sub_of( enc, sz, 5U, 0UL, &terr_sz );
  bytes = pb_sub_of( terr, terr_sz, 1U, 0UL, &bytes_sz );
  FD_TEST( bytes_sz==sizeof(expected) && !memcmp( bytes, expected, bytes_sz ) );
}

/* A transaction that left an account below the rent exempt minimum,
   which is the error that names an account. */

static void
test_rent_err( void ) {
  rec_t         rec[1];
  fd_txn_meta_t meta[1];
  pl_instr_t    instr[1] = {{ .program_id = 2U, .acct_cnt = 1UL, .accts = { 0 },
                              .data_sz = 1UL, .data = { 0x01 } }};

  rec_init( rec );
  pl_legacy( rec->payload, 0, 3U, instr, 1UL, 0UL, 0UL );
  rec->ev->payload_cnt = rec->payload->sz;
  rec_keys( rec, 3UL, 0UL, 0UL );

  rec->ev->txn_err              = -32L; /* insufficient funds for rent */
  rec->ev->rent_err_account_idx = 1U;

  FD_TEST( !fd_txn_meta_from_commit( meta, scratch, rec->parts ) );
  FD_TEST( meta->err.kind==FD_TXN_META_ERR_TXN );
  FD_TEST( meta->err.acct_idx==1U );

  /* InsufficientFundsForRent is variant 31, which is -32 as -(31+1),
     and carries the account index as a u8. */
  uchar err[ FD_TXN_META_ERR_SZ_MAX ];
  ulong err_sz = fd_txn_meta_err_encode( &meta->err, err );
  uchar const expected[] = { 31,0,0,0, 1 };
  FD_TEST( err_sz==sizeof(expected) );
  FD_TEST( !memcmp( err, expected, err_sz ) );
}

/* The plain transaction errors, and the ones that report why a
   blockhash lookup failed, which agave has one variant for. */

static void
test_plain_errs( void ) {
  struct { long code; uint variant; } const cases[] = {
    { -2L,  1U }, /* AccountLoadedTwice */
    { -3L,  2U }, /* AccountNotFound */
    { -5L,  4U }, /* InsufficientFundsForFee */
    { -8L,  7U }, /* BlockhashNotFound */
    { -13L, 12U }, /* SignatureFailure */
    { -37L, 36U }, /* UnbalancedTransaction */
    { -50L, 7U }, /* nonce already advanced, reported as BlockhashNotFound */
    { -51L, 7U },
    { -52L, 7U }
  };

  for( ulong i=0UL; i<sizeof(cases)/sizeof(cases[0]); i++ ) {
    fd_txn_meta_err_t err = { .kind = FD_TXN_META_ERR_TXN, .txn_err = cases[ i ].code,
                              .instr_idx = UINT_MAX, .custom = UINT_MAX, .acct_idx = UINT_MAX };
    uchar out[ FD_TXN_META_ERR_SZ_MAX ];
    FD_TEST( fd_txn_meta_err_encode( &err, out )==4UL );
    FD_TEST( out[ 0 ]==(uchar)cases[ i ].variant && !out[ 1 ] && !out[ 2 ] && !out[ 3 ] );
  }

  /* A code no agave variant corresponds to encodes to nothing. */
  fd_txn_meta_err_t none = { .kind = FD_TXN_META_ERR_NONE };
  uchar out[ FD_TXN_META_ERR_SZ_MAX ];
  FD_TEST( !fd_txn_meta_err_encode( &none, out ) );
  fd_txn_meta_err_t peer = { .kind = FD_TXN_META_ERR_TXN, .txn_err = -40L };
  FD_TEST( !fd_txn_meta_err_encode( &peer, out ) );
}

/* A transaction that landed but only paid fees: it never ran, so it
   reports no logs, no inner instructions, no return data and no
   compute units. */

static void
test_fees_only( void ) {
  rec_t         rec[1];
  fd_txn_meta_t meta[1];
  pl_instr_t    instr[1] = {{ .program_id = 2U, .acct_cnt = 1UL, .accts = { 0 },
                              .data_sz = 1UL, .data = { 0x01 } }};

  rec_init( rec );
  pl_legacy( rec->payload, 0, 3U, instr, 1UL, 0UL, 0UL );
  rec->ev->payload_cnt = rec->payload->sz;
  rec_keys( rec, 3UL, 0UL, 0UL );

  rec->ev->is_fees_only           = 1;
  rec->ev->txn_err                = -4L; /* program account not found */
  rec->ev->execution_fee          = 5000UL;
  rec->ev->compute_unit_limit     = 200000UL;
  rec->ev->compute_units_consumed = 0UL;
  rec->ev->cost_units             = 720UL;

  FD_TEST( !fd_txn_meta_from_commit( meta, scratch, rec->parts ) );
  FD_TEST( meta->inner_none && meta->logs_none && meta->return_data_none );
  FD_TEST( !meta->inner_cnt && !meta->logs.cnt && !meta->return_data_sz );
  FD_TEST( !meta->compute_units_consumed );
  FD_TEST( meta->fee==5000UL );

  ulong sz = fd_txn_meta_encode_meta( meta, enc, sizeof(enc) );
  FD_TEST( sz!=ULONG_MAX && pb_valid( enc, sz ) );
  FD_TEST( pb_varint_of( enc, sz, 10U )==1UL ); /* inner instructions absent */
  FD_TEST( pb_varint_of( enc, sz, 11U )==1UL ); /* logs absent */
  FD_TEST( pb_varint_of( enc, sz, 15U )==1UL ); /* return data absent */
  FD_TEST( pb_varint_of( enc, sz, 16U )==0UL ); /* compute units consumed */
  FD_TEST( pb_varint_of( enc, sz, 17U )==720UL );
  FD_TEST( !pb_field( enc, sz, 5U, 0UL, NULL, NULL, NULL ) );
  FD_TEST( !pb_field( enc, sz, 6U, 0UL, NULL, NULL, NULL ) );
}

/* A simple vote transaction. */

static void
test_vote( void ) {
  rec_t         rec[1];
  fd_txn_meta_t meta[1];
  pl_instr_t    instr[1] = {{ .program_id = 2U, .acct_cnt = 1UL, .accts = { 0 },
                              .data_sz = 1UL, .data = { 0x01 } }};

  rec_init( rec );
  pl_legacy( rec->payload, 0, 3U, instr, 1UL, 0UL, 0UL );
  rec->ev->payload_cnt    = rec->payload->sz;
  rec->ev->is_simple_vote = 1;
  rec_keys( rec, 3UL, 0UL, 0UL );

  FD_TEST( !fd_txn_meta_from_commit( meta, scratch, rec->parts ) );
  FD_TEST( meta->is_vote );

  ulong sz = fd_txn_meta_encode_txn_update( meta, enc, sizeof(enc) );
  FD_TEST( sz!=ULONG_MAX && pb_valid( enc, sz ) );
  ulong         info_sz;
  uchar const * info = pb_sub_of( enc, sz, 1U, 0UL, &info_sz );
  FD_TEST( pb_varint_of( info, info_sz, 2U )==1UL );

  sz = fd_txn_meta_encode_txn_status( meta, enc, sizeof(enc) );
  FD_TEST( sz!=ULONG_MAX && pb_valid( enc, sz ) );
  FD_TEST( pb_varint_of( enc, sz, 3U )==1UL );
}

/* A V0 transaction: the message is versioned and carries its lookup
   table, and the addresses the table loaded are in the meta, the
   writable ones first. */

static void
test_v0_loaded( void ) {
  rec_t         rec[1];
  fd_txn_meta_t meta[1];
  pl_instr_t    instr[1] = {{ .program_id = 2U, .acct_cnt = 1UL, .accts = { 0 },
                              .data_sz = 1UL, .data = { 0x01 } }};

  rec_init( rec );
  pl_legacy( rec->payload, 1, 3U, instr, 1UL, 2UL, 1UL );
  rec->ev->payload_cnt = rec->payload->sz;
  rec_keys( rec, 3UL, 2UL, 1UL );

  FD_TEST( !fd_txn_meta_from_commit( meta, scratch, rec->parts ) );
  FD_TEST( meta->txn->transaction_version==FD_TXN_V0 );
  FD_TEST( meta->key_cnt==6UL && meta->static_key_cnt==3UL );
  FD_TEST( meta->loaded_writable_cnt==2UL && meta->loaded_readonly_cnt==1UL );

  ulong sz = fd_txn_meta_encode_transaction( meta, enc, sizeof(enc) );
  FD_TEST( sz!=ULONG_MAX && pb_valid( enc, sz ) );
  ulong         msg_sz;
  uchar const * message = pb_sub_of( enc, sz, 2U, 0UL, &msg_sz );
  FD_TEST( pb_cnt_of( message, msg_sz, 2U )==3UL ); /* the message's own keys */
  FD_TEST( pb_varint_of( message, msg_sz, 5U )==1UL ); /* versioned */
  ulong         lut_sz;
  uchar const * lut = pb_sub_of( message, msg_sz, 6U, 0UL, &lut_sz );
  ulong         idx_sz;
  uchar const * key = pb_sub_of( lut, lut_sz, 1U, 0UL, &idx_sz );
  FD_TEST( idx_sz==32UL && key[ 0 ]==0x40 );
  uchar const * w = pb_sub_of( lut, lut_sz, 2U, 0UL, &idx_sz );
  FD_TEST( idx_sz==2UL && w[ 0 ]==7 && w[ 1 ]==8 );
  uchar const * r = pb_sub_of( lut, lut_sz, 3U, 0UL, &idx_sz );
  FD_TEST( idx_sz==1UL && r[ 0 ]==9 );

  sz = fd_txn_meta_encode_meta( meta, enc, sizeof(enc) );
  FD_TEST( sz!=ULONG_MAX && pb_valid( enc, sz ) );
  FD_TEST( pb_cnt_of( enc, sz, 12U )==2UL );
  FD_TEST( pb_cnt_of( enc, sz, 13U )==1UL );
  uchar const * addr = pb_sub_of( enc, sz, 12U, 0UL, &idx_sz );
  FD_TEST( idx_sz==32UL && addr[ 0 ]==0x50 );
  addr = pb_sub_of( enc, sz, 13U, 0UL, &idx_sz );
  FD_TEST( idx_sz==32UL && addr[ 0 ]==0x52 );
}

/* A V1 transaction: versioned, no lookup tables, and the inline budget
   fields its config mask names. */

static void
test_v1_config( void ) {
  rec_t         rec[1];
  fd_txn_meta_t meta[1];
  pl_instr_t    instr[1] = {{ .program_id = 2U, .acct_cnt = 1UL, .accts = { 0 },
                              .data_sz = 1UL, .data = { 0x01 } }};

  /* Bits 0 and 1 are the priority fee, bit 2 the compute unit limit,
     bit 3 the loaded accounts data size limit and bit 4 the heap
     size. */
  rec_init( rec );
  pl_v1( rec->payload, 0x1FU, 12345UL, 300000U, 65536U, 64UL*1024UL, 3U, instr, 1UL );
  rec->ev->payload_cnt = rec->payload->sz;
  rec_keys( rec, 3UL, 0UL, 0UL );

  FD_TEST( !fd_txn_meta_from_commit( meta, scratch, rec->parts ) );
  FD_TEST( meta->txn->transaction_version==FD_TXN_V1 );

  ulong sz = fd_txn_meta_encode_transaction( meta, enc, sizeof(enc) );
  FD_TEST( sz!=ULONG_MAX && pb_valid( enc, sz ) );
  ulong         msg_sz;
  uchar const * message = pb_sub_of( enc, sz, 2U, 0UL, &msg_sz );
  FD_TEST( pb_varint_of( message, msg_sz, 5U )==1UL );              /* versioned */
  FD_TEST( !pb_field( message, msg_sz, 6U, 0UL, NULL, NULL, NULL ) ); /* no lookups */
  ulong         cfg_sz;
  uchar const * cfg = pb_sub_of( message, msg_sz, 7U, 0UL, &cfg_sz );
  FD_TEST( pb_varint_of( cfg, cfg_sz, 1U )==12345UL );
  FD_TEST( pb_varint_of( cfg, cfg_sz, 2U )==300000UL );
  FD_TEST( pb_varint_of( cfg, cfg_sz, 3U )==65536UL );
  FD_TEST( pb_varint_of( cfg, cfg_sz, 4U )==65536UL );

  /* A V1 transaction whose mask names only the compute unit limit
     reports that field and no other. */
  rec_init( rec );
  pl_v1( rec->payload, 0x04U, 0UL, 1U, 0U, 0U, 3U, instr, 1UL );
  rec->ev->payload_cnt = rec->payload->sz;
  rec_keys( rec, 3UL, 0UL, 0UL );
  FD_TEST( !fd_txn_meta_from_commit( meta, scratch, rec->parts ) );

  sz      = fd_txn_meta_encode_transaction( meta, enc, sizeof(enc) );
  FD_TEST( sz!=ULONG_MAX && pb_valid( enc, sz ) );
  message = pb_sub_of( enc, sz, 2U, 0UL, &msg_sz );
  cfg     = pb_sub_of( message, msg_sz, 7U, 0UL, &cfg_sz );
  FD_TEST( !pb_field( cfg, cfg_sz, 1U, 0UL, NULL, NULL, NULL ) );
  FD_TEST( pb_varint_of( cfg, cfg_sz, 2U )==1UL );
  FD_TEST( !pb_field( cfg, cfg_sz, 3U, 0UL, NULL, NULL, NULL ) );
  FD_TEST( !pb_field( cfg, cfg_sz, 4U, 0UL, NULL, NULL, NULL ) );
}

/* Logs the collector truncated, and a log buffer that does not parse to
   its end, which is cut back to the messages that do. */

static void
test_logs( void ) {
  rec_t         rec[1];
  fd_txn_meta_t meta[1];
  pl_instr_t    instr[1] = {{ .program_id = 2U, .acct_cnt = 1UL, .accts = { 0 },
                              .data_sz = 1UL, .data = { 0x01 } }};

  rec_init( rec );
  pl_legacy( rec->payload, 0, 3U, instr, 1UL, 0UL, 0UL );
  rec->ev->payload_cnt   = rec->payload->sz;
  rec->ev->logs_truncated = 1;
  rec_keys( rec, 3UL, 0UL, 0UL );
  rec_log( rec, "Program log: a" );
  rec_log( rec, "Log truncated" );

  FD_TEST( !fd_txn_meta_from_commit( meta, scratch, rec->parts ) );
  FD_TEST( meta->logs_truncated && meta->logs.cnt==2UL );

  ulong sz = fd_txn_meta_encode_meta( meta, enc, sizeof(enc) );
  FD_TEST( sz!=ULONG_MAX && pb_valid( enc, sz ) );
  FD_TEST( pb_cnt_of( enc, sz, 6U )==2UL );
  ulong         last_sz;
  uchar const * last = pb_sub_of( enc, sz, 6U, 1UL, &last_sz );
  FD_TEST( last_sz==13UL && !memcmp( last, "Log truncated", 13UL ) );

  /* A trailing byte that starts no message is dropped. */
  rec->logs[ rec->ev->logs_cnt++ ] = FD_LOG_COLLECTOR_PROTO_TAG;
  FD_TEST( !fd_txn_meta_from_commit( meta, scratch, rec->parts ) );
  FD_TEST( meta->logs.cnt==2UL );
  sz = fd_txn_meta_encode_meta( meta, enc, sizeof(enc) );
  FD_TEST( sz!=ULONG_MAX && pb_valid( enc, sz ) );
}

/* A record whose payload is not a transaction is refused. */

static void
test_bad_payload( void ) {
  rec_t         rec[1];
  fd_txn_meta_t meta[1];

  rec_init( rec );
  rec->ev->payload_cnt = 8UL;
  rec_keys( rec, 3UL, 0UL, 0UL );
  FD_TEST( fd_txn_meta_from_commit( meta, scratch, rec->parts )==-1 );
}

/* A message that does not fit the caller's buffer is refused rather
   than truncated. */

static void
test_no_room( void ) {
  rec_t         rec[1];
  fd_txn_meta_t meta[1];
  fixture_success( rec, meta );

  ulong sz = fd_txn_meta_encode_txn_update( meta, enc, sizeof(enc) );
  FD_TEST( sz!=ULONG_MAX );
  for( ulong n=0UL; n<sz; n += 17UL ) {
    FD_TEST( fd_txn_meta_encode_txn_update( meta, enc, n )==ULONG_MAX );
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_success();
  test_success_bytes();
  test_custom_err();
  test_rent_err();
  test_plain_errs();
  test_fees_only();
  test_vote();
  test_v0_loaded();
  test_v1_config();
  test_logs();
  test_bad_payload();
  test_no_room();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
