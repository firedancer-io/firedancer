#include "fd_txn_meta.h"
#include "../runtime/fd_runtime_err.h"
#include "../runtime/fd_executor_err.h"
#include "../log_collector/fd_log_collector_base.h"
#include "../../ballet/txn/fd_txn_v1.h"

/* Protobuf writing ***************************************************/

/* Wire types of the encoding.  Only varints and length delimited
   fields appear in these messages. */

#define PB_VARINT (0U)
#define PB_LEN    (2U)

static inline ulong
pb_varint_sz( ulong v ) {
  ulong n = 1UL;
  while( v>=0x80UL ) { v >>= 7; n++; }
  return n;
}

/* A field's tag is the varint of (field<<3)|wire_type; every field
   number in these messages is below 16, so its tag is one byte. */

static inline ulong
pb_key_sz( uint field ) {
  return pb_varint_sz( ((ulong)field)<<3 );
}

static inline ulong
pb_u64_sz( uint  field,
           ulong v ) {
  return pb_key_sz( field ) + pb_varint_sz( v );
}

/* pb_len_sz is the size of a length delimited field whose body is
   body_sz bytes: bytes, strings and submessages. */

static inline ulong
pb_len_sz( uint  field,
           ulong body_sz ) {
  return pb_key_sz( field ) + pb_varint_sz( body_sz ) + body_sz;
}

struct pb_wr {
  uchar * buf;
  ulong   sz;
  ulong   off;
  int     err;
};

typedef struct pb_wr pb_wr_t;

static void
pb_raw( pb_wr_t *    wr,
        void const * data,
        ulong        data_sz ) {
  if( FD_UNLIKELY( wr->off+data_sz>wr->sz ) ) { wr->err = 1; return; }
  if( FD_LIKELY( data_sz ) ) fd_memcpy( wr->buf+wr->off, data, data_sz );
  wr->off += data_sz;
}

static void
pb_varint( pb_wr_t * wr,
           ulong     v ) {
  uchar tmp[ 10 ];
  ulong n = 0UL;
  while( v>=0x80UL ) { tmp[ n++ ] = (uchar)( (v&0x7FUL) | 0x80UL ); v >>= 7; }
  tmp[ n++ ] = (uchar)v;
  pb_raw( wr, tmp, n );
}

static void
pb_key( pb_wr_t * wr,
        uint      field,
        uint      wire ) {
  pb_varint( wr, ( ((ulong)field)<<3 ) | (ulong)wire );
}

static void
pb_u64( pb_wr_t * wr,
        uint      field,
        ulong     v ) {
  pb_key( wr, field, PB_VARINT );
  pb_varint( wr, v );
}

static void
pb_bool( pb_wr_t * wr,
         uint      field,
         int       v ) {
  pb_key( wr, field, PB_VARINT );
  pb_varint( wr, (ulong)!!v );
}

static void
pb_bytes( pb_wr_t *    wr,
          uint         field,
          void const * data,
          ulong        data_sz ) {
  pb_key( wr, field, PB_LEN );
  pb_varint( wr, data_sz );
  pb_raw( wr, data, data_sz );
}

/* pb_sub opens a length delimited field whose body the caller writes
   next.  The body's size has to be known, which is why every message
   below has a size function beside its writer. */

static void
pb_sub( pb_wr_t * wr,
        uint      field,
        ulong     body_sz ) {
  pb_key( wr, field, PB_LEN );
  pb_varint( wr, body_sz );
}

/* Errors *************************************************************/

/* The number of variants of agave's TransactionError
   (solana-transaction-error, AccountInUse .. CommitCancelled) and of
   InstructionError (solana-instruction-error, GenericError ..
   BuiltinProgramsMustConsumeComputeUnits).  A Firedancer code maps to
   the variant -(code+1), so a code outside [-CNT,-1] names no agave
   variant. */

#define TXN_ERR_VARIANT_CNT   (39U)
#define INSTR_ERR_VARIANT_CNT (54U)

/* The variants that carry a payload, by index in agave's enum:

     8 InstructionError(u8, InstructionError)
    30 DuplicateInstruction(u8)
    31 InsufficientFundsForRent{ account_index: u8 }
    35 ProgramExecutionTemporarilyRestricted{ account_index: u8 }

   and InstructionError::Custom(u32) at index 25. */

#define TXN_ERR_INSTRUCTION      ( 8U)
#define TXN_ERR_DUPLICATE_INSTR  (30U)
#define TXN_ERR_FUNDS_FOR_RENT   (31U)
#define TXN_ERR_EXEC_RESTRICTED  (35U)
#define INSTR_ERR_CUSTOM         (25U)

static void
bincode_u32( uchar * out,
             uint    v ) {
  out[ 0 ] = (uchar)( v       );
  out[ 1 ] = (uchar)( v >>  8 );
  out[ 2 ] = (uchar)( v >> 16 );
  out[ 3 ] = (uchar)( v >> 24 );
}

ulong
fd_txn_meta_err_encode( fd_txn_meta_err_t const * err,
                        uchar *                   out ) {
  if( FD_LIKELY( err->kind==FD_TXN_META_ERR_NONE ) ) return 0UL;

  long code = err->txn_err;

  /* The error codes that report why a blockhash lookup failed are all
     the same agave variant. */
  if( FD_UNLIKELY( code==FD_RUNTIME_TXN_ERR_BLOCKHASH_NONCE_ALREADY_ADVANCED ||
                   code==FD_RUNTIME_TXN_ERR_BLOCKHASH_FAIL_ADVANCE_NONCE_INSTR ||
                   code==FD_RUNTIME_TXN_ERR_BLOCKHASH_FAIL_WRONG_NONCE ) ) {
    code = FD_RUNTIME_TXN_ERR_BLOCKHASH_NOT_FOUND;
  }

  if( FD_UNLIKELY( code>=0L || code<-(long)TXN_ERR_VARIANT_CNT ) ) return 0UL;
  uint variant = (uint)( -code - 1L );

  bincode_u32( out, variant );
  ulong o = 4UL;

  switch( variant ) {

  case TXN_ERR_INSTRUCTION: {
    long instr_code = err->instr_err;
    if( FD_UNLIKELY( instr_code>=0L || instr_code<-(long)INSTR_ERR_VARIANT_CNT ) ) return 0UL;
    uint instr_variant = (uint)( -instr_code - 1L );
    out[ o++ ] = (uchar)err->instr_idx;
    bincode_u32( out+o, instr_variant ); o += 4UL;
    if( instr_variant==INSTR_ERR_CUSTOM ) { bincode_u32( out+o, err->custom ); o += 4UL; }
    break;
  }

  case TXN_ERR_DUPLICATE_INSTR:
    out[ o++ ] = (uchar)( err->instr_idx==UINT_MAX ? 0U : err->instr_idx );
    break;

  case TXN_ERR_FUNDS_FOR_RENT:
  case TXN_ERR_EXEC_RESTRICTED:
    out[ o++ ] = (uchar)( err->acct_idx==UINT_MAX ? 0U : err->acct_idx );
    break;

  default:
    break;
  }

  return o;
}

/* Construction *******************************************************/

uchar const *
fd_txn_meta_log_next( fd_txn_meta_logs_t const * logs,
                      ulong *                    off,
                      ulong *                    msg_sz ) {
  ulong         o   = *off;
  uchar const * buf = logs->buf;

  if( FD_UNLIKELY( o>=logs->buf_sz ) ) return NULL;
  if( FD_UNLIKELY( buf[ o ]!=FD_LOG_COLLECTOR_PROTO_TAG ) ) return NULL;
  o++;

  /* The length is a protobuf varint, which the collector writes in one
     or two bytes. */
  if( FD_UNLIKELY( o>=logs->buf_sz ) ) return NULL;
  ulong len = (ulong)( buf[ o ] & 0x7F );
  int   ext = !!( buf[ o ] & 0x80 );
  o++;
  if( FD_UNLIKELY( ext ) ) {
    if( FD_UNLIKELY( o>=logs->buf_sz ) ) return NULL;
    len |= ( (ulong)( buf[ o ] & 0x7F ) )<<7;
    if( FD_UNLIKELY( buf[ o ] & 0x80 ) ) return NULL;
    o++;
  }

  if( FD_UNLIKELY( len>logs->buf_sz-o ) ) return NULL;

  *msg_sz = len;
  *off    = o+len;
  return buf+o;
}

/* txn_meta_log_scan counts the messages of the collector buffer and
   reports how much of it is well formed.  The encoder copies the
   buffer verbatim, so a buffer that does not parse to its end is cut
   back to the last message that did. */

static void
txn_meta_log_scan( fd_txn_meta_logs_t * logs ) {
  ulong off = 0UL;
  ulong cnt = 0UL;
  for(;;) {
    ulong msg_sz;
    if( FD_UNLIKELY( !fd_txn_meta_log_next( logs, &off, &msg_sz ) ) ) break;
    cnt++;
  }
  logs->buf_sz = off;
  logs->cnt    = cnt;
}

int
fd_txn_meta_from_commit( fd_txn_meta_t *                          out,
                         fd_txn_meta_scratch_t *                  scratch,
                         fd_event_internal_commit_parts_t const * parts ) {
  fd_event_internal_commit_t const * msg = parts->prefix;

  fd_memset( out, 0, sizeof(fd_txn_meta_t) );

  if( FD_UNLIKELY( !fd_txn_parse( parts->payload, msg->payload_cnt, scratch->txn_buf, NULL ) ) ) return -1;
  fd_txn_t const * txn = (fd_txn_t const *)scratch->txn_buf;

  out->txn           = txn;
  out->payload       = parts->payload;
  out->payload_sz    = msg->payload_cnt;
  out->signature     = msg->signature;
  out->is_vote       = !!msg->is_simple_vote;
  out->index_in_slot = msg->index_in_slot;
  out->slot          = msg->slot;
  out->bank_id       = msg->bank_seq;

  out->keys                = parts->keys;
  out->key_cnt             = msg->keys_cnt;
  out->static_key_cnt      = fd_ulong_min( (ulong)msg->acct_addr_cnt, msg->keys_cnt );
  out->loaded_writable_cnt = fd_ulong_min( (ulong)msg->adtl_writable_cnt, msg->keys_cnt-out->static_key_cnt );
  out->loaded_readonly_cnt = msg->keys_cnt - out->static_key_cnt - out->loaded_writable_cnt;

  /* The error.  A transaction error that names an instruction carries
     the instruction's own error; every other one stands alone. */
  if( FD_UNLIKELY( msg->txn_err ) ) {
    out->err.kind      = msg->txn_err==FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR ? FD_TXN_META_ERR_INSTR
                                                                            : FD_TXN_META_ERR_TXN;
    out->err.txn_err   = msg->txn_err;
    out->err.instr_err = msg->exec_err;
    out->err.instr_idx = msg->exec_err_idx;
    out->err.custom    = msg->custom_err;
    out->err.acct_idx  = msg->rent_err_account_idx;
  } else {
    out->err.kind      = FD_TXN_META_ERR_NONE;
    out->err.instr_idx = UINT_MAX;
    out->err.custom    = UINT_MAX;
    out->err.acct_idx  = UINT_MAX;
  }

  /* agave's fee_details.total_fee() */
  out->fee = msg->execution_fee + msg->priority_fee;

  out->pre_balances  = parts->pre_lamports;
  out->post_balances = parts->post_lamports;
  out->balance_cnt   = msg->keys_cnt;

  /* A transaction that only paid fees never ran, so agave records no
     logs, no inner instructions and no return data for it. */
  out->inner_none       = !!msg->is_fees_only;
  out->logs_none        = !!msg->is_fees_only;
  out->logs_truncated   = !!msg->logs_truncated;
  out->logs.buf         = parts->logs;
  out->logs.buf_sz      = msg->is_fees_only ? 0UL : msg->logs_cnt;
  txn_meta_log_scan( &out->logs );

  out->return_data            = parts->return_data;
  out->return_data_sz         = msg->is_fees_only ? 0UL : msg->return_data_cnt;
  out->return_data_program_id = msg->return_data_program_id;
  out->return_data_none       = !out->return_data_sz;

  out->compute_units_consumed = msg->compute_units_consumed;
  out->cost_units             = msg->cost_units;

  /* The instruction trace, grouped the way agave's
     map_inner_instructions groups it
     (transaction-status/src/lib.rs:130-146): a top level instruction
     opens the group of the instructions it invokes, the group is
     indexed by the position of that instruction, and a group with no
     inner instructions is dropped. */
  ulong trace_cnt = msg->is_fees_only ? 0UL : msg->trace_cnt;
  for( ulong i=0UL; i<trace_cnt; i++ ) {
    fd_event_internal_commit_trace_t const * t = parts->trace + i;
    scratch->instr[ i ].program_id_idx = t->program_id_idx;
    scratch->instr[ i ].stack_height   = t->stack_height;
    scratch->instr[ i ].accts          = parts->trace_accts + t->acct_off;
    scratch->instr[ i ].acct_cnt       = t->acct_cnt;
    scratch->instr[ i ].data           = parts->trace_data + t->data_off;
    scratch->instr[ i ].data_sz        = t->data_sz;
  }

  ulong inner_cnt = 0UL;
  ulong top_idx   = ULONG_MAX;
  ulong open      = ULONG_MAX; /* the group being filled, if any */
  for( ulong i=0UL; i<trace_cnt; i++ ) {
    if( scratch->instr[ i ].stack_height<=1U ) {
      top_idx = top_idx==ULONG_MAX ? 0UL : top_idx+1UL;
      open    = ULONG_MAX;
      continue;
    }
    if( FD_UNLIKELY( top_idx==ULONG_MAX || top_idx>=FD_TXN_INSTR_MAX ) ) continue;

    if( open==ULONG_MAX ) {
      if( FD_UNLIKELY( inner_cnt>=FD_TXN_INSTR_MAX ) ) break;
      open = inner_cnt++;
      scratch->inner[ open ].index     = (uint)top_idx;
      scratch->inner[ open ].instr     = scratch->instr + i;
      scratch->inner[ open ].instr_cnt = 0UL;
    }
    scratch->inner[ open ].instr_cnt++;
  }

  out->inner     = scratch->inner;
  out->inner_cnt = inner_cnt;
  return 0;
}

/* Transaction encoding ***********************************************/

/* solana.storage.ConfirmedBlock.MessageHeader */

static ulong
enc_header_sz( fd_txn_t const * txn ) {
  ulong sz = 0UL;
  if( txn->signature_cnt         ) sz += pb_u64_sz( FD_TXN_META_F_HDR_NUM_REQUIRED_SIGNATURES, (ulong)txn->signature_cnt         );
  if( txn->readonly_signed_cnt   ) sz += pb_u64_sz( FD_TXN_META_F_HDR_NUM_READONLY_SIGNED, (ulong)txn->readonly_signed_cnt   );
  if( txn->readonly_unsigned_cnt ) sz += pb_u64_sz( FD_TXN_META_F_HDR_NUM_READONLY_UNSIGNED, (ulong)txn->readonly_unsigned_cnt );
  return sz;
}

static void
enc_header( pb_wr_t *        wr,
            fd_txn_t const * txn ) {
  if( txn->signature_cnt         ) pb_u64( wr, FD_TXN_META_F_HDR_NUM_REQUIRED_SIGNATURES, (ulong)txn->signature_cnt         );
  if( txn->readonly_signed_cnt   ) pb_u64( wr, FD_TXN_META_F_HDR_NUM_READONLY_SIGNED, (ulong)txn->readonly_signed_cnt   );
  if( txn->readonly_unsigned_cnt ) pb_u64( wr, FD_TXN_META_F_HDR_NUM_READONLY_UNSIGNED, (ulong)txn->readonly_unsigned_cnt );
}

/* solana.storage.ConfirmedBlock.CompiledInstruction */

static ulong
enc_instr_sz( fd_txn_instr_t const * instr ) {
  ulong sz = 0UL;
  if( instr->program_id ) sz += pb_u64_sz( FD_TXN_META_F_CI_PROGRAM_ID_INDEX, (ulong)instr->program_id );
  if( instr->acct_cnt   ) sz += pb_len_sz( FD_TXN_META_F_CI_ACCOUNTS, (ulong)instr->acct_cnt   );
  if( instr->data_sz    ) sz += pb_len_sz( FD_TXN_META_F_CI_DATA, (ulong)instr->data_sz    );
  return sz;
}

static void
enc_instr( pb_wr_t *              wr,
           fd_txn_instr_t const * instr,
           uchar const *          payload ) {
  if( instr->program_id ) pb_u64  ( wr, FD_TXN_META_F_CI_PROGRAM_ID_INDEX, (ulong)instr->program_id );
  if( instr->acct_cnt   ) pb_bytes( wr, FD_TXN_META_F_CI_ACCOUNTS, fd_txn_get_instr_accts( instr, payload ), (ulong)instr->acct_cnt );
  if( instr->data_sz    ) pb_bytes( wr, FD_TXN_META_F_CI_DATA, fd_txn_get_instr_data ( instr, payload ), (ulong)instr->data_sz  );
}

/* solana.storage.ConfirmedBlock.MessageAddressTableLookup */

static ulong
enc_lut_sz( fd_txn_acct_addr_lut_t const * lut ) {
  ulong sz = pb_len_sz( FD_TXN_META_F_LUT_ACCOUNT_KEY, 32UL );
  if( lut->writable_cnt ) sz += pb_len_sz( FD_TXN_META_F_LUT_WRITABLE_INDEXES, (ulong)lut->writable_cnt );
  if( lut->readonly_cnt ) sz += pb_len_sz( FD_TXN_META_F_LUT_READONLY_INDEXES, (ulong)lut->readonly_cnt );
  return sz;
}

static void
enc_lut( pb_wr_t *                      wr,
         fd_txn_acct_addr_lut_t const * lut,
         uchar const *                  payload ) {
  pb_bytes( wr, FD_TXN_META_F_LUT_ACCOUNT_KEY, payload+lut->addr_off, 32UL );
  if( lut->writable_cnt ) pb_bytes( wr, FD_TXN_META_F_LUT_WRITABLE_INDEXES, payload+lut->writable_off, (ulong)lut->writable_cnt );
  if( lut->readonly_cnt ) pb_bytes( wr, FD_TXN_META_F_LUT_READONLY_INDEXES, payload+lut->readonly_off, (ulong)lut->readonly_cnt );
}

/* solana.storage.ConfirmedBlock.TransactionConfig, the inline budget
   of a V1 transaction.  Every field has explicit presence, so the ones
   the transaction's config mask names are written even when they are
   zero, and the ones it does not name are absent.  The mask sits right
   behind the four header bytes of the payload; the values it names are
   packed in ascending bit order at v1_txn_config_values_off. */

#define V1_CONFIG_MASK_OFF (4UL)

#define V1_CONFIG_PRIORITY_FEE (1U<<0)
#define V1_CONFIG_CU_LIMIT     (1U<<2)
#define V1_CONFIG_LOADED_SZ    (1U<<3)
#define V1_CONFIG_HEAP_SZ      (1U<<4)

struct txn_v1_config {
  int   present;
  uint  mask;
  ulong priority_fee;
  uint  cu_limit;
  uint  loaded_sz;
  uint  heap_sz;
};

typedef struct txn_v1_config txn_v1_config_t;

static void
txn_v1_config( txn_v1_config_t *     cfg,
               fd_txn_meta_t const * meta ) {
  fd_memset( cfg, 0, sizeof(txn_v1_config_t) );
  if( meta->txn->transaction_version!=FD_TXN_V1 ) return;
  if( FD_UNLIKELY( meta->payload_sz<V1_CONFIG_MASK_OFF+4UL ) ) return;

  cfg->present = 1;
  cfg->mask    = fd_uint_load_4( meta->payload+V1_CONFIG_MASK_OFF );

  uchar const * v = meta->payload + meta->txn->v1_txn_config_values_off;
  if(  cfg->mask & V1_CONFIG_PRIORITY_FEE ) { cfg->priority_fee = FD_LOAD( ulong, v ); v += 8UL; }
  if(  cfg->mask & V1_CONFIG_CU_LIMIT     ) { cfg->cu_limit     = FD_LOAD( uint,  v ); v += 4UL; }
  if(  cfg->mask & V1_CONFIG_LOADED_SZ    ) { cfg->loaded_sz    = FD_LOAD( uint,  v ); v += 4UL; }
  if(  cfg->mask & V1_CONFIG_HEAP_SZ      ) { cfg->heap_sz      = FD_LOAD( uint,  v );           }
}

static ulong
enc_config_sz( txn_v1_config_t const * cfg ) {
  ulong sz = 0UL;
  if( cfg->mask & V1_CONFIG_PRIORITY_FEE ) sz += pb_u64_sz( FD_TXN_META_F_CFG_PRIORITY_FEE, cfg->priority_fee     );
  if( cfg->mask & V1_CONFIG_CU_LIMIT     ) sz += pb_u64_sz( FD_TXN_META_F_CFG_COMPUTE_UNIT_LIMIT, (ulong)cfg->cu_limit  );
  if( cfg->mask & V1_CONFIG_LOADED_SZ    ) sz += pb_u64_sz( FD_TXN_META_F_CFG_LOADED_ACCOUNTS_DATA_SIZE, (ulong)cfg->loaded_sz );
  if( cfg->mask & V1_CONFIG_HEAP_SZ      ) sz += pb_u64_sz( FD_TXN_META_F_CFG_HEAP_SIZE, (ulong)cfg->heap_sz   );
  return sz;
}

static void
enc_config( pb_wr_t *               wr,
            txn_v1_config_t const * cfg ) {
  if( cfg->mask & V1_CONFIG_PRIORITY_FEE ) pb_u64( wr, FD_TXN_META_F_CFG_PRIORITY_FEE, cfg->priority_fee     );
  if( cfg->mask & V1_CONFIG_CU_LIMIT     ) pb_u64( wr, FD_TXN_META_F_CFG_COMPUTE_UNIT_LIMIT, (ulong)cfg->cu_limit  );
  if( cfg->mask & V1_CONFIG_LOADED_SZ    ) pb_u64( wr, FD_TXN_META_F_CFG_LOADED_ACCOUNTS_DATA_SIZE, (ulong)cfg->loaded_sz );
  if( cfg->mask & V1_CONFIG_HEAP_SZ      ) pb_u64( wr, FD_TXN_META_F_CFG_HEAP_SIZE, (ulong)cfg->heap_sz   );
}

/* solana.storage.ConfirmedBlock.Message.  versioned is false only for
   a legacy transaction, lookup tables appear only in a V0 one and the
   inline config only in a V1 one (yellowstone create_message,
   convert_to.rs:33-68). */

static ulong
enc_message_sz( fd_txn_meta_t const *   meta,
                txn_v1_config_t const * cfg ) {
  fd_txn_t const * txn = meta->txn;

  ulong sz = pb_len_sz( FD_TXN_META_F_MSG_HEADER, enc_header_sz( txn ) );
  sz += (ulong)txn->acct_addr_cnt*pb_len_sz( FD_TXN_META_F_MSG_ACCOUNT_KEYS, 32UL );
  sz += pb_len_sz( FD_TXN_META_F_MSG_RECENT_BLOCKHASH, 32UL );
  for( ulong i=0UL; i<(ulong)txn->instr_cnt; i++ ) sz += pb_len_sz( FD_TXN_META_F_MSG_INSTRUCTIONS, enc_instr_sz( txn->instr+i ) );
  if( txn->transaction_version!=FD_TXN_VLEGACY ) sz += pb_key_sz( FD_TXN_META_F_MSG_VERSIONED )+1UL;

  fd_txn_acct_addr_lut_t const * lut = fd_txn_get_address_tables_const( txn );
  for( ulong i=0UL; i<(ulong)txn->addr_table_lookup_cnt; i++ ) sz += pb_len_sz( FD_TXN_META_F_MSG_ADDRESS_TABLE_LOOKUPS, enc_lut_sz( lut+i ) );

  if( cfg->present ) sz += pb_len_sz( FD_TXN_META_F_MSG_CONFIG, enc_config_sz( cfg ) );
  return sz;
}

static void
enc_message( pb_wr_t *               wr,
             fd_txn_meta_t const *   meta,
             txn_v1_config_t const * cfg ) {
  fd_txn_t const *      txn     = meta->txn;
  uchar const *         payload = meta->payload;
  fd_acct_addr_t const * addr   = fd_txn_get_acct_addrs( txn, payload );

  pb_sub( wr, FD_TXN_META_F_MSG_HEADER, enc_header_sz( txn ) );
  enc_header( wr, txn );

  for( ulong i=0UL; i<(ulong)txn->acct_addr_cnt; i++ ) pb_bytes( wr, FD_TXN_META_F_MSG_ACCOUNT_KEYS, addr[ i ].b, 32UL );

  pb_bytes( wr, FD_TXN_META_F_MSG_RECENT_BLOCKHASH, fd_txn_get_recent_blockhash( txn, payload ), 32UL );

  for( ulong i=0UL; i<(ulong)txn->instr_cnt; i++ ) {
    pb_sub( wr, FD_TXN_META_F_MSG_INSTRUCTIONS, enc_instr_sz( txn->instr+i ) );
    enc_instr( wr, txn->instr+i, payload );
  }

  if( txn->transaction_version!=FD_TXN_VLEGACY ) pb_bool( wr, FD_TXN_META_F_MSG_VERSIONED, 1 );

  fd_txn_acct_addr_lut_t const * lut = fd_txn_get_address_tables_const( txn );
  for( ulong i=0UL; i<(ulong)txn->addr_table_lookup_cnt; i++ ) {
    pb_sub( wr, FD_TXN_META_F_MSG_ADDRESS_TABLE_LOOKUPS, enc_lut_sz( lut+i ) );
    enc_lut( wr, lut+i, payload );
  }

  if( cfg->present ) {
    pb_sub( wr, FD_TXN_META_F_MSG_CONFIG, enc_config_sz( cfg ) );
    enc_config( wr, cfg );
  }
}

/* solana.storage.ConfirmedBlock.Transaction */

static ulong
enc_transaction_sz( fd_txn_meta_t const *   meta,
                    txn_v1_config_t const * cfg ) {
  ulong sz = (ulong)meta->txn->signature_cnt*pb_len_sz( FD_TXN_META_F_TXN_SIGNATURES, 64UL );
  sz += pb_len_sz( FD_TXN_META_F_TXN_MESSAGE, enc_message_sz( meta, cfg ) );
  return sz;
}

static void
enc_transaction( pb_wr_t *               wr,
                 fd_txn_meta_t const *   meta,
                 txn_v1_config_t const * cfg ) {
  fd_ed25519_sig_t const * sig = fd_txn_get_signatures( meta->txn, meta->payload );
  for( ulong i=0UL; i<(ulong)meta->txn->signature_cnt; i++ ) pb_bytes( wr, FD_TXN_META_F_TXN_SIGNATURES, sig[ i ], 64UL );

  pb_sub( wr, FD_TXN_META_F_TXN_MESSAGE, enc_message_sz( meta, cfg ) );
  enc_message( wr, meta, cfg );
}

ulong
fd_txn_meta_encode_transaction( fd_txn_meta_t const * meta,
                                uchar *               out,
                                ulong                 out_sz ) {
  txn_v1_config_t cfg[1];
  txn_v1_config( cfg, meta );

  pb_wr_t wr = { .buf = out, .sz = out_sz };
  enc_transaction( &wr, meta, cfg );
  return wr.err ? ULONG_MAX : wr.off;
}

/* Meta encoding ******************************************************/

/* solana.storage.ConfirmedBlock.InnerInstruction */

static ulong
enc_inner_instr_sz( fd_txn_meta_instr_t const * instr ) {
  ulong sz = 0UL;
  if( instr->program_id_idx ) sz += pb_u64_sz( FD_TXN_META_F_IN_PROGRAM_ID_INDEX, (ulong)instr->program_id_idx );
  if( instr->acct_cnt       ) sz += pb_len_sz( FD_TXN_META_F_IN_ACCOUNTS, instr->acct_cnt              );
  if( instr->data_sz        ) sz += pb_len_sz( FD_TXN_META_F_IN_DATA, instr->data_sz               );
  sz += pb_u64_sz( FD_TXN_META_F_IN_STACK_HEIGHT, (ulong)instr->stack_height );
  return sz;
}

static void
enc_inner_instr( pb_wr_t *                   wr,
                 fd_txn_meta_instr_t const * instr ) {
  if( instr->program_id_idx ) pb_u64  ( wr, FD_TXN_META_F_IN_PROGRAM_ID_INDEX, (ulong)instr->program_id_idx );
  if( instr->acct_cnt       ) pb_bytes( wr, FD_TXN_META_F_IN_ACCOUNTS, instr->accts, instr->acct_cnt );
  if( instr->data_sz        ) pb_bytes( wr, FD_TXN_META_F_IN_DATA, instr->data,  instr->data_sz  );
  pb_u64( wr, FD_TXN_META_F_IN_STACK_HEIGHT, (ulong)instr->stack_height );
}

/* solana.storage.ConfirmedBlock.InnerInstructions */

static ulong
enc_inner_sz( fd_txn_meta_inner_t const * inner ) {
  ulong sz = 0UL;
  if( inner->index ) sz += pb_u64_sz( FD_TXN_META_F_II_INDEX, (ulong)inner->index );
  for( ulong i=0UL; i<inner->instr_cnt; i++ ) sz += pb_len_sz( FD_TXN_META_F_II_INSTRUCTIONS, enc_inner_instr_sz( inner->instr+i ) );
  return sz;
}

static void
enc_inner( pb_wr_t *                   wr,
           fd_txn_meta_inner_t const * inner ) {
  if( inner->index ) pb_u64( wr, FD_TXN_META_F_II_INDEX, (ulong)inner->index );
  for( ulong i=0UL; i<inner->instr_cnt; i++ ) {
    pb_sub( wr, FD_TXN_META_F_II_INSTRUCTIONS, enc_inner_instr_sz( inner->instr+i ) );
    enc_inner_instr( wr, inner->instr+i );
  }
}

/* solana.storage.ConfirmedBlock.ReturnData */

static ulong
enc_return_data_sz( fd_txn_meta_t const * meta ) {
  return pb_len_sz( FD_TXN_META_F_RD_PROGRAM_ID, 32UL ) + pb_len_sz( FD_TXN_META_F_RD_DATA, meta->return_data_sz );
}

static void
enc_return_data( pb_wr_t *             wr,
                 fd_txn_meta_t const * meta ) {
  pb_bytes( wr, FD_TXN_META_F_RD_PROGRAM_ID, meta->return_data_program_id, 32UL );
  pb_bytes( wr, FD_TXN_META_F_RD_DATA, meta->return_data, meta->return_data_sz );
}

/* A repeated uint64 field of a proto3 message is packed: one length
   delimited field holding the varints. */

static ulong
enc_balances_body_sz( ulong const * v,
                      ulong         cnt ) {
  ulong sz = 0UL;
  for( ulong i=0UL; i<cnt; i++ ) sz += pb_varint_sz( v[ i ] );
  return sz;
}

static void
enc_balances( pb_wr_t *     wr,
              uint          field,
              ulong const * v,
              ulong         cnt ) {
  if( FD_UNLIKELY( !cnt ) ) return;
  pb_sub( wr, field, enc_balances_body_sz( v, cnt ) );
  for( ulong i=0UL; i<cnt; i++ ) pb_varint( wr, v[ i ] );
}

static ulong
enc_balances_sz( uint          field,
                 ulong const * v,
                 ulong         cnt ) {
  if( FD_UNLIKELY( !cnt ) ) return 0UL;
  return pb_len_sz( field, enc_balances_body_sz( v, cnt ) );
}

/* solana.storage.ConfirmedBlock.TransactionStatusMeta.  The fields go
   out in ascending field number, which is the order prost writes them
   in, so the bytes are the ones a yellowstone server would produce.

   The log messages are copied verbatim: the log collector's buffer is
   already the protobuf encoding of the repeated string field they
   belong to (fd_log_collector.h).

   Token balances and rewards are empty, and an empty repeated field
   occupies no bytes. */

static ulong
enc_meta_sz( fd_txn_meta_t const * meta,
             ulong                 err_sz ) {
  ulong sz = 0UL;

  if( meta->err.kind!=FD_TXN_META_ERR_NONE )
    sz += pb_len_sz( FD_TXN_META_F_META_ERR, err_sz ? pb_len_sz( FD_TXN_META_F_ERR_ERR, err_sz ) : 0UL );
  if( meta->fee ) sz += pb_u64_sz( FD_TXN_META_F_META_FEE, meta->fee );

  sz += enc_balances_sz( FD_TXN_META_F_META_PRE_BALANCES,  meta->pre_balances,  meta->balance_cnt );
  sz += enc_balances_sz( FD_TXN_META_F_META_POST_BALANCES, meta->post_balances, meta->balance_cnt );

  for( ulong i=0UL; i<meta->inner_cnt; i++ )
    sz += pb_len_sz( FD_TXN_META_F_META_INNER_INSTRUCTIONS, enc_inner_sz( meta->inner+i ) );

  sz += meta->logs.buf_sz;

  if( meta->inner_none ) sz += pb_key_sz( FD_TXN_META_F_META_INNER_INSTRUCTIONS_NONE )+1UL;
  if( meta->logs_none  ) sz += pb_key_sz( FD_TXN_META_F_META_LOG_MESSAGES_NONE       )+1UL;

  sz += meta->loaded_writable_cnt*pb_len_sz( FD_TXN_META_F_META_LOADED_WRITABLE, 32UL );
  sz += meta->loaded_readonly_cnt*pb_len_sz( FD_TXN_META_F_META_LOADED_READONLY, 32UL );

  if( !meta->return_data_none ) sz += pb_len_sz( FD_TXN_META_F_META_RETURN_DATA, enc_return_data_sz( meta ) );
  if(  meta->return_data_none ) sz += pb_key_sz( FD_TXN_META_F_META_RETURN_DATA_NONE )+1UL;

  sz += pb_u64_sz( FD_TXN_META_F_META_COMPUTE_UNITS_CONSUMED, meta->compute_units_consumed );
  sz += pb_u64_sz( FD_TXN_META_F_META_COST_UNITS,             meta->cost_units             );
  return sz;
}

static void
enc_meta( pb_wr_t *             wr,
          fd_txn_meta_t const * meta,
          uchar const *         err,
          ulong                 err_sz ) {
  if( meta->err.kind!=FD_TXN_META_ERR_NONE ) {
    pb_sub( wr, FD_TXN_META_F_META_ERR, err_sz ? pb_len_sz( FD_TXN_META_F_ERR_ERR, err_sz ) : 0UL );
    if( FD_LIKELY( err_sz ) ) pb_bytes( wr, FD_TXN_META_F_ERR_ERR, err, err_sz );
  }
  if( meta->fee ) pb_u64( wr, FD_TXN_META_F_META_FEE, meta->fee );

  enc_balances( wr, FD_TXN_META_F_META_PRE_BALANCES,  meta->pre_balances,  meta->balance_cnt );
  enc_balances( wr, FD_TXN_META_F_META_POST_BALANCES, meta->post_balances, meta->balance_cnt );

  for( ulong i=0UL; i<meta->inner_cnt; i++ ) {
    pb_sub( wr, FD_TXN_META_F_META_INNER_INSTRUCTIONS, enc_inner_sz( meta->inner+i ) );
    enc_inner( wr, meta->inner+i );
  }

  pb_raw( wr, meta->logs.buf, meta->logs.buf_sz );

  if( meta->inner_none ) pb_bool( wr, FD_TXN_META_F_META_INNER_INSTRUCTIONS_NONE, 1 );
  if( meta->logs_none  ) pb_bool( wr, FD_TXN_META_F_META_LOG_MESSAGES_NONE,       1 );

  uchar const (* keys)[ 32UL ] = meta->keys;
  for( ulong i=0UL; i<meta->loaded_writable_cnt; i++ )
    pb_bytes( wr, FD_TXN_META_F_META_LOADED_WRITABLE, keys[ meta->static_key_cnt+i ], 32UL );
  for( ulong i=0UL; i<meta->loaded_readonly_cnt; i++ )
    pb_bytes( wr, FD_TXN_META_F_META_LOADED_READONLY, keys[ meta->static_key_cnt+meta->loaded_writable_cnt+i ], 32UL );

  if( !meta->return_data_none ) {
    pb_sub( wr, FD_TXN_META_F_META_RETURN_DATA, enc_return_data_sz( meta ) );
    enc_return_data( wr, meta );
  } else {
    pb_bool( wr, FD_TXN_META_F_META_RETURN_DATA_NONE, 1 );
  }

  pb_u64( wr, FD_TXN_META_F_META_COMPUTE_UNITS_CONSUMED, meta->compute_units_consumed );
  pb_u64( wr, FD_TXN_META_F_META_COST_UNITS,             meta->cost_units             );
}

ulong
fd_txn_meta_encode_meta( fd_txn_meta_t const * meta,
                         uchar *               out,
                         ulong                 out_sz ) {
  uchar err[ FD_TXN_META_ERR_SZ_MAX ];
  ulong err_sz = fd_txn_meta_err_encode( &meta->err, err );

  pb_wr_t wr = { .buf = out, .sz = out_sz };
  enc_meta( &wr, meta, err, err_sz );
  return wr.err ? ULONG_MAX : wr.off;
}

/* Update encoding ****************************************************/

/* geyser.SubscribeUpdateTransactionInfo */

static ulong
enc_txn_info_sz( fd_txn_meta_t const *   meta,
                 txn_v1_config_t const * cfg,
                 ulong                   err_sz ) {
  ulong sz = pb_len_sz( FD_TXN_META_F_INFO_SIGNATURE, 64UL );
  if( meta->is_vote ) sz += pb_key_sz( FD_TXN_META_F_INFO_IS_VOTE )+1UL;
  sz += pb_len_sz( FD_TXN_META_F_INFO_TRANSACTION, enc_transaction_sz( meta, cfg ) );
  sz += pb_len_sz( FD_TXN_META_F_INFO_META,        enc_meta_sz( meta, err_sz ) );
  if( meta->index_in_slot ) sz += pb_u64_sz( FD_TXN_META_F_INFO_INDEX, meta->index_in_slot );
  return sz;
}

static void
enc_txn_info( pb_wr_t *               wr,
              fd_txn_meta_t const *   meta,
              txn_v1_config_t const * cfg,
              uchar const *           err,
              ulong                   err_sz ) {
  pb_bytes( wr, FD_TXN_META_F_INFO_SIGNATURE, meta->signature, 64UL );
  if( meta->is_vote ) pb_bool( wr, FD_TXN_META_F_INFO_IS_VOTE, 1 );

  pb_sub( wr, FD_TXN_META_F_INFO_TRANSACTION, enc_transaction_sz( meta, cfg ) );
  enc_transaction( wr, meta, cfg );

  pb_sub( wr, FD_TXN_META_F_INFO_META, enc_meta_sz( meta, err_sz ) );
  enc_meta( wr, meta, err, err_sz );

  if( meta->index_in_slot ) pb_u64( wr, FD_TXN_META_F_INFO_INDEX, meta->index_in_slot );
}

ulong
fd_txn_meta_encode_txn_info( fd_txn_meta_t const * meta,
                             uchar *               out,
                             ulong                 out_sz ) {
  txn_v1_config_t cfg[1];
  txn_v1_config( cfg, meta );

  uchar err[ FD_TXN_META_ERR_SZ_MAX ];
  ulong err_sz = fd_txn_meta_err_encode( &meta->err, err );

  pb_wr_t wr = { .buf = out, .sz = out_sz };
  enc_txn_info( &wr, meta, cfg, err, err_sz );
  return wr.err ? ULONG_MAX : wr.off;
}

ulong
fd_txn_meta_encode_txn_update( fd_txn_meta_t const * meta,
                               uchar *               out,
                               ulong                 out_sz ) {
  txn_v1_config_t cfg[1];
  txn_v1_config( cfg, meta );

  uchar err[ FD_TXN_META_ERR_SZ_MAX ];
  ulong err_sz = fd_txn_meta_err_encode( &meta->err, err );

  pb_wr_t wr = { .buf = out, .sz = out_sz };

  pb_sub( &wr, FD_TXN_META_F_UPDATE_TRANSACTION, enc_txn_info_sz( meta, cfg, err_sz ) );
  enc_txn_info( &wr, meta, cfg, err, err_sz );

  if( meta->slot    ) pb_u64( &wr, FD_TXN_META_F_UPDATE_SLOT,    meta->slot    );
  if( meta->bank_id ) pb_u64( &wr, FD_TXN_META_F_UPDATE_BANK_ID, meta->bank_id );

  return wr.err ? ULONG_MAX : wr.off;
}

ulong
fd_txn_meta_encode_txn_status( fd_txn_meta_t const * meta,
                               uchar *               out,
                               ulong                 out_sz ) {
  uchar err[ FD_TXN_META_ERR_SZ_MAX ];
  ulong err_sz = fd_txn_meta_err_encode( &meta->err, err );

  pb_wr_t wr = { .buf = out, .sz = out_sz };

  if( meta->slot ) pb_u64( &wr, FD_TXN_META_F_STATUS_SLOT, meta->slot );

  pb_bytes( &wr, FD_TXN_META_F_STATUS_SIGNATURE, meta->signature, 64UL );

  if( meta->is_vote       ) pb_bool ( &wr, FD_TXN_META_F_STATUS_IS_VOTE, 1 );
  if( meta->index_in_slot ) pb_u64  ( &wr, FD_TXN_META_F_STATUS_INDEX, meta->index_in_slot );
  if( meta->err.kind!=FD_TXN_META_ERR_NONE ) {
    pb_sub( &wr, FD_TXN_META_F_STATUS_ERR, err_sz ? pb_len_sz( FD_TXN_META_F_ERR_ERR, err_sz ) : 0UL );
    if( FD_LIKELY( err_sz ) ) pb_bytes( &wr, FD_TXN_META_F_ERR_ERR, err, err_sz );
  }
  if( meta->bank_id       ) pb_u64  ( &wr, FD_TXN_META_F_STATUS_BANK_ID, meta->bank_id );

  return wr.err ? ULONG_MAX : wr.off;
}
