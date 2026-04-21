#include "fd_sysvar_slot_history.h"
#include "fd_sysvar.h"
#include "../fd_system_ids.h"
#include "../fd_accdb_svm.h"

#define FD_SLOT_HISTORY_BITS_PER_BLOCK (8UL * sizeof(ulong))

#define FD_SLOT_HISTORY_BLOCKS_LEN (FD_SLOT_HISTORY_MAX_ENTRIES / FD_SLOT_HISTORY_BITS_PER_BLOCK)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/slot_history.rs#L16 */

void
fd_sysvar_slot_history_init( fd_bank_t *        bank,
                             fd_accdb_t *       accdb,
                             fd_capture_ctx_t * capture_ctx ) {
  uchar data[ FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ ];
  uchar * p = data;

  /* has_bits */
  *p = 1;
  p++;

  /* bits_bitvec_len */
  FD_STORE( ulong, p, FD_SLOT_HISTORY_BLOCKS_LEN );
  p += sizeof(ulong);

  /* content */
  fd_memset( p, 0, FD_SLOT_HISTORY_BLOCKS_LEN * sizeof(ulong) );
  p += FD_SLOT_HISTORY_BLOCKS_LEN * sizeof(ulong);

  /* bits_len */
  FD_STORE( ulong, p, FD_SLOT_HISTORY_MAX_ENTRIES );
  p += sizeof(ulong);

  /* next_slot */
  FD_STORE( ulong, p, bank->f.slot + 1UL );
  p += sizeof(ulong);

  FD_STATIC_ASSERT( FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ == 1 + sizeof(ulong) + FD_SLOT_HISTORY_BLOCKS_LEN * sizeof(ulong) + sizeof(ulong) + sizeof(ulong), "bin code size mismatch" );

  fd_sysvar_account_update( bank, accdb, capture_ctx, &fd_sysvar_slot_history_id, data, FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ );
}

void
fd_sysvar_slot_history_update( fd_bank_t *        bank,
                               fd_accdb_t *       accdb,
                               fd_capture_ctx_t * capture_ctx ) {
  fd_accdb_svm_update_t update[1];
  fd_accdb_entry_t entry = fd_accdb_svm_open_rw( bank, accdb, update, &fd_sysvar_slot_history_id, 0 );
  FD_TEST( entry.lamports ); /* Slot history account must exist */
  FD_TEST( !memcmp( entry.owner, fd_sysvar_owner_id.uc, sizeof(fd_pubkey_t) ) ); /* Slot history account must be owned by sysvar owner */

  if( FD_UNLIKELY( entry.data[ 0 ]!=1 ) ) {
    /* initialize if !has_bits */
    if( FD_UNLIKELY( entry.data_len<FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ ) ) FD_LOG_HEXDUMP_ERR(( "invalid slot history sysvar (data_sz too small)", entry.data, entry.data_len ));
    entry.data[ 0 ] = 1;
    FD_STORE( ulong, entry.data+1, FD_SLOT_HISTORY_BLOCKS_LEN );
    fd_memset( entry.data+9, 0, FD_SLOT_HISTORY_BLOCKS_LEN * sizeof(ulong) );
    FD_STORE( ulong, entry.data+9+FD_SLOT_HISTORY_BLOCKS_LEN*sizeof(ulong), FD_SLOT_HISTORY_MAX_ENTRIES );
    FD_STORE( ulong, entry.data+9+FD_SLOT_HISTORY_BLOCKS_LEN*sizeof(ulong)+8UL, 0UL );
  }

  ulong bits_bitvec_len = FD_LOAD( ulong, entry.data+1UL );
  if( FD_UNLIKELY( !bits_bitvec_len ) ) {
    fd_accdb_svm_close_rw( bank, accdb, capture_ctx, &entry, update );
    return;
  }

  ulong min_sz = 25UL + bits_bitvec_len*sizeof(ulong);
  if( FD_UNLIKELY( entry.data_len<min_sz ) ) FD_LOG_ERR(( "invalid slot history sysvar: data_sz too small (%lu, required %lu)", entry.data_len, min_sz ));

  uchar * bits      = entry.data + 9UL;
  uchar * footer    = entry.data + 9UL + bits_bitvec_len * sizeof(ulong);
  ulong   next_slot = FD_LOAD( ulong, footer+8UL );

  /* https://github.com/anza-xyz/solana-sdk/blob/slot-history%40v2.2.1/slot-history/src/lib.rs#L62-L74 */
  ulong cur_slot = bank->f.slot;
  if( FD_UNLIKELY( cur_slot>next_slot && cur_slot-next_slot>=FD_SLOT_HISTORY_MAX_ENTRIES ) ) {
    fd_memset( bits, 0, bits_bitvec_len * sizeof(ulong) );
  } else {
    for( ulong i=next_slot; i<cur_slot; i++ ) {
      ulong   block_idx = (i / FD_SLOT_HISTORY_BITS_PER_BLOCK) % bits_bitvec_len;
      uchar * word      = &bits[ block_idx*sizeof(ulong) ];
      FD_STORE( ulong, word, FD_LOAD( ulong, word ) & (~(1UL << (i % FD_SLOT_HISTORY_BITS_PER_BLOCK))) );
    }
  }

  /* new slot */
  ulong   block_idx = (cur_slot / FD_SLOT_HISTORY_BITS_PER_BLOCK) % bits_bitvec_len;
  uchar * word      = &bits[ block_idx*sizeof(ulong) ];
  FD_STORE( ulong, word, FD_LOAD( ulong, word ) | (1UL << (cur_slot % FD_SLOT_HISTORY_BITS_PER_BLOCK)) );

  FD_STORE( ulong, footer+8UL, cur_slot+1UL );

  fd_accdb_svm_close_rw( bank, accdb, capture_ctx, &entry, update );
}

int
fd_sysvar_slot_history_validate( uchar const * data,
                                 ulong         sz ) {
  if( FD_UNLIKELY( sz < 17UL ) ) return 0;
  uchar has_bits = data[0];
  if( FD_UNLIKELY( has_bits>1 ) ) return 0;
  if( !has_bits ) return 1;
  if( FD_UNLIKELY( sz < 25UL ) ) return 0;
  ulong blocks_len = FD_LOAD( ulong, data+1 );
  ulong min_sz;
  if( FD_UNLIKELY( __builtin_umull_overflow( blocks_len, sizeof(ulong), &min_sz ) ) ) return 0;
  if( FD_UNLIKELY( __builtin_uaddl_overflow( min_sz, 25UL, &min_sz ) ) ) return 0;
  if( FD_UNLIKELY( sz < min_sz ) ) return 0;
  return 1;
}

fd_slot_history_view_t *
fd_sysvar_slot_history_view( fd_slot_history_view_t * view,
                             uchar const *            data,
                             ulong                    sz ) {
  if( FD_UNLIKELY( !fd_sysvar_slot_history_validate( data, sz ) ) ) return NULL;
  if( FD_UNLIKELY( !data[0] ) ) {
    view->bits       = NULL;
    view->blocks_len = 0UL;
    view->bits_len   = FD_LOAD( ulong, data+1    );
    view->next_slot  = FD_LOAD( ulong, data+1+8UL );
    return view;
  }
  ulong blocks_len = FD_LOAD( ulong, data+1 );
  uchar const * footer = data + 9UL + blocks_len * sizeof(ulong);
  view->bits       = data + 9UL;
  view->blocks_len = blocks_len;
  view->bits_len   = FD_LOAD( ulong, footer    );
  view->next_slot  = FD_LOAD( ulong, footer+8UL );
  return view;
}

int
fd_sysvar_slot_history_find_slot( fd_slot_history_view_t const * view,
                                  ulong                          slot ) {
  if( FD_UNLIKELY( !view->blocks_len ) ) return FD_SLOT_HISTORY_SLOT_NOT_FOUND;
  if( slot > view->next_slot - 1UL ) {
    return FD_SLOT_HISTORY_SLOT_FUTURE;
  }
  if( slot < fd_ulong_sat_sub( view->next_slot, FD_SLOT_HISTORY_MAX_ENTRIES ) ) {
    return FD_SLOT_HISTORY_SLOT_TOO_OLD;
  }
  ulong block_idx = (slot / FD_SLOT_HISTORY_BITS_PER_BLOCK) % view->blocks_len;
  ulong word      = FD_LOAD( ulong, view->bits + block_idx*sizeof(ulong) );
  if( word & (1UL << (slot % FD_SLOT_HISTORY_BITS_PER_BLOCK)) ) {
    return FD_SLOT_HISTORY_SLOT_FOUND;
  }
  return FD_SLOT_HISTORY_SLOT_NOT_FOUND;
}
