#include "fd_accdb_fsck.h"
#include "../../funk/fd_funk.h"
#include "../../flamenco/fd_flamenco_base.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/lthash/fd_lthash_adder.h"

static void
process_rec( fd_funk_t *           funk,
             fd_funk_rec_t const * rec,
             fd_lthash_adder_t *   adder,
             fd_lthash_value_t *   sum ) {
  if( FD_UNLIKELY( !fd_funk_txn_xid_eq_root( rec->pair.xid ) ) ) return;
  fd_account_meta_t const * meta = fd_funk_val_const( rec, funk->wksp );
  if( FD_UNLIKELY( !meta ) ) return;
  void const * data       = (void const *)( meta+1 );
  ulong        data_sz    = meta->dlen;
  void const * pubkey     = rec->pair.key->uc;
  ulong        lamports   = meta->lamports;
  _Bool        executable = !!meta->executable;
  void const * owner      = meta->owner;
  if( FD_LIKELY( lamports ) ) {
    fd_lthash_adder_push_solana_account( adder, sum, pubkey, data, data_sz, lamports, executable, owner );
  }
}

static void
process_chain( fd_funk_t *         funk,
               ulong               chain_idx,
               fd_lthash_adder_t * adder,
               fd_lthash_value_t * sum ) {
  fd_funk_rec_map_t * rec_map = fd_funk_rec_map( funk );
  for(
      fd_funk_rec_map_iter_t iter = fd_funk_rec_map_iter( rec_map, chain_idx );
      !fd_funk_rec_map_iter_done( iter );
      iter = fd_funk_rec_map_iter_next( iter )
  ) {
    fd_funk_rec_t const * rec = fd_funk_rec_map_iter_ele_const( iter );
    process_rec( funk, rec, adder, sum );
  }
}

uint
fd_accdb_fsck_funk( fd_funk_t * funk ) {

  FD_LOG_NOTICE(( "FSCK starting integrity checks ..." ));
  long dt = -fd_log_wallclock();
  int funk_err = fd_funk_verify( funk );
  dt += fd_log_wallclock();
  if( FD_UNLIKELY( funk_err ) ) {
    FD_LOG_WARNING(( "FSCK: detected database integrity errors (took %g seconds)", (double)dt/1e9 ));
  } else {
    FD_LOG_NOTICE(( "FSCK: funk integrity OK (took %g seconds)", (double)dt/1e9 ));
  }

  FD_LOG_NOTICE(( "FSCK computing lthash ..." ));
  fd_lthash_adder_t adder_[1];
  fd_lthash_adder_t * adder = fd_lthash_adder_new( adder_ );
  FD_TEST( adder );
  fd_lthash_value_t sum[1]; fd_lthash_zero( sum );
  dt = -fd_log_wallclock();

  fd_funk_rec_map_t * rec_map = fd_funk_rec_map( funk );
  ulong chain_cnt = fd_funk_rec_map_chain_cnt( rec_map );
  for( ulong i=0UL; i<chain_cnt; i++ ) process_chain( funk, i, adder, sum );

  dt += fd_log_wallclock();
  fd_lthash_adder_flush( adder, sum );
  uchar hash32[32]; fd_blake3_hash( sum->bytes, FD_LTHASH_LEN_BYTES, hash32 );
  FD_BASE58_ENCODE_32_BYTES( sum->bytes, sum_enc    );
  FD_BASE58_ENCODE_32_BYTES( hash32,     hash32_enc );
  FD_LOG_NOTICE(( "FSCK: lthash[..32]=%s blake3(lthash)=%s", sum_enc, hash32_enc ));

  return funk_err==FD_FUNK_SUCCESS ? FD_ACCDB_FSCK_NO_ERROR : FD_ACCDB_FSCK_CORRUPT;
}
