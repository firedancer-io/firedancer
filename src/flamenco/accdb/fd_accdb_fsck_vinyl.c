#include "fd_accdb_fsck.h"
#include "../runtime/fd_runtime_const.h"
#include "../../ballet/lthash/fd_lthash_adder.h"

#define VINYL_KEY_FMT             "%016lx%016lx%016lx%016lx"
#define VINYL_KEY_FMT_ARGS( key ) fd_ulong_bswap( (key).ul[0] ), fd_ulong_bswap( (key).ul[1] ), fd_ulong_bswap( (key).ul[2] ), fd_ulong_bswap( (key).ul[3] )

/* meta_query_fast is a simplified version of fd_vinyl_meta_prepare */

static fd_vinyl_meta_ele_t *
meta_query_fast( fd_vinyl_meta_t *      join,
                 fd_vinyl_key_t const * key,
                 ulong                  memo ) {
  fd_vinyl_meta_ele_t * ele0      = join->ele;
  ulong                 ele_max   = join->ele_max;
  ulong                 probe_max = join->probe_max;
  void *                ctx       = join->ctx;

  ulong start_idx = memo & (ele_max-1UL);

  for(;;) {
    ulong ele_idx = start_idx;
    for( ulong probe_rem=probe_max; probe_rem; probe_rem-- ) {
      fd_vinyl_meta_ele_t * ele = ele0 + ele_idx;
      if( fd_vinyl_meta_private_ele_is_free( ctx, ele ) ) return NULL;
      if( fd_vinyl_key_eq( &ele->phdr.key, key ) ) {
        if( FD_UNLIKELY( ele->memo != memo ) ) FD_LOG_ERR(( "memo mismatch" ));
        return ele;
      }
      ele_idx = (ele_idx+1UL) & (ele_max-1UL);
    }
    return NULL;
  }
  __builtin_unreachable();
}

uint
fd_accdb_fsck_vinyl( fd_vinyl_io_t *   io,
                     fd_vinyl_meta_t * meta ) {
  uint        err     = FD_ACCDB_FSCK_NO_ERROR;
  ulong       err_cnt =   0UL;
  ulong const err_max = 512UL;

  /* Join memory-mapped bstream */

  ulong         const io_seed     = fd_vinyl_io_seed( io );
  uchar const * const mmio        = fd_vinyl_mmio   ( io );
  ulong         const mmio_sz     = fd_vinyl_mmio_sz( io );
  ulong         const seq_past    = io->seq_past;
  ulong         const seq_present = io->seq_present;
  ulong         const dev_sz      = mmio_sz;
  FD_LOG_INFO(( "FSCK starting ... seq_past=%lu seq_present=%lu mmio_sz=%lu",
                seq_past, seq_present, mmio_sz ));
  /* FIXME ASSUMING dev_sz==mmio_sz IS NOT VAILD ACCORDING TO DOCS */

  if( FD_UNLIKELY( !fd_ulong_is_aligned( seq_past, FD_VINYL_BSTREAM_BLOCK_SZ ) ) ) {
    FD_LOG_WARNING(( "misaligned seq_past (%lu)", seq_past ));
    return FD_ACCDB_FSCK_INVARIANT;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( seq_present, FD_VINYL_BSTREAM_BLOCK_SZ ) ) ) {
    FD_LOG_WARNING(( "misaligned seq_present (%lu)", seq_present ));
    return FD_ACCDB_FSCK_INVARIANT;
  }
  ulong dseq = seq_present - seq_past;
  if( FD_UNLIKELY( fd_vinyl_seq_gt( seq_past, seq_present ) || dseq>mmio_sz ) ) {
    FD_LOG_WARNING(( "invalid seq range [%lu,%lu) for mmio_sz %lu", seq_past, seq_present, mmio_sz ));
    return FD_ACCDB_FSCK_INVARIANT;
  }

  /* Phase 1: Scan meta map left-to-right.  Verify the following:
     - memo (key hash correct?)
     - ctl (obviously incorrect meta entry?)
     - probe_max (key outside of probe range?)
     - query (is this key visible to queries? detect duplicate)
     Mark each element as not-visited. */

  ulong                 const meta_seed   = meta->seed;
  fd_vinyl_meta_ele_t * const ele0        = meta->ele;
  ulong                 const ele_max     = meta->ele_max;

  for( ulong i=0UL; i<ele_max; i++ ) {
    fd_vinyl_meta_ele_t * ele = &ele0[ i ];
    if( FD_LIKELY( fd_vinyl_meta_private_ele_is_free( meta->ctx, ele ) ) ) continue;

    ulong memo    = fd_vinyl_key_memo( meta_seed, &ele->phdr.key );
    ulong val_esz = fd_vinyl_bstream_ctl_sz( ele->phdr.ctl );

    int bad_ctl   = fd_vinyl_bstream_ctl_type ( ele->phdr.ctl )!=FD_VINYL_BSTREAM_CTL_TYPE_PAIR;
    int bad_style = fd_vinyl_bstream_ctl_style( ele->phdr.ctl )!=FD_VINYL_BSTREAM_CTL_STYLE_RAW;
    int bad_memo  = memo != ele->memo;
    int bad_query = meta_query_fast( meta, &ele->phdr.key, ele->memo )!=ele;
    int bad_sz    = val_esz > sizeof(fd_account_meta_t)+FD_RUNTIME_ACC_SZ_MAX;
    int bad_seq0  = fd_vinyl_seq_lt( ele->seq, seq_past ) | fd_vinyl_seq_ge( ele->seq, seq_present );
    int bad_seq1  = fd_vinyl_seq_gt( ele->seq+fd_vinyl_bstream_pair_sz( val_esz ), seq_present );

    if( FD_UNLIKELY( bad_ctl | bad_style | bad_memo | bad_query | bad_sz | bad_seq0 | bad_seq1 ) ) {
      FD_LOG_WARNING(( "fd_accdb_fsck_vinyl: index corruption detected key=" VINYL_KEY_FMT " memo=%016lx meta_idx=%lu seq=%lu err=%s",
                       VINYL_KEY_FMT_ARGS( ele->phdr.key ),
                       memo,
                       i,
                       ele->seq,
                       bad_ctl   ? "bad ctl"   :
                       bad_style ? "bad style" :
                       bad_memo  ? "bad memo"  :
                       bad_query ? "bad query" :
                       bad_sz    ? "bad sz"    :
                       bad_seq0  ? "bad seq0"  :
                                   "bad seq1" ));
      if( FD_UNLIKELY( ++err_cnt>=err_max ) ) {
        FD_LOG_WARNING(( "fd_accdb_fsck_vinyl: too many errors, stopping" ));
        return FD_ACCDB_FSCK_UNKNOWN;
      }
    }

    ele->line_idx = ULONG_MAX; /* mark not visited */
  }

  if( !err_cnt ) FD_LOG_INFO(( "FSCK: meta OK" ));

  /* Phase 2: Scan bstream past-to-present.  Mark meta elements as
     visited along the way.  Verify that:
     - meta entries match bstream blocks
     - bstream block checksums are valid */

  fd_lthash_adder_t adder_[1];
  fd_lthash_adder_t * adder = fd_lthash_adder_new( adder_ );
  FD_TEST( adder );
  fd_lthash_value_t sum[1]; fd_lthash_zero( sum );

  ulong seq        = seq_past;
  ulong seq_report = seq;
  while( seq<seq_present ) {
    if( FD_UNLIKELY( seq>=seq_report+(1UL<<30) ) ) {
      FD_LOG_INFO(( "FSCK progress: seq=%lu", seq ));
      seq_report = seq;
    }

    /* Map block to device */
    ulong mm_off  = seq % dev_sz;
    ulong dev_off = mm_off+FD_VINYL_BSTREAM_BLOCK_SZ;
    if( FD_UNLIKELY( mm_off+FD_VINYL_BSTREAM_BLOCK_SZ > mmio_sz ) ) {
      FD_LOG_WARNING(( "fd_accdb_fsck_vinyl: bstream block crosses mmio boundary: seq=%lu dev_off=%lu", seq, dev_off ));
      return FD_ACCDB_FSCK_CORRUPT;
    }

    /* Interpret block */
    fd_vinyl_bstream_block_t block = FD_LOAD( fd_vinyl_bstream_block_t, mmio+mm_off );
    int ctl_type = fd_vinyl_bstream_ctl_type( block.ctl );
    switch( ctl_type ) {

    case FD_VINYL_BSTREAM_CTL_TYPE_PAIR: {
      ulong val_esz  = fd_vinyl_bstream_ctl_sz( block.ctl );
      ulong block_sz = fd_vinyl_bstream_pair_sz( val_esz );
      if( FD_UNLIKELY( block_sz<FD_VINYL_BSTREAM_BLOCK_SZ ) ) {
        FD_LOG_WARNING(( "fd_accdb_fsck_vinyl: bstream pair has invalid block size (%lu) at seq=%lu dev_off=%lu", block_sz, seq, dev_off ));
        err_cnt++;
        err = fd_uint_max( err, FD_ACCDB_FSCK_INVARIANT );
        seq += FD_VINYL_BSTREAM_BLOCK_SZ;
        break;
      }
      ulong seq1     = seq + block_sz;
      ulong dev_off1 = seq1 % dev_sz;

      if( FD_UNLIKELY( val_esz>sizeof(fd_account_meta_t)+FD_RUNTIME_ACC_SZ_MAX ) ) {
        FD_LOG_WARNING(( "fd_accdb_fsck_vinyl: bstream pair has invalid record size (%lu) at seq=%lu dev_off=%lu", val_esz, seq, dev_off ));
        err_cnt++;
        err = fd_uint_max( err, FD_ACCDB_FSCK_INVARIANT );
        goto next;
      }
      if( FD_UNLIKELY( mm_off>=dev_off1 ) ) {
        FD_LOG_WARNING(( "fd_accdb_fsck_vinyl: bstream pair is fragmented around bstream boundary: seq=%lu dev_off=%lu", seq, dev_off ));
        err_cnt++;
        err = fd_uint_max( err, FD_ACCDB_FSCK_INVARIANT );
        goto next;
      }

      char const * errstr = fd_vinyl_bstream_pair_test( io_seed, seq, (void *)( mmio+mm_off ), block_sz );
      if( FD_UNLIKELY( errstr ) ) {
        FD_LOG_WARNING(( "fd_accdb_fsck_vinyl: invalid pair block (%s): key=" VINYL_KEY_FMT " seq=%lu dev_off=%lu", errstr, VINYL_KEY_FMT_ARGS( block.phdr.key ), seq, dev_off ));
        err_cnt++;
        err = fd_uint_max( err, FD_ACCDB_FSCK_CORRUPT );
        goto next;
      }

      ulong memo = fd_vinyl_key_memo( meta_seed, &block.phdr.key );
      fd_vinyl_meta_ele_t * ele = meta_query_fast( meta, &block.phdr.key, memo );
      if( FD_UNLIKELY( !ele ) ) {
        FD_LOG_WARNING(( "fd_accdb_fsck_vinyl: bstream pair has no matching meta entry: key=" VINYL_KEY_FMT " memo=%016lx seq=%lu dev_off=%lu",
                         VINYL_KEY_FMT_ARGS( block.phdr.key ), memo, seq, dev_off ));
        err_cnt++;
        err = fd_uint_max( err, FD_ACCDB_FSCK_INVARIANT );
        goto next;
      }
      if( FD_UNLIKELY( ele->seq < seq ) ) {
        FD_LOG_WARNING(( "fd_accdb_fsck_vinyl: meta entry points to older bstream seq: key=" VINYL_KEY_FMT " memo=%016lx meta_seq=%lu bstream_seq=%lu dev_off=%lu",
                         VINYL_KEY_FMT_ARGS( block.phdr.key ), memo, ele->seq, seq, dev_off ));
        err_cnt++;
        err = fd_uint_max( err, FD_ACCDB_FSCK_INVARIANT );
        goto next;
      }
      if( FD_UNLIKELY( ele->seq > seq ) ) goto next;  /* ignore, assume bstream entry is stale */

      /* Mark as visited */
      if( FD_UNLIKELY( ele->line_idx==0UL ) ) {
        FD_LOG_WARNING(( "fd_accdb_fsck_vinyl: duplicate bstream entry detected: key=" VINYL_KEY_FMT " memo=%016lx seq=%lu dev_off=%lu",
                         VINYL_KEY_FMT_ARGS( block.phdr.key ), memo, seq, dev_off ));
        err_cnt++;
        err = fd_uint_max( err, FD_ACCDB_FSCK_CORRUPT );
        goto next;
      }
      ele->line_idx = 0UL;

      int phdr_ok = fd_memeq( &ele->phdr, &block.phdr, sizeof(fd_vinyl_bstream_phdr_t) );
      if( FD_UNLIKELY( !phdr_ok ) ) {
        FD_LOG_WARNING(( "fd_accdb_fsck_vinyl: bstream pair header mismatch at seq=%lu dev_off=%lu", seq, dev_off ));
        err_cnt++;
        err = fd_uint_max( err, FD_ACCDB_FSCK_CORRUPT );
      }

      /* At this point, found the latest revision of an account for the
         first time */
      fd_account_meta_t const * meta       = fd_type_pun_const( mmio+mm_off+sizeof(fd_vinyl_bstream_phdr_t) );
      void const *              data       = (void const *)( meta+1 );
      void const *              pubkey     = &ele->phdr.key.uc;
      ulong                     data_sz    = meta->dlen;
      ulong                     lamports   = meta->lamports;
      _Bool                     executable = !!meta->executable;
      void const *              owner      = meta->owner;
      if( FD_LIKELY( lamports ) ) {
        fd_lthash_adder_push_solana_account( adder, sum, pubkey, data, data_sz, lamports, executable, owner );
      }

next:
      seq = seq1;
      break;
    }

    case FD_VINYL_BSTREAM_CTL_TYPE_ZPAD: {
      char const * errstr = fd_vinyl_bstream_zpad_test( io_seed, seq, &block );
      if( FD_UNLIKELY( errstr ) ) {
        FD_LOG_WARNING(( "fd_accdb_fsck_vinyl: invalid zpad block (%s): seq=%lu dev_off=%lu", errstr, seq, dev_off ) );
        err_cnt++;
        err = fd_uint_max( err, FD_ACCDB_FSCK_INVARIANT );
      }
      seq += FD_VINYL_BSTREAM_BLOCK_SZ;
      break;
    }

    default:
      FD_LOG_WARNING(( "fd_accdb_fsck_vinyl: unexpected block type %i at seq=%lu dev_off=%lu", ctl_type, seq, dev_off ));
      err_cnt++;
      return FD_ACCDB_FSCK_INVARIANT;

    }

    if( FD_UNLIKELY( err_cnt>=err_max ) ) {
      FD_LOG_WARNING(( "fd_accdb_fsck_vinyl: too many errors, stopping" ));
      return FD_ACCDB_FSCK_UNKNOWN;
    }
  }

  if( FD_UNLIKELY( seq!=seq_present ) ) {
    FD_LOG_WARNING(( "fd_accdb_fsck_vinyl: bstream scan ended abruptly at seq=%lu (expected %lu)", seq, seq_present ));
    return FD_ACCDB_FSCK_CORRUPT;
  }

  fd_lthash_adder_flush( adder, sum );
  uchar hash32[32]; fd_blake3_hash( sum->bytes, FD_LTHASH_LEN_BYTES, hash32 );
  FD_BASE58_ENCODE_32_BYTES( sum->bytes, sum_enc    );
  FD_BASE58_ENCODE_32_BYTES( hash32,     hash32_enc );
  FD_LOG_NOTICE(( "FSCK: lthash[..32]=%s blake3(lthash)=%s", sum_enc, hash32_enc ));

  if( !err_cnt ) FD_LOG_INFO(( "FSCK: bstream OK" ));

  /* Phase 3: Scan meta map left-to-right.  Verify that all elements
     were visited. */

  for( ulong i=0UL; i<ele_max; i++ ) {
    fd_vinyl_meta_ele_t * ele = &ele0[ i ];
    if( FD_LIKELY( fd_vinyl_meta_private_ele_is_free( meta->ctx, ele ) ) ) continue;
    if( FD_UNLIKELY( ele->line_idx==ULONG_MAX ) ) {
      FD_LOG_WARNING(( "fd_accdb_fsck_vinyl: unvisited meta entry detected"
                       " key=%016lx:%016lx:%016lx:%016lx"
                       " memo=%016lx"
                       " meta_idx=%lu"
                       " seq=%lu",
                       fd_ulong_bswap( ele->phdr.key.ul[0] ), fd_ulong_bswap( ele->phdr.key.ul[1] ),
                       fd_ulong_bswap( ele->phdr.key.ul[2] ), fd_ulong_bswap( ele->phdr.key.ul[3] ),
                       ele->memo, i, ele->seq ));
      if( FD_UNLIKELY( ++err_cnt>=err_max ) ) {
        FD_LOG_WARNING(( "fd_accdb_fsck_vinyl: too many errors, stopping" ));
        return FD_ACCDB_FSCK_UNKNOWN;
      }
      err = fd_uint_max( err, FD_ACCDB_FSCK_CORRUPT );
    } else {
      ele->line_idx = ULONG_MAX; /* reset mark */
    }
  }

  if( !err_cnt ) FD_LOG_INFO(( "FSCK: meta-bstream sync OK" ));

  return err;
}
