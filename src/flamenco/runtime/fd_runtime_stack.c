#include "fd_runtime_stack_tmpl.h"

#include <errno.h>
#include <unistd.h>

/* Spill table layout in stake_accum_fd: bucket_cnt {gen,idx} buckets
   (linear probing, load <=2/3, gen!=current means empty so a reset is
   a gen bump) followed by dense fd_stake_accum_t records.  The file is
   sparse; short reads zero-fill. */

struct stake_accum_bucket {
  uint gen;
  uint idx;
};
typedef struct stake_accum_bucket stake_accum_bucket_t;

static void
spill_read( fd_runtime_stack_t const * runtime_stack,
            void *                     dst,
            ulong                      off,
            ulong                      sz ) {
  int   fd  = runtime_stack->stakes.stake_accum_fd;
  ulong got = 0UL;
  while( got<sz ) {
    long n = pread( fd, (uchar *)dst+got, sz-got, (long)(off+got) );
    if( FD_UNLIKELY( n<0L ) ) {
      if( FD_LIKELY( errno==EINTR ) ) continue;
      FD_LOG_CRIT(( "pread(stake accum spill file, fd=%d) failed (%i-%s)", fd, errno, fd_io_strerror( errno ) ));
    }
    if( FD_UNLIKELY( !n ) ) break;
    got += (ulong)n;
  }
  if( FD_UNLIKELY( got<sz ) ) fd_memset( (uchar *)dst+got, 0, sz-got );
}

static void
spill_write( fd_runtime_stack_t const * runtime_stack,
             void const *               src,
             ulong                      off,
             ulong                      sz ) {
  int   fd  = runtime_stack->stakes.stake_accum_fd;
  ulong put = 0UL;
  while( put<sz ) {
    long n = pwrite( fd, (uchar const *)src+put, sz-put, (long)(off+put) );
    if( FD_LIKELY( n>0L ) ) { put += (ulong)n; continue; }
    if( FD_UNLIKELY( n<0L && errno==EINTR ) ) continue;
    if( FD_UNLIKELY( !n ) ) errno = EIO;
    FD_LOG_CRIT(( "pwrite(stake accum spill file, fd=%d) failed (%i-%s)", fd, errno, fd_io_strerror( errno ) ));
  }
}

static inline ulong
spill_rec_off( fd_runtime_stack_t const * runtime_stack,
               ulong                      idx ) {
  return runtime_stack->stakes.stake_accum_spill_bucket_cnt*sizeof(stake_accum_bucket_t) + idx*sizeof(fd_stake_accum_t);
}

/* Probes for key.  Returns 1 with *rec filled if found, else 0 with
   *bucket_idx at the empty bucket ending the probe. */

static int
spill_probe( fd_runtime_stack_t const * runtime_stack,
             fd_pubkey_t const *        key,
             fd_stake_accum_t *         rec,
             ulong *                    bucket_idx ) {
  ulong mask = runtime_stack->stakes.stake_accum_spill_bucket_cnt-1UL;
  ulong seed = fd_stake_accum_map_seed( runtime_stack->stakes.stake_accum_map );
  ulong b    = fd_ulong_hash( seed^FD_LOAD( ulong, key->uc+24UL ) ) & mask;
  for(;;) {
    stake_accum_bucket_t bucket;
    spill_read( runtime_stack, &bucket, b*sizeof(stake_accum_bucket_t), sizeof(bucket) );
    *bucket_idx = b;
    if( bucket.gen!=runtime_stack->stakes.stake_accum_spill_gen ) return 0;
    FD_TEST( (ulong)bucket.idx<runtime_stack->stakes.stake_accum_spill_cnt );
    spill_read( runtime_stack, rec, spill_rec_off( runtime_stack, bucket.idx ), sizeof(fd_stake_accum_t) );
    if( fd_pubkey_eq( &rec->pubkey, key ) ) {
      rec->next = bucket.idx;
      return 1;
    }
    b = (b+1UL) & mask;
  }
}

fd_stake_accum_t *
fd_runtime_stack_stake_accum_spill_query( fd_runtime_stack_t * runtime_stack,
                                          fd_pubkey_t const *  key,
                                          fd_stake_accum_t *   scratch ) {
  ulong b;
  return spill_probe( runtime_stack, key, scratch, &b ) ? scratch : NULL;
}

void
fd_runtime_stack_stake_accum_spill_add( fd_runtime_stack_t * runtime_stack,
                                        fd_pubkey_t const *  key,
                                        ulong                stake,
                                        ulong                reward_stake ) {
  fd_stake_accum_t rec;
  ulong            b;
  if( spill_probe( runtime_stack, key, &rec, &b ) ) {
    rec.stake += stake;
    FD_TEST( !__builtin_uaddl_overflow( rec.reward_stake, reward_stake, &rec.reward_stake ) );
    spill_write( runtime_stack, &rec, spill_rec_off( runtime_stack, rec.next ), sizeof(rec) );
    return;
  }

  ulong idx = runtime_stack->stakes.stake_accum_spill_cnt;
  if( FD_UNLIKELY( idx>=runtime_stack->stakes.stake_accum_spill_max ) ) {
    FD_LOG_ERR(( "invariant violation: staked_accounts >= max_vote_accounts" ));
  }
  rec = (fd_stake_accum_t){ .pubkey = *key, .stake = stake, .reward_stake = reward_stake, .next = (uint)idx };
  spill_write( runtime_stack, &rec, spill_rec_off( runtime_stack, idx ), sizeof(rec) );
  stake_accum_bucket_t bucket = { .gen = runtime_stack->stakes.stake_accum_spill_gen, .idx = (uint)idx };
  spill_write( runtime_stack, &bucket, b*sizeof(stake_accum_bucket_t), sizeof(bucket) );
  runtime_stack->stakes.stake_accum_spill_cnt = idx+1UL;
}

void
fd_runtime_stack_stake_accum_spill_read( fd_runtime_stack_t const * runtime_stack,
                                         ulong                      idx,
                                         fd_stake_accum_t *         out,
                                         ulong                      cnt ) {
  FD_TEST( idx+cnt<=runtime_stack->stakes.stake_accum_spill_cnt );
  spill_read( runtime_stack, out, spill_rec_off( runtime_stack, idx ), cnt*sizeof(fd_stake_accum_t) );
}
