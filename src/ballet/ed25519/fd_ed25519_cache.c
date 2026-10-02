#include "fd_ed25519.h"
#include "fd_curve25519.h"

#define FD_ED25519_CACHE_MAGIC (0xfd3d25519cac4e00UL) /* fd ed25519 cache ver 0 */

/* A set holds the keys of its WAY_CNT ways in 2 cache lines.  use[w]
   is the tick of the last use of way w (0 if way w is invalid). */

#define WAY_CNT (4UL)

struct __attribute__((aligned(128))) fd_ed25519_cache_set {
  uchar key[ WAY_CNT ][ 32 ];
  ulong use[ WAY_CNT ];
};
typedef struct fd_ed25519_cache_set fd_ed25519_cache_set_t;

struct __attribute__((aligned(FD_ED25519_CACHE_ALIGN))) fd_ed25519_cache {
  ulong magic;
  ulong set_cnt;    /* power of 2 */
  ulong filter_cnt; /* power of 2 */
  ulong seed;

  ulong credit; /* table builds are paid for with credits, see cache_admit */
  ulong tick;   /* incremented on every lookup */

  ulong hit_cnt;
  ulong miss_cnt;
  ulong insert_cnt;

  fd_ed25519_cache_set_t * set;    /* indexed [0,set_cnt) */
  ulong *                  filter; /* indexed [0,filter_cnt), hashes of recent successful misses */
  fd_ed25519_point_t *     tbl;    /* indexed [0,WAY_CNT*set_cnt*FD_ED25519_SPLIT_A_TBL_CNT), split tables of -A */

  fd_ed25519_point_t b_tbl[ FD_ED25519_SPLIT_B_TBL_CNT ];
};

/* The admission filter has 4 slots per entry */

#define FILTER_RATIO (4UL)

/* Each evaluated group equation earns a credit and a table build
   (~0.7 verify) costs BUILD_COST credits, bounding the build overhead
   to <10% even when every key is new.  Up to CREDIT_MAX credits bank
   up for bursts of new keys. */

#define BUILD_COST (8UL)
#define CREDIT_MAX (64UL*BUILD_COST)

FD_FN_CONST ulong
fd_ed25519_cache_align( void ) {
  return FD_ED25519_CACHE_ALIGN;
}

FD_FN_CONST ulong
fd_ed25519_cache_footprint( ulong ent_cnt ) {
  if( FD_UNLIKELY( !fd_ulong_is_pow2( ent_cnt ) || ent_cnt<WAY_CNT || ent_cnt>(1UL<<20) ) ) return 0UL;
  ulong set_cnt = ent_cnt/WAY_CNT;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_ed25519_cache_t),     sizeof(fd_ed25519_cache_t)                              );
  l = FD_LAYOUT_APPEND( l, alignof(fd_ed25519_cache_set_t), set_cnt*sizeof(fd_ed25519_cache_set_t)                  );
  l = FD_LAYOUT_APPEND( l, alignof(ulong),                  FILTER_RATIO*ent_cnt*sizeof(ulong)                      );
  l = FD_LAYOUT_APPEND( l, alignof(fd_ed25519_point_t),     ent_cnt*FD_ED25519_SPLIT_A_TBL_CNT*sizeof(fd_ed25519_point_t) );
  return FD_LAYOUT_FINI( l, fd_ed25519_cache_align() );
}

void *
fd_ed25519_cache_new( void * mem,
                      ulong  ent_cnt,
                      ulong  seed ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_ed25519_cache_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ed25519_cache_footprint( ent_cnt ) ) ) {
    FD_LOG_WARNING(( "bad ent_cnt" ));
    return NULL;
  }

  ulong set_cnt    = ent_cnt/WAY_CNT;
  ulong filter_cnt = FILTER_RATIO*ent_cnt;

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_ed25519_cache_t * cache = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_ed25519_cache_t),     sizeof(fd_ed25519_cache_t)                              );
  void *               set   = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_ed25519_cache_set_t), set_cnt*sizeof(fd_ed25519_cache_set_t)                  );
  ulong *              filt  = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),                  filter_cnt*sizeof(ulong)                                );
  void *               tbl   = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_ed25519_point_t),     ent_cnt*FD_ED25519_SPLIT_A_TBL_CNT*sizeof(fd_ed25519_point_t) );
  FD_SCRATCH_ALLOC_FINI( l, fd_ed25519_cache_align() );

  cache->set_cnt    = set_cnt;
  cache->filter_cnt = filter_cnt;
  cache->seed       = seed;
  cache->credit     = CREDIT_MAX;
  cache->tick       = 0UL;
  cache->hit_cnt    = 0UL;
  cache->miss_cnt   = 0UL;
  cache->insert_cnt = 0UL;
  cache->set        = set;
  cache->filter     = filt;
  cache->tbl        = tbl;

  memset( set,  0, set_cnt*sizeof(fd_ed25519_cache_set_t) );
  memset( filt, 0, filter_cnt*sizeof(ulong)               );

  fd_ed25519_split_table_b( cache->b_tbl );

  FD_COMPILER_MFENCE();
  cache->magic = FD_ED25519_CACHE_MAGIC;
  FD_COMPILER_MFENCE();

  return mem;
}

fd_ed25519_cache_t *
fd_ed25519_cache_join( void * shcache ) {
  fd_ed25519_cache_t * cache = (fd_ed25519_cache_t *)shcache;
  if( FD_UNLIKELY( !cache ) ) {
    FD_LOG_WARNING(( "NULL shcache" ));
    return NULL;
  }
  if( FD_UNLIKELY( cache->magic!=FD_ED25519_CACHE_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }
  return cache;
}

void *
fd_ed25519_cache_leave( fd_ed25519_cache_t * cache ) {
  return (void *)cache;
}

void *
fd_ed25519_cache_delete( void * shcache ) {
  fd_ed25519_cache_t * cache = (fd_ed25519_cache_t *)shcache;
  if( FD_UNLIKELY( !cache ) ) {
    FD_LOG_WARNING(( "NULL shcache" ));
    return NULL;
  }
  if( FD_UNLIKELY( cache->magic!=FD_ED25519_CACHE_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }
  FD_COMPILER_MFENCE();
  cache->magic = 0UL;
  FD_COMPILER_MFENCE();
  return shcache;
}

ulong fd_ed25519_cache_hit_cnt   ( fd_ed25519_cache_t const * cache ) { return cache->hit_cnt;    }
ulong fd_ed25519_cache_miss_cnt  ( fd_ed25519_cache_t const * cache ) { return cache->miss_cnt;   }
ulong fd_ed25519_cache_insert_cnt( fd_ed25519_cache_t const * cache ) { return cache->insert_cnt; }

/* cache_query returns the split table of -A for public_key, or NULL if
   public_key is not cached.  *_h is set to the hash of public_key. */

static fd_ed25519_point_t const *
cache_query( fd_ed25519_cache_t * cache,
             uchar const          public_key[ 32 ],
             ulong *              _h ) {
  ulong h   = fd_hash( cache->seed, public_key, 32UL );
  ulong idx = h & (cache->set_cnt-1UL);
  *_h = h;

  fd_ed25519_cache_set_t * set = cache->set + idx;
  ulong tick = ++cache->tick;

  for( ulong w=0UL; w<WAY_CNT; w++ ) {
    if( FD_LIKELY( set->use[ w ] && fd_memeq( set->key[ w ], public_key, 32UL ) ) ) {
      set->use[ w ] = tick;
      cache->hit_cnt++;
      fd_ed25519_point_t const * tbl = cache->tbl + (WAY_CNT*idx+w)*FD_ED25519_SPLIT_A_TBL_CNT;
      for( ulong off=0UL; off<FD_ED25519_SPLIT_A_TBL_CNT*sizeof(fd_ed25519_point_t); off+=64UL ) {
        __builtin_prefetch( (uchar const *)tbl + off, 0, 3 );
      }
      return tbl;
    }
  }
  cache->miss_cnt++;
  return NULL;
}

/* cache_admit is called after a signature by public_key (hash h, not
   cached) verified successfully, with neg_a the decoded point -A.  The
   key is inserted if it also verified successfully recently.  Only
   keys that decode to a valid, not small order point can verify
   successfully, and building a table requires a valid signature, so
   junk traffic can't force table builds. */

static void
cache_admit( fd_ed25519_cache_t *       cache,
             uchar const                public_key[ 32 ],
             ulong                      h,
             fd_ed25519_point_t const * neg_a ) {

  ulong * slot = cache->filter + (fd_ulong_hash( h ) & (cache->filter_cnt-1UL));
  if( FD_LIKELY( *slot!=h ) ) {
    *slot = h;
    return;
  }
  if( FD_UNLIKELY( cache->credit<BUILD_COST ) ) return;
  cache->credit -= BUILD_COST;
  *slot = 0UL;

  /* Replace the least recently used way (invalid ways have use 0) */

  ulong idx = h & (cache->set_cnt-1UL);
  fd_ed25519_cache_set_t * set = cache->set + idx;
  ulong w = 0UL;
  for( ulong v=1UL; v<WAY_CNT; v++ ) w = fd_ulong_if( set->use[ v ]<set->use[ w ], v, w );

  fd_ed25519_split_table_a( cache->tbl + (WAY_CNT*idx+w)*FD_ED25519_SPLIT_A_TBL_CNT, neg_a );
  memcpy( set->key[ w ], public_key, 32UL );
  set->use[ w ] = ++cache->tick;
  cache->insert_cnt++;
}

/* verify_one does the checks of fd_ed25519_verify on one signature, in
   the same order and with the same error codes, and returns the first
   failing check's error code.  If all checks pass, it returns
   FD_ED25519_SUCCESS and, if *_ok is non-zero on entry, sets *_ok to
   whether the group equation holds (if *_ok is zero on entry, the
   group equation is not evaluated). */

static int
verify_one( uchar const          msg[],
            ulong                msg_sz,
            uchar const          sig[ 64 ],
            uchar const          public_key[ 32 ],
            fd_sha512_t *        sha,
            fd_ed25519_cache_t * cache,
            int *                _ok ) {

  uchar const * r = sig;
  uchar const * S = sig + 32;

  if( FD_UNLIKELY( !fd_curve25519_scalar_validate( S ) ) ) return FD_ED25519_ERR_SIG;

  ulong h;
  fd_ed25519_point_t const * a_tbl = cache_query( cache, public_key, &h );

  fd_ed25519_point_t Aprime[1], R[1];
  if( FD_LIKELY( a_tbl ) ) {

    /* A is cached, so it decodes and is not small order: the checks of
       the uncached path reduce to the ones on R.  frombytes_1x gives
       the same point as frombytes_2x, so the small order checks
       agree.  When the equation is evaluated, R's decode is
       interleaved with the scalar mul and its checks run afterwards,
       in the same order. */

    if( FD_UNLIKELY( !*_ok ) ) {
      if( FD_UNLIKELY( fd_ed25519_point_frombytes_1x( R, r ) ) ) return FD_ED25519_ERR_SIG;
      if( FD_UNLIKELY( fd_ed25519_affine_is_small_order( R ) ) ) return FD_ED25519_ERR_SIG;
      return FD_ED25519_SUCCESS;
    }

    fd_ed25519_point_decode_t dec[1];
    fd_ed25519_point_decode_init( dec, r );

    uchar k[ 64 ];
    fd_sha512_fini( fd_sha512_append( fd_sha512_append( fd_sha512_append( fd_sha512_init( sha ),
                    r, 32UL ), public_key, 32UL ), msg, msg_sz ), k );
    fd_curve25519_scalar_reduce( k, k );

    /* Rcmp = [k](-A') + [S]B */

    fd_ed25519_point_t Rcmp[1];
    fd_ed25519_double_scalar_mul_base_split_decode( Rcmp, k, a_tbl, S, cache->b_tbl, dec );

    if( FD_UNLIKELY( fd_ed25519_point_decode_fini( R, dec ) ) ) return FD_ED25519_ERR_SIG;
    if( FD_UNLIKELY( fd_ed25519_affine_is_small_order( R ) ) ) return FD_ED25519_ERR_SIG;

    cache->credit = fd_ulong_min( cache->credit+1UL, CREDIT_MAX );
    *_ok = fd_ed25519_point_eq_z1( Rcmp, R );
    return FD_ED25519_SUCCESS;
  }

  int res = fd_ed25519_point_frombytes_2x( Aprime, public_key, R, r );
  if( FD_UNLIKELY( res ) ) return res == -1 ? FD_ED25519_ERR_PUBKEY : FD_ED25519_ERR_SIG;
  if( FD_UNLIKELY( fd_ed25519_affine_is_small_order( Aprime ) ) ) return FD_ED25519_ERR_PUBKEY;
  if( FD_UNLIKELY( fd_ed25519_affine_is_small_order( R      ) ) ) return FD_ED25519_ERR_SIG;

  if( FD_UNLIKELY( !*_ok ) ) return FD_ED25519_SUCCESS;

  cache->credit = fd_ulong_min( cache->credit+1UL, CREDIT_MAX );

  uchar k[ 64 ];
  fd_sha512_fini( fd_sha512_append( fd_sha512_append( fd_sha512_append( fd_sha512_init( sha ),
                  r, 32UL ), public_key, 32UL ), msg, msg_sz ), k );
  fd_curve25519_scalar_reduce( k, k );

  /* Rcmp = [k](-A') + [S]B */

  fd_ed25519_point_t Rcmp[1];
  fd_ed25519_point_neg( Aprime, Aprime );
  fd_ed25519_double_scalar_mul_base( Rcmp, k, Aprime, S );
  *_ok = fd_ed25519_point_eq_z1( Rcmp, R );
  if( FD_LIKELY( *_ok ) ) cache_admit( cache, public_key, h, Aprime );
  return FD_ED25519_SUCCESS;
}

int
fd_ed25519_verify_cached( uchar const          msg[], /* msg_sz */
                          ulong                msg_sz,
                          uchar const          sig[ 64 ],
                          uchar const          public_key[ 32 ],
                          fd_sha512_t *        sha,
                          fd_ed25519_cache_t * cache ) {
  int ok  = 1;
  int err = verify_one( msg, msg_sz, sig, public_key, sha, cache, &ok );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_LIKELY( ok ) ? FD_ED25519_SUCCESS : FD_ED25519_ERR_MSG;
}

int
fd_ed25519_verify_batch_single_msg_cached( uchar const          msg[], /* msg_sz */
                                           ulong const          msg_sz,
                                           uchar const          signatures[ 64 ], /* 64 * batch_sz */
                                           uchar const          pubkeys[ 32 ],    /* 32 * batch_sz */
                                           fd_sha512_t *        shas[ 1 ],        /* batch_sz */
                                           uchar const          batch_sz,
                                           fd_ed25519_cache_t * cache ) {
  if( FD_UNLIKELY( batch_sz == 0 || batch_sz > 16 ) ) return FD_ED25519_ERR_SIG;

  /* The uncached version runs all checks first and then the group
     equations.  A check failure on any signature takes precedence over
     a group equation failure on an earlier one, so group equation
     failures are only reported after all checks pass.  Once a group
     equation fails, the remaining ones are skipped. */

  int ok = 1;
  for( ulong j=0UL; j<batch_sz; j++ ) {
    int err = verify_one( msg, msg_sz, signatures+64UL*j, pubkeys+32UL*j, shas[j], cache, &ok );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return FD_LIKELY( ok ) ? FD_ED25519_SUCCESS : FD_ED25519_ERR_MSG;
}
