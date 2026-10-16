#include "fd_ed25519_verifier.h"

/* FD_ED25519_VERIFIER_DELAY is 1 on the builds whose fastest path is
   the eight-lane group of fd_ed25519_verify_batch_multi_msg: there the
   batch verifier collects signatures and verifies full groups without
   the signer cache (the group beats the cached serial path at any hit
   rate).  FD_ED25519_CRC comes from the build of the crc backend. */

#ifndef FD_ED25519_CRC
#define FD_ED25519_CRC 0
#endif

#define FD_ED25519_VERIFIER_DELAY (FD_ED25519_CRC && FD_HAS_AVX512)

#define FD_ED25519_VERIFIER_MAGIC       (0xfd3d25519e71f1e0UL) /* fd ed25519 verifier ver 0 */
#define FD_ED25519_BATCH_VERIFIER_MAGIC (0xfd3d25519ba7c4e0UL) /* fd ed25519 batch verifier ver 0 */

#define FD_ED25519_VERIFIER_CACHE_DEFAULT_ENT_CNT (2048UL)

/* cache_ent_cnt_resolve maps a FD_ED25519_VERIFIER_CACHE_* value or a
   cache entry count to the entry count to allocate, 0 for no cache
   and ULONG_MAX for an invalid value. */

static ulong
cache_ent_cnt_resolve( ulong cache_ent_cnt ) {
  if( cache_ent_cnt==FD_ED25519_VERIFIER_CACHE_DEFAULT ) return FD_ED25519_VERIFIER_CACHE_DEFAULT_ENT_CNT;
  if( cache_ent_cnt==FD_ED25519_VERIFIER_CACHE_OFF     ) return 0UL;
  if( FD_UNLIKELY( !fd_ed25519_cache_footprint( cache_ent_cnt ) ) ) return ULONG_MAX;
  return cache_ent_cnt;
}

/* verdict reduces the per-signature codes of one transaction: the
   first code that is neither SUCCESS nor ERR_MSG, else ERR_MSG if any,
   else SUCCESS. */

static int
verdict( int const * results,
         ulong       cnt ) {
  int err = FD_ED25519_SUCCESS;
  for( ulong j=0UL; j<cnt; j++ ) {
    int r = results[ j ];
    if( r==FD_ED25519_SUCCESS ) continue;
    if( r!=FD_ED25519_ERR_MSG ) return r;
    err = FD_ED25519_ERR_MSG;
  }
  return err;
}

/* ---- fd_ed25519_verifier_t ---- */

struct __attribute__((aligned(FD_ED25519_VERIFIER_ALIGN))) fd_ed25519_verifier {
  ulong                magic;
  ulong                cache_ent_cnt; /* 0 without a cache */
  fd_ed25519_cache_t * cache;         /* NULL without a cache, else the join of the region after sha */
  fd_sha512_t *        sha_ptr[ FD_ED25519_VERIFIER_SIG_MAX ];
  fd_sha512_t          sha    [ FD_ED25519_VERIFIER_SIG_MAX ];
};

FD_STATIC_ASSERT( FD_ED25519_CACHE_ALIGN<=FD_ED25519_VERIFIER_ALIGN, verifier_align );
FD_STATIC_ASSERT( FD_SHA512_ALIGN       <=FD_ED25519_VERIFIER_ALIGN, verifier_align );

ulong
fd_ed25519_verifier_align( void ) {
  return FD_ED25519_VERIFIER_ALIGN;
}

ulong
fd_ed25519_verifier_footprint( ulong cache_ent_cnt ) {
  ulong ent_cnt = cache_ent_cnt_resolve( cache_ent_cnt );
  if( FD_UNLIKELY( ent_cnt==ULONG_MAX ) ) return 0UL;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_ed25519_verifier_t), sizeof(fd_ed25519_verifier_t) );
  if( ent_cnt ) l = FD_LAYOUT_APPEND( l, fd_ed25519_cache_align(), fd_ed25519_cache_footprint( ent_cnt ) );
  return FD_LAYOUT_FINI( l, FD_ED25519_VERIFIER_ALIGN );
}

void *
fd_ed25519_verifier_new( void * mem,
                         ulong  cache_ent_cnt,
                         ulong  seed ) {
  if( FD_UNLIKELY( !mem ) ) { FD_LOG_WARNING(( "NULL mem" )); return NULL; }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_ED25519_VERIFIER_ALIGN ) ) ) { FD_LOG_WARNING(( "misaligned mem" )); return NULL; }
  ulong ent_cnt = cache_ent_cnt_resolve( cache_ent_cnt );
  if( FD_UNLIKELY( ent_cnt==ULONG_MAX ) ) { FD_LOG_WARNING(( "bad cache_ent_cnt" )); return NULL; }

  fd_ed25519_verifier_t * verifier = (fd_ed25519_verifier_t *)mem;
  verifier->cache_ent_cnt = ent_cnt;
  verifier->cache         = NULL;
  for( ulong j=0UL; j<FD_ED25519_VERIFIER_SIG_MAX; j++ ) {
    if( FD_UNLIKELY( !fd_sha512_new( verifier->sha+j ) ) ) { FD_LOG_WARNING(( "fd_sha512_new failed" )); return NULL; }
  }
  if( ent_cnt ) {
    if( FD_UNLIKELY( !fd_ed25519_cache_new( verifier+1, ent_cnt, seed ) ) ) { FD_LOG_WARNING(( "fd_ed25519_cache_new failed" )); return NULL; }
  }

  FD_COMPILER_MFENCE();
  verifier->magic = FD_ED25519_VERIFIER_MAGIC;
  FD_COMPILER_MFENCE();
  return mem;
}

fd_ed25519_verifier_t *
fd_ed25519_verifier_join( void * shverifier ) {
  fd_ed25519_verifier_t * verifier = (fd_ed25519_verifier_t *)shverifier;
  if( FD_UNLIKELY( !verifier ) ) { FD_LOG_WARNING(( "NULL shverifier" )); return NULL; }
  if( FD_UNLIKELY( verifier->magic!=FD_ED25519_VERIFIER_MAGIC ) ) { FD_LOG_WARNING(( "bad magic" )); return NULL; }
  for( ulong j=0UL; j<FD_ED25519_VERIFIER_SIG_MAX; j++ ) {
    verifier->sha_ptr[ j ] = fd_sha512_join( verifier->sha+j );
    if( FD_UNLIKELY( !verifier->sha_ptr[ j ] ) ) { FD_LOG_WARNING(( "fd_sha512_join failed" )); return NULL; }
  }
  if( verifier->cache_ent_cnt ) {
    verifier->cache = fd_ed25519_cache_join( verifier+1 );
    if( FD_UNLIKELY( !verifier->cache ) ) { FD_LOG_WARNING(( "fd_ed25519_cache_join failed" )); return NULL; }
  }
  return verifier;
}

void *
fd_ed25519_verifier_leave( fd_ed25519_verifier_t * verifier ) {
  if( FD_UNLIKELY( !verifier ) ) { FD_LOG_WARNING(( "NULL verifier" )); return NULL; }
  if( verifier->cache ) fd_ed25519_cache_leave( verifier->cache );
  for( ulong j=0UL; j<FD_ED25519_VERIFIER_SIG_MAX; j++ ) fd_sha512_leave( verifier->sha_ptr[ j ] );
  return (void *)verifier;
}

void *
fd_ed25519_verifier_delete( void * shverifier ) {
  fd_ed25519_verifier_t * verifier = (fd_ed25519_verifier_t *)shverifier;
  if( FD_UNLIKELY( !verifier ) ) { FD_LOG_WARNING(( "NULL shverifier" )); return NULL; }
  if( FD_UNLIKELY( verifier->magic!=FD_ED25519_VERIFIER_MAGIC ) ) { FD_LOG_WARNING(( "bad magic" )); return NULL; }
  if( verifier->cache_ent_cnt ) fd_ed25519_cache_delete( verifier+1 );
  for( ulong j=0UL; j<FD_ED25519_VERIFIER_SIG_MAX; j++ ) fd_sha512_delete( verifier->sha+j );
  FD_COMPILER_MFENCE();
  verifier->magic = 0UL;
  FD_COMPILER_MFENCE();
  return shverifier;
}

int
fd_ed25519_verifier_verify( fd_ed25519_verifier_t * verifier,
                            uchar const             msg[],
                            ulong                   msg_sz,
                            uchar const             sig[ 64 ],
                            uchar const             public_key[ 32 ] ) {
  if( verifier->cache ) return fd_ed25519_verify_cached( msg, msg_sz, sig, public_key, verifier->sha_ptr[ 0 ], verifier->cache );
  return fd_ed25519_verify( msg, msg_sz, sig, public_key, verifier->sha_ptr[ 0 ] );
}

/* verify_run verifies sig_cnt<=FD_ED25519_VERIFIER_SIG_MAX signatures
   together. */

static void
verify_run( fd_ed25519_verifier_t * verifier,
            uchar const * const     msgs[],
            ulong const             msg_szs[],
            uchar const * const     sigs[],
            uchar const * const     public_keys[],
            int                     results[],
            ulong                   sig_cnt ) {
  if( verifier->cache ) fd_ed25519_verify_batch_multi_msg_cached( msgs, msg_szs, sigs, public_keys, verifier->sha_ptr, results, sig_cnt, verifier->cache );
  else                  fd_ed25519_verify_batch_multi_msg       ( msgs, msg_szs, sigs, public_keys, verifier->sha_ptr, results, sig_cnt );
}

void
fd_ed25519_verifier_verify_batch( fd_ed25519_verifier_t * verifier,
                                  uchar const * const     msgs[],
                                  ulong const             msg_szs[],
                                  uchar const * const     sigs[],
                                  uchar const * const     public_keys[],
                                  int                     results[],
                                  ulong                   sig_cnt ) {
  for( ulong j=0UL; j<sig_cnt; j+=FD_ED25519_VERIFIER_SIG_MAX ) {
    ulong run = fd_ulong_min( sig_cnt-j, FD_ED25519_VERIFIER_SIG_MAX );
    verify_run( verifier, msgs+j, msg_szs+j, sigs+j, public_keys+j, results+j, run );
  }
}

/* txn_lanes appends the signatures of txn to the lane arrays at
   index lane and returns the new lane count. */

static ulong
txn_lanes( fd_txn_t const * txn,
           uchar const *    payload,
           ulong            payload_sz,
           ulong            lane,
           uchar const *    msgs[],
           ulong            msg_szs[],
           uchar const *    sigs[],
           uchar const *    public_keys[] ) {
  ulong msg_sz = fd_txn_msg_sz( txn, payload_sz );
  for( ulong j=0UL; j<txn->signature_cnt; j++ ) {
    msgs       [ lane ] = payload + txn->message_off;
    msg_szs    [ lane ] = msg_sz;
    sigs       [ lane ] = payload + txn->signature_off + 64UL*j;
    public_keys[ lane ] = payload + txn->acct_addr_off + 32UL*j;
    lane++;
  }
  return lane;
}

int
fd_ed25519_verifier_verify_txn( fd_ed25519_verifier_t * verifier,
                                fd_txn_t const *        txn,
                                uchar const *           payload,
                                ulong                   payload_sz ) {
  uchar const * msgs       [ FD_TXN_SIG_MAX ];
  ulong         msg_szs    [ FD_TXN_SIG_MAX ];
  uchar const * sigs       [ FD_TXN_SIG_MAX ];
  uchar const * public_keys[ FD_TXN_SIG_MAX ];
  int           results    [ FD_TXN_SIG_MAX ];
  ulong lane_cnt = txn_lanes( txn, payload, payload_sz, 0UL, msgs, msg_szs, sigs, public_keys );
  verify_run( verifier, msgs, msg_szs, sigs, public_keys, results, lane_cnt );
  return verdict( results, lane_cnt );
}

void
fd_ed25519_verifier_verify_txns( fd_ed25519_verifier_t * verifier,
                                 fd_txn_t const * const  txns[],
                                 uchar const * const     payloads[],
                                 ulong const             payload_szs[],
                                 int                     results[],
                                 ulong                   txn_cnt ) {
  uchar const * msgs       [ FD_ED25519_VERIFIER_SIG_MAX ];
  ulong         msg_szs    [ FD_ED25519_VERIFIER_SIG_MAX ];
  uchar const * sigs       [ FD_ED25519_VERIFIER_SIG_MAX ];
  uchar const * public_keys[ FD_ED25519_VERIFIER_SIG_MAX ];
  int           codes      [ FD_ED25519_VERIFIER_SIG_MAX ];
  ulong lane_cnt  = 0UL;
  ulong run_start = 0UL; /* first txn of the run in hand */
  for( ulong i=0UL; i<txn_cnt; i++ ) {
    lane_cnt = txn_lanes( txns[ i ], payloads[ i ], payload_szs[ i ], lane_cnt, msgs, msg_szs, sigs, public_keys );
    if( lane_cnt<FD_ED25519_BATCH_VERIFIER_GROUP && i+1UL<txn_cnt ) continue;
    verify_run( verifier, msgs, msg_szs, sigs, public_keys, codes, lane_cnt );
    ulong lane = 0UL;
    for( ulong k=run_start; k<=i; k++ ) {
      results[ k ] = verdict( codes+lane, txns[ k ]->signature_cnt );
      lane += txns[ k ]->signature_cnt;
    }
    lane_cnt  = 0UL;
    run_start = i+1UL;
  }
}

ulong fd_ed25519_verifier_hit_cnt   ( fd_ed25519_verifier_t const * verifier ) { return verifier->cache ? fd_ed25519_cache_hit_cnt   ( verifier->cache ) : 0UL; }
ulong fd_ed25519_verifier_miss_cnt  ( fd_ed25519_verifier_t const * verifier ) { return verifier->cache ? fd_ed25519_cache_miss_cnt  ( verifier->cache ) : 0UL; }
ulong fd_ed25519_verifier_insert_cnt( fd_ed25519_verifier_t const * verifier ) { return verifier->cache ? fd_ed25519_cache_insert_cnt( verifier->cache ) : 0UL; }

/* ---- fd_ed25519_batch_verifier_t ---- */

#if FD_ED25519_VERIFIER_DELAY

/* The pending group: each lane holds a copy of its signature and
   public key and the index of the message slot of its transaction.
   Slot t belongs to the t-th transaction of the group; pending_cnt
   below GROUP bounds the pending transactions by GROUP-1, so the slot
   of the transaction being added always exists. */

struct __attribute__((aligned(FD_ED25519_VERIFIER_ALIGN))) fd_ed25519_batch_verifier {
  ulong         magic;
  ulong         pending_cnt; /* lanes in hand, <GROUP between calls */
  ulong         txn_cnt;     /* message slots in hand */
  fd_sha512_t * sha_ptr[ FD_ED25519_BATCH_VERIFIER_GROUP ];
  fd_sha512_t   sha    [ FD_ED25519_BATCH_VERIFIER_GROUP ];
  uchar         sig    [ FD_ED25519_BATCH_VERIFIER_GROUP ][ 64 ];
  uchar         pubkey [ FD_ED25519_BATCH_VERIFIER_GROUP ][ 32 ];
  ulong         slot   [ FD_ED25519_BATCH_VERIFIER_GROUP ];
  ulong         msg_sz [ FD_ED25519_BATCH_VERIFIER_GROUP ];
  uchar         msg    [ FD_ED25519_BATCH_VERIFIER_GROUP ][ FD_TXN_MTU ];
};

ulong
fd_ed25519_batch_verifier_align( void ) {
  return FD_ED25519_VERIFIER_ALIGN;
}

ulong
fd_ed25519_batch_verifier_footprint( ulong cache_ent_cnt ) {
  if( FD_UNLIKELY( cache_ent_cnt_resolve( cache_ent_cnt )==ULONG_MAX ) ) return 0UL;
  return sizeof(fd_ed25519_batch_verifier_t);
}

void *
fd_ed25519_batch_verifier_new( void * mem,
                               ulong  cache_ent_cnt,
                               ulong  seed ) {
  (void)seed;
  if( FD_UNLIKELY( !mem ) ) { FD_LOG_WARNING(( "NULL mem" )); return NULL; }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_ED25519_VERIFIER_ALIGN ) ) ) { FD_LOG_WARNING(( "misaligned mem" )); return NULL; }
  if( FD_UNLIKELY( cache_ent_cnt_resolve( cache_ent_cnt )==ULONG_MAX ) ) { FD_LOG_WARNING(( "bad cache_ent_cnt" )); return NULL; }

  fd_ed25519_batch_verifier_t * verifier = (fd_ed25519_batch_verifier_t *)mem;
  verifier->pending_cnt = 0UL;
  verifier->txn_cnt     = 0UL;
  for( ulong j=0UL; j<FD_ED25519_BATCH_VERIFIER_GROUP; j++ ) {
    if( FD_UNLIKELY( !fd_sha512_new( verifier->sha+j ) ) ) { FD_LOG_WARNING(( "fd_sha512_new failed" )); return NULL; }
  }

  FD_COMPILER_MFENCE();
  verifier->magic = FD_ED25519_BATCH_VERIFIER_MAGIC;
  FD_COMPILER_MFENCE();
  return mem;
}

fd_ed25519_batch_verifier_t *
fd_ed25519_batch_verifier_join( void * shverifier ) {
  fd_ed25519_batch_verifier_t * verifier = (fd_ed25519_batch_verifier_t *)shverifier;
  if( FD_UNLIKELY( !verifier ) ) { FD_LOG_WARNING(( "NULL shverifier" )); return NULL; }
  if( FD_UNLIKELY( verifier->magic!=FD_ED25519_BATCH_VERIFIER_MAGIC ) ) { FD_LOG_WARNING(( "bad magic" )); return NULL; }
  for( ulong j=0UL; j<FD_ED25519_BATCH_VERIFIER_GROUP; j++ ) {
    verifier->sha_ptr[ j ] = fd_sha512_join( verifier->sha+j );
    if( FD_UNLIKELY( !verifier->sha_ptr[ j ] ) ) { FD_LOG_WARNING(( "fd_sha512_join failed" )); return NULL; }
  }
  return verifier;
}

void *
fd_ed25519_batch_verifier_leave( fd_ed25519_batch_verifier_t * verifier ) {
  if( FD_UNLIKELY( !verifier ) ) { FD_LOG_WARNING(( "NULL verifier" )); return NULL; }
  for( ulong j=0UL; j<FD_ED25519_BATCH_VERIFIER_GROUP; j++ ) fd_sha512_leave( verifier->sha_ptr[ j ] );
  return (void *)verifier;
}

void *
fd_ed25519_batch_verifier_delete( void * shverifier ) {
  fd_ed25519_batch_verifier_t * verifier = (fd_ed25519_batch_verifier_t *)shverifier;
  if( FD_UNLIKELY( !verifier ) ) { FD_LOG_WARNING(( "NULL shverifier" )); return NULL; }
  if( FD_UNLIKELY( verifier->magic!=FD_ED25519_BATCH_VERIFIER_MAGIC ) ) { FD_LOG_WARNING(( "bad magic" )); return NULL; }
  for( ulong j=0UL; j<FD_ED25519_BATCH_VERIFIER_GROUP; j++ ) fd_sha512_delete( verifier->sha+j );
  FD_COMPILER_MFENCE();
  verifier->magic = 0UL;
  FD_COMPILER_MFENCE();
  return shverifier;
}

/* cut verifies the pending lanes and empties the group.  Returns 0 if
   all passed, -1 if any failed. */

static int
cut( fd_ed25519_batch_verifier_t * verifier ) {
  uchar const * msgs       [ FD_ED25519_BATCH_VERIFIER_GROUP ] = { 0 };
  ulong         msg_szs    [ FD_ED25519_BATCH_VERIFIER_GROUP ] = { 0 };
  uchar const * sigs       [ FD_ED25519_BATCH_VERIFIER_GROUP ] = { 0 };
  uchar const * public_keys[ FD_ED25519_BATCH_VERIFIER_GROUP ] = { 0 };
  int           results    [ FD_ED25519_BATCH_VERIFIER_GROUP ] = { 0 };
  ulong cnt = verifier->pending_cnt;
  for( ulong l=0UL; l<cnt; l++ ) {
    ulong t = verifier->slot[ l ];
    msgs       [ l ] = verifier->msg[ t ];
    msg_szs    [ l ] = verifier->msg_sz[ t ];
    sigs       [ l ] = verifier->sig[ l ];
    public_keys[ l ] = verifier->pubkey[ l ];
  }
  fd_ed25519_verify_batch_multi_msg( msgs, msg_szs, sigs, public_keys, verifier->sha_ptr, results, cnt );
  int ok = 1;
  for( ulong l=0UL; l<cnt; l++ ) ok &= (results[ l ]==FD_ED25519_SUCCESS);
  verifier->pending_cnt = 0UL;
  verifier->txn_cnt     = 0UL;
  return ok ? 0 : -1;
}

/* msg_slot_add copies the message of txn into the next slot and
   returns the slot index. */

static ulong
msg_slot_add( fd_ed25519_batch_verifier_t * verifier,
              fd_txn_t const *              txn,
              uchar const *                 payload,
              ulong                         payload_sz ) {
  ulong t      = verifier->txn_cnt++;
  ulong msg_sz = fd_txn_msg_sz( txn, payload_sz );
  verifier->msg_sz[ t ] = msg_sz;
  fd_memcpy( verifier->msg[ t ], payload + txn->message_off, msg_sz );
  return t;
}

int
fd_ed25519_batch_verifier_verify_txn( fd_ed25519_batch_verifier_t * verifier,
                                      fd_txn_t const *              txn,
                                      uchar const *                 payload,
                                      ulong                         payload_sz ) {
  if( FD_UNLIKELY( !txn->signature_cnt ) ) return 0;
  int rc = 1;
  ulong t = msg_slot_add( verifier, txn, payload, payload_sz );
  for( ulong j=0UL; j<txn->signature_cnt; j++ ) {
    ulong l = verifier->pending_cnt++;
    fd_memcpy( verifier->sig   [ l ], payload + txn->signature_off + 64UL*j, 64UL );
    fd_memcpy( verifier->pubkey[ l ], payload + txn->acct_addr_off + 32UL*j, 32UL );
    verifier->slot[ l ] = t;
    if( verifier->pending_cnt<FD_ED25519_BATCH_VERIFIER_GROUP ) continue;
    int cut_rc = cut( verifier );
    rc = (rc==-1 || cut_rc==-1) ? -1 : 0;
    /* the signatures left in txn open the next group with its message in slot 0 */
    if( j+1UL<txn->signature_cnt ) t = msg_slot_add( verifier, txn, payload, payload_sz );
  }
  return rc;
}

int
fd_ed25519_batch_verifier_flush( fd_ed25519_batch_verifier_t * verifier ) {
  if( !verifier->pending_cnt ) return 1;
  return cut( verifier );
}

void
fd_ed25519_batch_verifier_clear( fd_ed25519_batch_verifier_t * verifier ) {
  verifier->pending_cnt = 0UL;
  verifier->txn_cnt     = 0UL;
}

ulong
fd_ed25519_batch_verifier_pending_cnt( fd_ed25519_batch_verifier_t const * verifier ) {
  return verifier->pending_cnt;
}

ulong fd_ed25519_batch_verifier_hit_cnt   ( fd_ed25519_batch_verifier_t const * verifier ) { (void)verifier; return 0UL; }
ulong fd_ed25519_batch_verifier_miss_cnt  ( fd_ed25519_batch_verifier_t const * verifier ) { (void)verifier; return 0UL; }
ulong fd_ed25519_batch_verifier_insert_cnt( fd_ed25519_batch_verifier_t const * verifier ) { (void)verifier; return 0UL; }

#else /* !FD_ED25519_VERIFIER_DELAY: a verifier that answers at once */

struct fd_ed25519_batch_verifier {
  fd_ed25519_verifier_t verifier;
};

ulong
fd_ed25519_batch_verifier_align( void ) {
  return fd_ed25519_verifier_align();
}

ulong
fd_ed25519_batch_verifier_footprint( ulong cache_ent_cnt ) {
  return fd_ed25519_verifier_footprint( cache_ent_cnt );
}

void *
fd_ed25519_batch_verifier_new( void * mem,
                               ulong  cache_ent_cnt,
                               ulong  seed ) {
  return fd_ed25519_verifier_new( mem, cache_ent_cnt, seed );
}

fd_ed25519_batch_verifier_t *
fd_ed25519_batch_verifier_join( void * shverifier ) {
  return (fd_ed25519_batch_verifier_t *)fd_ed25519_verifier_join( shverifier );
}

void *
fd_ed25519_batch_verifier_leave( fd_ed25519_batch_verifier_t * verifier ) {
  return fd_ed25519_verifier_leave( &verifier->verifier );
}

void *
fd_ed25519_batch_verifier_delete( void * shverifier ) {
  return fd_ed25519_verifier_delete( shverifier );
}

int
fd_ed25519_batch_verifier_verify_txn( fd_ed25519_batch_verifier_t * verifier,
                                      fd_txn_t const *              txn,
                                      uchar const *                 payload,
                                      ulong                         payload_sz ) {
  return fd_ed25519_verifier_verify_txn( &verifier->verifier, txn, payload, payload_sz )==FD_ED25519_SUCCESS ? 0 : -1;
}

int
fd_ed25519_batch_verifier_flush( fd_ed25519_batch_verifier_t * verifier ) {
  (void)verifier;
  return 1;
}

void
fd_ed25519_batch_verifier_clear( fd_ed25519_batch_verifier_t * verifier ) {
  (void)verifier;
}

ulong
fd_ed25519_batch_verifier_pending_cnt( fd_ed25519_batch_verifier_t const * verifier ) {
  (void)verifier;
  return 0UL;
}

ulong fd_ed25519_batch_verifier_hit_cnt   ( fd_ed25519_batch_verifier_t const * verifier ) { return fd_ed25519_verifier_hit_cnt   ( &verifier->verifier ); }
ulong fd_ed25519_batch_verifier_miss_cnt  ( fd_ed25519_batch_verifier_t const * verifier ) { return fd_ed25519_verifier_miss_cnt  ( &verifier->verifier ); }
ulong fd_ed25519_batch_verifier_insert_cnt( fd_ed25519_batch_verifier_t const * verifier ) { return fd_ed25519_verifier_insert_cnt( &verifier->verifier ); }

#endif /* FD_ED25519_VERIFIER_DELAY */
