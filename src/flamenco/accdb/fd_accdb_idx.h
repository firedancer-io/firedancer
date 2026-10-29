#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_idx_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_idx_h

/* Disk-resident account index primitives (index mode only).

   Index file regions (4 KiB pages, explicit pread/pwritev2 on the
   index fd, fallocated at boot):

     bkt   rooted slots, keyed by pubkey
     ovl   spilled unrooted versions, keyed by (pubkey, fork_id)
     olog  per-fork spill logs

   A page is a 64 B header plus 63 slots of 64 B.  Linear probing; a
   page an insert ever passed over full gets the sticky OVERFLOWED flag
   (deletes never clear it) so probes continue past it.

   One uint seqlock per FD_ACCDB_IDX_SEQ_GROUP pages.  The region has a
   single writer at a time (T2, or the snapin lead while T2 is
   quiescent), which is what makes a shared group word sound.  Writers
   use buffered same-thread pwritev2 so the page bytes are ordered
   between the odd and even seq stores.

   The cuckoo filter answers "maybe in bkt" for any pubkey.  4 x 16-bit
   fingerprints per ulong bucket, two candidate buckets per key:
   i1 = fastrange(h,nb), i2 = (fastrange(hash(fp),nb) - i1) mod nb, an
   involution for any nb.  Only the writer mutates it.  Plain inserts
   and deletes are one 8 B store.  A kick path is computed first, then
   applied in reverse under cf_seq odd, so every fingerprint is always
   in one of its buckets and probes revalidate negatives against
   cf_seq. */

#include "../../util/fd_util_base.h"
#include "../../util/bits/fd_bits.h"
#include "../../util/fd_hash32.h"
#include "../../util/log/fd_log.h"

#include <errno.h>
#include <unistd.h>
#include <sys/uio.h>

#define FD_ACCDB_IDX_PAGE_SZ      (4096UL)
#define FD_ACCDB_IDX_SLOT_CNT     (63UL)
#define FD_ACCDB_IDX_PROBE_MAX    (64UL)
#define FD_ACCDB_IDX_OVERFLOWED   (1U)
#define FD_ACCDB_IDX_SEQ_LG_GROUP (3)
#define FD_ACCDB_IDX_LOAD_PCT     (60UL)

#define FD_ACCDB_IDX_SALT_B  (0x6b6b745f62756b74UL)
#define FD_ACCDB_IDX_SALT_O  (0x6f766c5f6f766c5fUL)
#define FD_ACCDB_IDX_SALT_CF (0x63756b6f6f63756bUL)

#define FD_ACCDB_CF_LANES     (4UL)
#define FD_ACCDB_CF_LOAD_PCT  (90UL)
#define FD_ACCDB_CF_KICK_MAX  (500UL)
#define FD_ACCDB_CF_STASH_MAX (64UL)

struct __attribute__((packed)) fd_accdb_idx_slot {
  uchar  pubkey[ 32UL ];
  ulong  off_plus1;  /* 0 = empty */
  ulong  lamports;
  uint   exec_size;  /* EXEC bit | len, no RAM-only bits */
  uint   generation;
  ushort fork_id;    /* ovl only */
  uchar  pd_write;   /* ovl only */
  uchar  flags;
  uint   aux;
};

typedef struct fd_accdb_idx_slot fd_accdb_idx_slot_t;

FD_STATIC_ASSERT( sizeof(fd_accdb_idx_slot_t)==64UL, idx_slot_layout );

struct fd_accdb_idx_page {
  uint  flags;
  uint  cnt;
  uchar pad[ 56UL ];
  fd_accdb_idx_slot_t slot[ FD_ACCDB_IDX_SLOT_CNT ];
};

typedef struct fd_accdb_idx_page fd_accdb_idx_page_t;

FD_STATIC_ASSERT( sizeof(fd_accdb_idx_page_t)==FD_ACCDB_IDX_PAGE_SZ, idx_page_layout );

/* A region view: page range [page0,page0+npage) of fd, seq words. */

struct fd_accdb_idx_region {
  int    fd;
  ulong  page0;
  ulong  npage;
  uint * seq;
  ulong  salt;
  int    keyed_fork; /* ovl: slot matches (pubkey, fork_id) */
};

typedef struct fd_accdb_idx_region fd_accdb_idx_region_t;

FD_PROTOTYPES_BEGIN

static FD_FN_CONST inline ulong
fd_accdb_idx_fastrange( ulong h,
                        ulong n ) {
  return (ulong)( ( (__uint128_t)h * (__uint128_t)n )>>64 );
}

static FD_FN_CONST inline ulong
fd_accdb_idx_npage( ulong key_max ) {
  return fd_ulong_max( 1UL, ( key_max*100UL + FD_ACCDB_IDX_SLOT_CNT*FD_ACCDB_IDX_LOAD_PCT-1UL )/( FD_ACCDB_IDX_SLOT_CNT*FD_ACCDB_IDX_LOAD_PCT ) );
}

static FD_FN_CONST inline ulong
fd_accdb_idx_seq_cnt( ulong npage ) {
  return ( npage + (1UL<<FD_ACCDB_IDX_SEQ_LG_GROUP)-1UL )>>FD_ACCDB_IDX_SEQ_LG_GROUP;
}

static FD_FN_CONST inline ulong
fd_accdb_cf_nb( ulong key_max ) {
  return fd_ulong_max( 2UL, ( key_max*100UL + FD_ACCDB_CF_LANES*FD_ACCDB_CF_LOAD_PCT-1UL )/( FD_ACCDB_CF_LANES*FD_ACCDB_CF_LOAD_PCT ) );
}

/* fd_accdb_idx_io: full-length explicit I/O, any error fatal (files
   are fallocated at boot). */

static inline void
fd_accdb_idx_io( int    fd,
                 int    write,
                 void * buf,
                 ulong  sz,
                 ulong  off ) {
  ulong done = 0UL;
  while( done<sz ) {
    struct iovec iov = { .iov_base = (uchar *)buf+done, .iov_len = sz-done };
    long r = write ? pwritev2( fd, &iov, 1, (long)(off+done), 0 )
                   : pread   ( fd, iov.iov_base, iov.iov_len, (long)(off+done) );
    if( FD_UNLIKELY( -1==r && errno==EINTR ) ) continue;
    if( FD_UNLIKELY( r<=0 ) ) FD_LOG_ERR(( "accdb index %s failed (%ld %i-%s)", write ? "pwritev2" : "pread", r, errno, fd_io_strerror( errno ) ));
    done += (ulong)r;
  }
}

static inline ulong
fd_accdb_idx_home( fd_accdb_idx_region_t const * r,
                   uchar const                   pubkey[ 32 ],
                   ushort                        fork_id,
                   ulong                         seed ) {
  ulong h = fd_hash32( pubkey, seed^r->salt );
  if( r->keyed_fork ) h ^= (ulong)fork_id*0x9E3779B97F4A7C15UL;
  return fd_accdb_idx_fastrange( h, r->npage );
}

/* page_read validates against the group seqlock (any reader);
   page_read_raw is for the region writer. */

static inline void
fd_accdb_idx_page_read( fd_accdb_idx_region_t const * r,
                        ulong                         page,
                        fd_accdb_idx_page_t *         buf ) {
  uint * seqp = &r->seq[ page>>FD_ACCDB_IDX_SEQ_LG_GROUP ];
  for(;;) {
    uint s0 = FD_VOLATILE_CONST( *seqp );
    if( FD_UNLIKELY( s0&1U ) ) { FD_SPIN_PAUSE(); continue; }
    FD_COMPILER_MFENCE();
    fd_accdb_idx_io( r->fd, 0, buf, FD_ACCDB_IDX_PAGE_SZ, (r->page0+page)*FD_ACCDB_IDX_PAGE_SZ );
    FD_COMPILER_MFENCE();
    if( FD_LIKELY( FD_VOLATILE_CONST( *seqp )==s0 ) ) return;
  }
}

static inline void
fd_accdb_idx_page_read_raw( fd_accdb_idx_region_t const * r,
                            ulong                         page,
                            fd_accdb_idx_page_t *         buf ) {
  fd_accdb_idx_io( r->fd, 0, buf, FD_ACCDB_IDX_PAGE_SZ, (r->page0+page)*FD_ACCDB_IDX_PAGE_SZ );
}

static inline void
fd_accdb_idx_page_write( fd_accdb_idx_region_t const * r,
                         ulong                         page,
                         fd_accdb_idx_page_t *         buf ) {
  uint * seqp = &r->seq[ page>>FD_ACCDB_IDX_SEQ_LG_GROUP ];
  uint   s    = FD_VOLATILE_CONST( *seqp );
  FD_VOLATILE( *seqp ) = s+1U;
  FD_COMPILER_MFENCE();
  fd_accdb_idx_io( r->fd, 1, buf, FD_ACCDB_IDX_PAGE_SZ, (r->page0+page)*FD_ACCDB_IDX_PAGE_SZ );
  FD_COMPILER_MFENCE();
  FD_VOLATILE( *seqp ) = s+2U;
}

static inline fd_accdb_idx_slot_t *
fd_accdb_idx_page_find( fd_accdb_idx_region_t const * r,
                        fd_accdb_idx_page_t *         buf,
                        uchar const                   pubkey[ 32 ],
                        ushort                        fork_id ) {
  for( ulong i=0UL; i<FD_ACCDB_IDX_SLOT_CNT; i++ ) {
    fd_accdb_idx_slot_t * s = &buf->slot[ i ];
    if( s->off_plus1 && !memcmp( s->pubkey, pubkey, 32UL ) && ( !r->keyed_fork || s->fork_id==fork_id ) ) return s;
  }
  return NULL;
}

/* fd_accdb_idx_lookup: returns 1 and copies the slot on hit. */

static inline int
fd_accdb_idx_lookup( fd_accdb_idx_region_t const * r,
                     ulong                         seed,
                     uchar const                   pubkey[ 32 ],
                     ushort                        fork_id,
                     fd_accdb_idx_slot_t *         out ) {
  fd_accdb_idx_page_t buf[1];
  ulong page = fd_accdb_idx_home( r, pubkey, fork_id, seed );
  for( ulong probe=0UL; probe<FD_ACCDB_IDX_PROBE_MAX; probe++ ) {
    fd_accdb_idx_page_read( r, page, buf );
    fd_accdb_idx_slot_t * s = fd_accdb_idx_page_find( r, buf, pubkey, fork_id );
    if( s ) { *out = *s; return 1; }
    if( FD_LIKELY( !(buf->flags & FD_ACCDB_IDX_OVERFLOWED) ) ) return 0;
    page = page+1UL==r->npage ? 0UL : page+1UL;
  }
  return 0;
}

/* fd_accdb_idx_upsert (writer only): insert or replace.  Returns 1 and
   fills *old when a slot was replaced. */

static inline int
fd_accdb_idx_upsert( fd_accdb_idx_region_t const * r,
                     ulong                         seed,
                     fd_accdb_idx_slot_t const *   rec,
                     fd_accdb_idx_slot_t *         old ) {
  fd_accdb_idx_page_t buf[1];
  ulong page  = fd_accdb_idx_home( r, rec->pubkey, rec->fork_id, seed );
  ulong epage = ULONG_MAX;
  for( ulong probe=0UL; probe<FD_ACCDB_IDX_PROBE_MAX; probe++ ) {
    fd_accdb_idx_page_read_raw( r, page, buf );
    fd_accdb_idx_slot_t * s = fd_accdb_idx_page_find( r, buf, rec->pubkey, rec->fork_id );
    if( s ) {
      *old = *s;
      *s   = *rec;
      fd_accdb_idx_page_write( r, page, buf );
      return 1;
    }
    if( epage==ULONG_MAX ) {
      if( buf->cnt<FD_ACCDB_IDX_SLOT_CNT ) epage = page;
      else if( !(buf->flags & FD_ACCDB_IDX_OVERFLOWED) ) {
        buf->flags |= FD_ACCDB_IDX_OVERFLOWED;
        fd_accdb_idx_page_write( r, page, buf );
      }
    }
    if( FD_LIKELY( !(buf->flags & FD_ACCDB_IDX_OVERFLOWED) ) ) break;
    page = page+1UL==r->npage ? 0UL : page+1UL;
  }
  if( FD_UNLIKELY( epage==ULONG_MAX ) ) FD_LOG_ERR(( "accounts index region over-full" ));
  fd_accdb_idx_page_read_raw( r, epage, buf );
  for( ulong i=0UL; i<FD_ACCDB_IDX_SLOT_CNT; i++ ) {
    if( buf->slot[ i ].off_plus1 ) continue;
    buf->slot[ i ] = *rec;
    buf->cnt++;
    fd_accdb_idx_page_write( r, epage, buf );
    return 0;
  }
  FD_LOG_CRIT(( "page cnt out of sync" ));
}

/* fd_accdb_idx_delete (writer only): removes the slot iff its
   generation < gen_lt.  Returns 1 and fills *old on delete. */

static inline int
fd_accdb_idx_delete( fd_accdb_idx_region_t const * r,
                     ulong                         seed,
                     uchar const                   pubkey[ 32 ],
                     ushort                        fork_id,
                     uint                          gen_lt,
                     fd_accdb_idx_slot_t *         old ) {
  fd_accdb_idx_page_t buf[1];
  ulong page = fd_accdb_idx_home( r, pubkey, fork_id, seed );
  for( ulong probe=0UL; probe<FD_ACCDB_IDX_PROBE_MAX; probe++ ) {
    fd_accdb_idx_page_read_raw( r, page, buf );
    fd_accdb_idx_slot_t * s = fd_accdb_idx_page_find( r, buf, pubkey, fork_id );
    if( s ) {
      if( FD_UNLIKELY( s->generation>=gen_lt ) ) return 0;
      *old = *s;
      memset( s, 0, sizeof(fd_accdb_idx_slot_t) );
      buf->cnt--;
      fd_accdb_idx_page_write( r, page, buf );
      return 1;
    }
    if( FD_LIKELY( !(buf->flags & FD_ACCDB_IDX_OVERFLOWED) ) ) return 0;
    page = page+1UL==r->npage ? 0UL : page+1UL;
  }
  return 0;
}

/* fd_accdb_idx_resync (writer only): repoint pubkey's slot from
   off_plus1 src to dst.  Returns 0 if the slot no longer names src. */

static inline int
fd_accdb_idx_resync( fd_accdb_idx_region_t const * r,
                     ulong                         seed,
                     uchar const                   pubkey[ 32 ],
                     ushort                        fork_id,
                     ulong                         src_plus1,
                     ulong                         dst_plus1 ) {
  fd_accdb_idx_page_t buf[1];
  ulong page = fd_accdb_idx_home( r, pubkey, fork_id, seed );
  for( ulong probe=0UL; probe<FD_ACCDB_IDX_PROBE_MAX; probe++ ) {
    fd_accdb_idx_page_read_raw( r, page, buf );
    fd_accdb_idx_slot_t * s = fd_accdb_idx_page_find( r, buf, pubkey, fork_id );
    if( s ) {
      if( s->off_plus1!=src_plus1 ) return 0;
      s->off_plus1 = dst_plus1;
      fd_accdb_idx_page_write( r, page, buf );
      return 1;
    }
    if( FD_LIKELY( !(buf->flags & FD_ACCDB_IDX_OVERFLOWED) ) ) return 0;
    page = page+1UL==r->npage ? 0UL : page+1UL;
  }
  return 0;
}

/* Cuckoo filter.  cf_seq: even = no kick in flight.  stash entries are
   (bucket<<16)|fp, 0 = empty.  disabled: every probe answers maybe. */

struct fd_accdb_cf {
  ulong * cf;
  ulong   nb;
  ulong   seed;
  ulong * seq;       /* shmem, own cache line */
  ulong * stash;     /* FD_ACCDB_CF_STASH_MAX */
  ulong * stash_cnt;
  ulong * disabled;
};

typedef struct fd_accdb_cf fd_accdb_cf_t;

static inline void
fd_accdb_cf_key( fd_accdb_cf_t const * f,
                 uchar const           pubkey[ 32 ],
                 ulong *               i1,
                 ulong *               i2,
                 ulong *               fp ) {
  ulong h  = fd_hash32( pubkey, f->seed^FD_ACCDB_IDX_SALT_CF );
  ulong p  = (h&0xFFFFUL) ? (h&0xFFFFUL) : 1UL; /* low bits: fastrange uses the high ones */
  ulong b1 = fd_accdb_idx_fastrange( h, f->nb );
  ulong hf = fd_accdb_idx_fastrange( fd_ulong_hash( p ), f->nb );
  *i1 = b1;
  *i2 = ( hf + f->nb - b1 ) % f->nb;
  *fp = p;
}

static inline ulong
fd_accdb_cf_alt( fd_accdb_cf_t const * f,
                 ulong                 b,
                 ulong                 fp ) {
  ulong hf = fd_accdb_idx_fastrange( fd_ulong_hash( fp ), f->nb );
  return ( hf + f->nb - b ) % f->nb;
}

static inline int
fd_accdb_cf_word_has( ulong w,
                      ulong fp ) {
  for( ulong l=0UL; l<FD_ACCDB_CF_LANES; l++ ) if( ((w>>(16UL*l))&0xFFFFUL)==fp ) return 1;
  return 0;
}

/* fd_accdb_cf_probe: 1 = maybe present, 0 = absent (no false
   negatives for keys inserted and not deleted). */

static inline int
fd_accdb_cf_probe( fd_accdb_cf_t const * f,
                   uchar const           pubkey[ 32 ] ) {
  if( FD_UNLIKELY( FD_VOLATILE_CONST( *f->disabled ) ) ) return 1;
  ulong i1, i2, fp;
  fd_accdb_cf_key( f, pubkey, &i1, &i2, &fp );
  for(;;) {
    ulong s = FD_VOLATILE_CONST( *f->seq );
    if( FD_UNLIKELY( s&1UL ) ) { FD_SPIN_PAUSE(); continue; }
    FD_COMPILER_MFENCE();
    if( fd_accdb_cf_word_has( FD_VOLATILE_CONST( f->cf[ i1 ] ), fp ) ) return 1;
    if( fd_accdb_cf_word_has( FD_VOLATILE_CONST( f->cf[ i2 ] ), fp ) ) return 1;
    if( FD_UNLIKELY( FD_VOLATILE_CONST( *f->stash_cnt ) ) ) {
      for( ulong k=0UL; k<FD_ACCDB_CF_STASH_MAX; k++ ) {
        ulong e = FD_VOLATILE_CONST( f->stash[ k ] );
        if( e && (e&0xFFFFUL)==fp && ( (e>>16)==i1 || (e>>16)==i2 ) ) return 1;
      }
    }
    FD_COMPILER_MFENCE();
    if( FD_LIKELY( FD_VOLATILE_CONST( *f->seq )==s ) ) return 0;
  }
}

static inline int
fd_accdb_cf_free_lane( ulong w ) {
  for( ulong l=0UL; l<FD_ACCDB_CF_LANES; l++ ) if( !((w>>(16UL*l))&0xFFFFUL) ) return (int)l;
  return -1;
}

static inline ulong
fd_accdb_cf_set_lane( ulong w,
                      ulong l,
                      ulong fp ) {
  return ( w & ~(0xFFFFUL<<(16UL*l)) ) | ( fp<<(16UL*l) );
}

/* fd_accdb_cf_insert (writer only).  rng picks kick lanes. */

static inline void
fd_accdb_cf_insert( fd_accdb_cf_t * f,
                    uchar const     pubkey[ 32 ],
                    ulong *         rng ) {
  if( FD_UNLIKELY( *f->disabled ) ) return;
  ulong i1, i2, fp;
  fd_accdb_cf_key( f, pubkey, &i1, &i2, &fp );
  ulong bs[ 2 ] = { i1, i2 };
  for( ulong k=0UL; k<2UL; k++ ) {
    int l = fd_accdb_cf_free_lane( f->cf[ bs[ k ] ] );
    if( l>=0 ) { FD_VOLATILE( f->cf[ bs[ k ] ] ) = fd_accdb_cf_set_lane( f->cf[ bs[ k ] ], (ulong)l, fp ); return; }
  }

  /* Compute the kick path without mutating: path[j] is the bucket and
     lane whose occupant moves to path[j+1].  Abort a walk that revisits
     a bucket. */
  ulong pb[ FD_ACCDB_CF_KICK_MAX+1UL ];
  ulong pl[ FD_ACCDB_CF_KICK_MAX+1UL ];
  ulong pf[ FD_ACCDB_CF_KICK_MAX+1UL ]; /* fingerprint placed into pb[j] */
  for( ulong attempt=0UL; attempt<4UL; attempt++ ) {
    *rng = fd_ulong_hash( *rng+0x9E3779B97F4A7C15UL );
    ulong b  = bs[ *rng&1UL ];
    ulong cf = fp;
    ulong n  = 0UL;
    int   ok = 0;
    for( ; n<FD_ACCDB_CF_KICK_MAX; n++ ) {
      int dup = 0;
      for( ulong j=0UL; j<n; j++ ) if( pb[ j ]==b ) { dup = 1; break; }
      if( dup ) break;
      *rng = fd_ulong_hash( *rng+1UL );
      ulong l      = *rng % FD_ACCDB_CF_LANES;
      ulong victim = (f->cf[ b ]>>(16UL*l)) & 0xFFFFUL;
      pb[ n ] = b; pl[ n ] = l; pf[ n ] = cf;
      ulong nb2 = fd_accdb_cf_alt( f, b, victim );
      int   fl  = fd_accdb_cf_free_lane( f->cf[ nb2 ] );
      int   dup2 = 0;
      for( ulong j=0UL; j<=n; j++ ) if( pb[ j ]==nb2 ) { dup2 = 1; break; }
      if( fl>=0 && !dup2 ) {
        n++;
        pb[ n ] = nb2; pl[ n ] = (ulong)fl; pf[ n ] = victim;
        ok = 1;
        break;
      }
      cf = victim;
      b  = nb2;
    }
    if( !ok ) continue;
    FD_VOLATILE( *f->seq ) = *f->seq+1UL;
    FD_COMPILER_MFENCE();
    for( ulong j=n+1UL; j>0UL; j-- ) {
      ulong k = j-1UL;
      FD_VOLATILE( f->cf[ pb[ k ] ] ) = fd_accdb_cf_set_lane( f->cf[ pb[ k ] ], pl[ k ], pf[ k ] );
    }
    FD_COMPILER_MFENCE();
    FD_VOLATILE( *f->seq ) = *f->seq+1UL;
    return;
  }

  /* No path: stash the new key itself (single store). */
  for( ulong k=0UL; k<FD_ACCDB_CF_STASH_MAX; k++ ) {
    if( f->stash[ k ] ) continue;
    FD_VOLATILE( *f->stash_cnt ) = *f->stash_cnt+1UL;
    FD_COMPILER_MFENCE();
    FD_VOLATILE( f->stash[ k ] ) = (i1<<16) | fp;
    return;
  }
  FD_LOG_WARNING(( "accdb cuckoo filter stash full, disabling the filter" ));
  FD_VOLATILE( *f->disabled ) = 1UL;
}

/* fd_accdb_cf_delete (writer only): removes one copy of the key's
   fingerprint.  Only for keys known to be inserted. */

static inline void
fd_accdb_cf_delete( fd_accdb_cf_t * f,
                    uchar const     pubkey[ 32 ] ) {
  if( FD_UNLIKELY( *f->disabled ) ) return;
  ulong i1, i2, fp;
  fd_accdb_cf_key( f, pubkey, &i1, &i2, &fp );
  ulong bs[ 2 ] = { i1, i2 };
  for( ulong k=0UL; k<2UL; k++ ) {
    ulong w = f->cf[ bs[ k ] ];
    for( ulong l=0UL; l<FD_ACCDB_CF_LANES; l++ ) {
      if( ((w>>(16UL*l))&0xFFFFUL)!=fp ) continue;
      FD_VOLATILE( f->cf[ bs[ k ] ] ) = fd_accdb_cf_set_lane( w, l, 0UL );
      return;
    }
  }
  for( ulong k=0UL; k<FD_ACCDB_CF_STASH_MAX; k++ ) {
    ulong e = f->stash[ k ];
    if( !e || (e&0xFFFFUL)!=fp || ( (e>>16)!=i1 && (e>>16)!=i2 ) ) continue;
    FD_VOLATILE( f->stash[ k ] ) = 0UL;
    FD_COMPILER_MFENCE();
    FD_VOLATILE( *f->stash_cnt ) = *f->stash_cnt-1UL;
    return;
  }
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_idx_h */
