#define _GNU_SOURCE   /* pwritev (see fd_gui_store_tmpl.c) */

#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdlib.h>
#include <string.h>
#include <sys/mman.h> /* memfd_create        */
#include <unistd.h>   /* ftruncate / close   */

#include "../fd_disco.h"
#include "../../util/sanitize/fd_fuzz.h"

/* Instantiate the keyed store with the (slot, block_id) composite key
   from the template's header docs, exactly as test_gui_store.c does. */

struct myrec_key {
  ulong slot;
  ulong block_id;
};
typedef struct myrec_key myrec_key_t;

#define GUI_STORE_NAME             myrec_store
#define GUI_STORE_KEY_T            myrec_key_t
#define GUI_STORE_KEY_HASH(k,seed) fd_ulong_hash( (k)->slot ^ \
                                     fd_ulong_rotate_left( (k)->block_id, 32 ) ^ (seed) )
#define GUI_STORE_KEY_EQ(k0,k1)    ( ((k0)->slot==(k1)->slot) & \
                                     ((k0)->block_id==(k1)->block_id) )
#include "fd_gui_store_tmpl.c"

/* Bounded key space so collisions, dup-insert rejection and key reuse
   after eviction all occur frequently.  KEY_CNT keys total. */

#define KEY_SLOTS  (4UL)
#define KEY_BLOCKS (8UL)
#define KEY_CNT    (KEY_SLOTS*KEY_BLOCKS)

#define MAX_OPS     (4096UL)
#define MAX_CACHE   (8192UL)

static uchar shmem[ 1UL<<20 ] __attribute__((aligned(4096UL)));

/* Byte-stream reader.  When the fuzz input is exhausted, fall back to a
   seeded LCG so short inputs still drive long op sequences. */

typedef struct {
  uchar const * data;
  ulong         data_sz;
  ulong         off;
  ulong         salt;
} reader_t;

static uchar
read_uchar( reader_t * r ) {
  if( FD_LIKELY( r->off<r->data_sz ) ) return r->data[ r->off++ ];
  r->salt = 6364136223846793005UL*r->salt + 1442695040888963407UL;
  return (uchar)( r->salt >> 56 );
}

static ulong
read_range( reader_t * r, ulong max ) {
  if( FD_UNLIKELY( !max ) ) return 0UL;
  return (ulong)read_uchar( r ) % max;
}

/* Reference model: per key, what we believe is stored and its value
   pattern id.  The value bytes are deterministic given (key, pat, sz). */

typedef struct {
  int   present;
  ulong sz;
  ulong align;
  uchar pat;
} model_t;

static void
key_of( myrec_key_t * k, ulong idx ) {
  k->slot     = idx / KEY_BLOCKS;
  k->block_id = idx % KEY_BLOCKS;
}

static void
fill( uchar * buf, myrec_key_t const * key, ulong sz, uchar pat ) {
  for( ulong i=0UL; i<sz; i++ ) {
    buf[ i ] = (uchar)( key->slot*31UL + key->block_id*7UL + i + pat*131UL );
  }
}

static int
check( uchar const * buf, myrec_key_t const * key, ulong sz, uchar pat ) {
  for( ulong i=0UL; i<sz; i++ ) {
    if( buf[ i ]!=(uchar)( key->slot*31UL + key->block_id*7UL + i + pat*131UL ) ) return 0;
  }
  return 1;
}

static int
tmpfile_fd( ulong len ) {
  int fd = memfd_create( "fuzz_gui_store", 0U );
  FD_TEST( fd>=0 );
  FD_TEST( !ftruncate( fd, (long)len ) );
  return fd;
}

/* footprint-with-header of a value: this is what must fit in cache_sz
   for an append to be guaranteed to succeed. */

static ulong
msg_fp( ulong align, ulong footprint ) {
  return fd_ulong_align_up( sizeof(myrec_store_msghdr_t), align ) + footprint;
}

static void
run_case( uchar const * data, ulong size ) {
  reader_t r[1] = {{ .data=data, .data_sz=size, .off=0UL, .salt=0x243f6a8885a308d3UL }};

  ulong const aligns[] = { 1UL,2UL,4UL,8UL,16UL,32UL,64UL };

  ulong ele_max  = 1UL << ( 1UL + read_range( r, 5UL ) );    /* {2,4,8,16,32} */
  ulong cache_sz = 512UL + read_range( r, MAX_CACHE-512UL ); /* [512, 8192)   */
  ulong seed     = (ulong)read_uchar( r );
  int   file_bk  = (int)read_range( r, 2UL );

  if( FD_UNLIKELY( myrec_store_footprint( ele_max, cache_sz, 0UL )>sizeof(shmem) ) ) return;

  int   fd       = -1;
  ulong file_len = 0UL;
  if( file_bk ) {
    /* file_len in [min, min + cache_sz*8): enough to force disk FIFO
       eviction during a long run. */
    ulong fmin = myrec_store_file_len_min( cache_sz );
    file_len   = fmin + read_range( r, cache_sz*8UL );
    file_len   = fd_ulong_align_up( file_len, 8UL );
    if( FD_UNLIKELY( myrec_store_footprint( ele_max, cache_sz, file_len )==0UL ) ) return;
    fd = tmpfile_fd( file_len );
  }

  myrec_store_t * store = myrec_store_join(
      myrec_store_new( shmem, ele_max, cache_sz, seed, 0UL, file_len ), fd );
  FD_TEST( store );
  FD_TEST( !myrec_store_verify( store ) );

  model_t model[ KEY_CNT ];
  memset( model, 0, sizeof(model) );

  ulong nops = read_range( r, MAX_OPS )+1UL;
  for( ulong op=0UL; op<nops; op++ ) {
    ulong       which = read_range( r, 16UL );
    ulong       kidx  = read_range( r, KEY_CNT );
    myrec_key_t key; key_of( &key, kidx );

    if( which<7UL ) { /* APPEND */
      ulong align = aligns[ read_range( r, sizeof(aligns)/sizeof(aligns[0]) ) ];

      /* Bias footprint toward boundaries of cache_sz. */
      ulong footprint;
      switch( read_range( r, 8UL ) ) {
        case 0:  footprint = 0UL;                             break;
        case 1:  footprint = 1UL;                             break;
        case 2:  footprint = 8UL;                             break;
        case 3:  footprint = cache_sz;                        break; /* exact -> reject */
        case 4:  footprint = cache_sz+read_range(r,256UL);    break; /* oversize -> reject */
        default: footprint = read_range( r, cache_sz );       break;
      }

      /* Confirm the store's view of the key before appending so a NULL
         result can be attributed: the model's present flag is optimistic
         (a key may have been silently evicted), but get_ro is ground
         truth. */
      int really_present = !!myrec_store_get_ro( store, &key, NULL );
      model[ kidx ].present = really_present;

      uchar * v = myrec_store_append( store, &key, align, footprint );

      if( v ) {
        /* Success implies the key was absent and the value fit. */
        FD_TEST( !really_present );
        FD_TEST( msg_fp( align, footprint )<=cache_sz );
        uchar pat = (uchar)read_uchar( r );
        fill( v, &key, footprint, pat );
        model[ kidx ] = (model_t){ .present=1, .sz=footprint, .align=align, .pat=pat };
      } else {
        /* A NULL append is legal for three reasons: the key is already
           present (dup), the value cannot fit the cache, or the bounded
           index could not seat the key even after evicting its oldest. */
        if( really_present ) {
          /* dup: the existing entry must be untouched */
          FD_TEST( myrec_store_get_ro( store, &key, NULL ) );
        } else {
          /* a failed insert never leaves a partial entry */
          FD_TEST( !myrec_store_get_ro( store, &key, NULL ) );
          model[ kidx ].present = 0;
        }
      }

    } else if( which<11UL ) { /* GET_RO */
      ulong         sz = ~0UL;
      uchar const * g  = myrec_store_get_ro( store, &key, &sz );
      if( g ) {
        FD_TEST( model[ kidx ].present );
        FD_TEST( sz==model[ kidx ].sz );
        FD_TEST( check( g, &key, sz, model[ kidx ].pat ) );
      } else {
        /* NULL is only legal if the key was evicted; downgrade model. */
        model[ kidx ].present = 0;
      }

    } else if( which<14UL ) { /* GET_MUT (+ optional rewrite) */
      ulong   sz = ~0UL;
      uchar * g  = myrec_store_get_mut( store, &key, &sz );
      if( g ) {
        FD_TEST( model[ kidx ].present );
        FD_TEST( sz==model[ kidx ].sz );
        FD_TEST( check( g, &key, sz, model[ kidx ].pat ) );
        if( read_range( r, 2UL ) ) { /* rewrite in place; must persist */
          uchar pat = (uchar)read_uchar( r );
          fill( g, &key, sz, pat );
          model[ kidx ].pat = pat;
        }
      } else {
        model[ kidx ].present = 0;
      }

    } else { /* PRE_EVICT */
      myrec_store_pre_evict( store );
    }

    FD_TEST( !myrec_store_verify( store ) );
    FD_TEST( store->live_cnt<=store->ele_max );
    FD_TEST( fd_circq_bytes_used( store->circq )<=store->cache_sz );
  }

  /* Final pass: every key the model still believes is present must read
     back with the correct size and bytes (eviction only ever produces
     NULL, never corruption or resurrection of stale data). */
  for( ulong kidx=0UL; kidx<KEY_CNT; kidx++ ) {
    myrec_key_t key; key_of( &key, kidx );
    ulong         sz = ~0UL;
    uchar const * g  = myrec_store_get_ro( store, &key, &sz );
    if( g ) {
      FD_TEST( model[ kidx ].present );
      FD_TEST( sz==model[ kidx ].sz );
      FD_TEST( check( g, &key, sz, model[ kidx ].pat ) );
    }
  }

  FD_TEST( !myrec_store_verify( store ) );
  FD_TEST( myrec_store_leave( store )==(void *)store );
  FD_TEST( myrec_store_delete( shmem )==shmem );
  if( fd>=0 ) FD_TEST( !close( fd ) );
}

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  /* Keep FD_LOG_WARNING (used for expected rejections in the template)
     non-fatal; FD_LOG_ERR (genuine internal impossibilities) still
     aborts. */
  fd_log_level_core_set( 3 );
  atexit( fd_halt );
  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  run_case( data, size );
  return 0;
}
