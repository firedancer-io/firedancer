#include "../../../ballet/hex/fd_hex.h"
#include "../../../ballet/sha256/fd_sha256.h"
#include "../../../tango/fd_tango.h"
#include "../../../util/fd_util.h"
#include "../../../util/tile/fd_tile_private.h"

#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>

#define ZSTD_WINDOW_SZ_MAX (1UL<<25UL) /* 32MiB */

#define MTU       (4096UL)
#define CHUNK_MTU (((MTU + 2UL*FD_CHUNK_SZ-1UL) >> (1+FD_CHUNK_LG_SZ)) << 1)

#define C_DEPTH ( 256UL)
#define D_DEPTH (2048UL)

#define DECOMP_FRAGS_MAX (ZSTD_BLOCKSIZE_MAX / MTU)

#define SHA256 1

#define CPU_BASE (10UL)

struct ctx {
  char const * fname;
  ulong        fsize;
  void *       wksp;
  ZSTD_DCtx *  zstd;

  fd_frag_meta_t * cm;
  fd_frag_meta_t * dm;
  uchar          * cd;
  uchar          * dd;
  ulong          * cf;
  ulong          * df;
};
typedef struct ctx ctx_t;

/* Reads the input file into the compressed data dcache.  Although we
   write frags in MTU chunks, we actually do the read() call with
   multiple MTU chunks at a time, based on how many credits we have
   from flow control and how many frags we can write contiguously.  The
   resulting byte stream is fully contiguous except for exactly one break
   when we wrap to the beginning of the dcache. */
void *
run_ld( void * _ctx ) {
  FD_CPUSET_DECL( cpu_set );
  fd_cpuset_insert( cpu_set, CPU_BASE+0UL );
  FD_TEST( !fd_cpuset_setaffinity( 0, cpu_set ) );
  FD_TEST( !prctl( PR_SET_NAME, "ld", 0, 0, 0 ) );

  FD_LOG_NOTICE(( "running ld thread" ));

  ctx_t * ctx = (ctx_t *)_ctx;

  struct stat st;
  FD_TEST( -1!=stat( ctx->fname, &st ) );
  FD_TEST( S_ISREG( st.st_mode ) );
  ctx->fsize = (ulong)st.st_size;

  int file_fd = open( ctx->fname, O_RDONLY|O_CLOEXEC|O_NONBLOCK );
  FD_TEST( -1!=file_fd );

  ulong const chunk0 = fd_dcache_compact_chunk0( ctx->wksp, ctx->cd );
  ulong const chunk1 = fd_dcache_compact_chunk1( ctx->wksp, ctx->cd );
  ulong const wmark  = fd_dcache_compact_wmark ( ctx->wksp, ctx->cd, MTU );
  FD_TEST( fd_dcache_compact_is_safe( ctx->wksp, ctx->cd, MTU, C_DEPTH ) );

  ulong seq      = fd_mcache_seq0( ctx->cm ); /* next mcache seq we will publish */
  ulong chunk    = chunk0;                    /* next dcache chunk we will publish */
  ulong offset   = 0UL;                       /* bytes in next chunk we've already read */
  ulong cons_seq = fd_fseq_query( ctx->cf );  /* cached value of consumer fseq */
  ulong read_sz  = 0UL;                       /* total compressed bytes read */

  while( FD_LIKELY( read_sz<ctx->fsize ) ) {
    /* Figure out how many contiguous bytes (frags * MTU) we can read()
       without overrunning the consumer. */
    ulong cred_avail = (ulong)fd_long_max( (long)C_DEPTH - fd_long_max( fd_seq_diff( seq, cons_seq ), 0L ), 0L );
    if( FD_UNLIKELY( cred_avail<4UL ) ) {
      FD_TEST( !offset );
      cons_seq = fd_fseq_query( ctx->cf );
      continue;
    }
    ulong frag_avail = (chunk1-chunk)/CHUNK_MTU;
    ulong frag_read  = fd_ulong_min( cred_avail, frag_avail );
    FD_TEST( frag_read>0UL );

    /* Read as many bytes as we can into the dcache */
    uchar * out = fd_chunk_to_laddr( ctx->wksp, chunk );
    long result = read( file_fd, out+offset, (frag_read*MTU)-offset );
    if( FD_UNLIKELY( result<=0L ) ) FD_LOG_ERR(( "read() failed %ld (%i-%s)", result, errno, fd_io_strerror( errno ) ));
    read_sz += (ulong)result;

    /* Publish frags with MTU granularity. Leave the tail (<MTU)
       unpublished, unless it is at the end of the buffer in which
       case we need to flush an undersized MTU. */
    offset += (ulong)result;
    while( FD_LIKELY( offset>=MTU ) ) {
      FD_TEST( chunk<=wmark );
      fd_mcache_publish( ctx->cm, C_DEPTH, seq, 0UL, chunk, MTU, 0UL, 0UL, 0UL );
      seq = fd_seq_inc( seq, 1UL );
      chunk += CHUNK_MTU;
      offset -= MTU;
    }
    if( FD_UNLIKELY( chunk>wmark ) ) {
      FD_TEST( offset==0UL );
      chunk = chunk0;
    } else if( FD_UNLIKELY( chunk==wmark && offset!=0UL ) ) {
      fd_mcache_publish( ctx->cm, C_DEPTH, seq, 0UL, chunk, offset, 0UL, 0UL, 0UL );
      seq = fd_seq_inc( seq, 1UL );
      chunk = chunk0;
      offset = 0UL;
    }
  }

  /* Flush any remaining tail of data at the end of the file */
  if( FD_LIKELY( offset ) ) {
    FD_TEST( offset<MTU );
    FD_TEST( chunk<=wmark );
    fd_mcache_publish( ctx->cm, C_DEPTH, seq, 0UL, chunk, offset, 0UL, 0UL, 0UL );
  }

  /* Make sure the file is actually finished and close it */
  uchar tmp[ 64 ];
  FD_TEST( 0L==read( file_fd, tmp, sizeof(tmp) ) );
  close( file_fd );

  FD_LOG_NOTICE(( "exiting ld thread read_sz %lu", read_sz ));

  return NULL;
}

void *
run_dc( void * _ctx ) {
  FD_CPUSET_DECL( cpu_set );
  fd_cpuset_insert( cpu_set, CPU_BASE+1UL );
  FD_TEST( !fd_cpuset_setaffinity( 0, cpu_set ) );
  FD_TEST( !prctl( PR_SET_NAME, "dc", 0, 0, 0 ) );

  FD_LOG_NOTICE(( "running dc thread" ));

  ctx_t * ctx = (ctx_t *)_ctx;

  /* Chunk indices for output dcache */
  ulong const ochunk0 = fd_dcache_compact_chunk0( ctx->wksp, ctx->dd );
  ulong const ochunk1 = fd_dcache_compact_chunk1( ctx->wksp, ctx->dd );
  ulong const owmark  = fd_dcache_compact_wmark ( ctx->wksp, ctx->dd, MTU );
  FD_TEST( fd_dcache_compact_is_safe( ctx->wksp, ctx->dd, MTU, D_DEPTH ) );

  ulong oseq      = fd_mcache_seq0( ctx->dm ); /* next mcache seq we will publish */
  ulong ochunk    = ochunk0;                   /* next dcache chunk we will publish */
  ulong ooff      = 0UL;                       /* bytes of next output frag zstd has already written */
  ulong iseq      = fd_fseq_query( ctx->cf );  /* current input mcache seq we are reading */
  ulong ioff      = 0UL;                       /* bytes of current input frag that we've already given to zstd */
  ulong cons_seq  = fd_fseq_query( ctx->df );  /* cached value of consumer fseq */
  ulong decomp_sz = 0UL;                       /* total decompressed bytes size */

  for(;;) {
    ulong cred_avail = (ulong)fd_long_max( (long)D_DEPTH - fd_long_max( fd_seq_diff( oseq, cons_seq ), 0L ), 0L );
    if( FD_UNLIKELY( cred_avail<DECOMP_FRAGS_MAX ) ) {
      cons_seq = fd_fseq_query( ctx->df );
      continue;
    }
    ulong frag_avail = (ochunk1-ochunk)/CHUNK_MTU;
    ulong frag_out   = fd_ulong_min( cred_avail, frag_avail );
    FD_TEST( frag_out>0UL );
    //FD_LOG_NOTICE(( "[%lu,%lu,%lu] frag_out %lu", ochunk0, ochunk, ochunk1, frag_out ));

    /* Speculatively consume input frags so that we can pass a large
       (>MTU) contiguous region of compressed data to ZSTD. */
    ulong schunk = ULONG_MAX; /* where we should start reading */
    ulong sz     = 0UL;       /* how many bytes we should read */
    ulong niseq = iseq;       /* where we should stop processing */
    for(;;) {
      ulong idx = (ulong)fd_seq_diff( niseq, iseq );
      if( FD_UNLIKELY( idx>=DECOMP_FRAGS_MAX ) ) break;
      fd_frag_meta_t         meta[1];
      fd_frag_meta_t const * mline;
      ulong                  poll_max = fd_ulong_if( idx==0UL, ULONG_MAX, 1UL );
      ulong                  tx_seq;
      long                   seq_diff;
      FD_MCACHE_WAIT( meta, mline, tx_seq, seq_diff, poll_max, ctx->cm, C_DEPTH, niseq );
      (void)tx_seq;
      (void)mline;
      if( FD_UNLIKELY( seq_diff ) ) break;
      if( idx==0UL ) {
        schunk = meta->chunk;
      } else {
        if( FD_UNLIKELY( meta->chunk<schunk ) ) break; /* dcache wrap */
      }
      sz += meta->sz;
      niseq = fd_seq_inc( niseq, 1UL );
    }
    FD_TEST( niseq!=iseq );

    /* We now have sz bytes of compressed data starting at schunk. ioff
       bytes of that has already been given to ZSTD. */
    FD_TEST( ioff<MTU );
    ZSTD_inBuffer zin = {
      .src = fd_chunk_to_laddr_const( ctx->wksp, schunk ),
      .size = sz,
      .pos = ioff
    };
    ZSTD_outBuffer zout = {
      .dst = fd_chunk_to_laddr( ctx->wksp, ochunk ),
      .size = frag_out*MTU,
      .pos = ooff
    };
    ulong rc = ZSTD_decompressStream( ctx->zstd, &zout, &zin );
    if( FD_UNLIKELY( ZSTD_isError( rc ) ) ) FD_LOG_ERR(( "ZSTD_decompressStream failed (%lu-%s)", rc, ZSTD_getErrorName( rc ) ));
    decomp_sz += (zout.pos-ooff);

    ioff = zin.pos % MTU;
    iseq = fd_seq_inc( iseq, zin.pos / MTU );
    fd_fseq_update( ctx->cf, iseq );

    /* Publish frags with MTU granularity. Leave the tail (<MTU)
       unpublished, unless it is at the end of the buffer in which
       case we need to flush an undersized MTU. */
    ooff = zout.pos;
    while( FD_LIKELY( ooff>=MTU ) ) {
      FD_TEST( ochunk<=owmark );
      fd_mcache_publish( ctx->dm, D_DEPTH, oseq, 0UL, ochunk, MTU, 0UL, 0UL, 0UL );
      oseq = fd_seq_inc( oseq, 1UL );
      ochunk += CHUNK_MTU;
      ooff -= MTU;
    }
    if( FD_UNLIKELY( ochunk>owmark ) ) {
      FD_TEST( ooff==0UL );
      ochunk = ochunk0;
    } else if( FD_UNLIKELY( ochunk==owmark && ooff!=0UL ) ) {
      fd_mcache_publish( ctx->dm, D_DEPTH, oseq, 0UL, ochunk, ooff, 0UL, 0UL, 0UL );
      oseq = fd_seq_inc( oseq, 1UL );
      ochunk = ochunk0;
      ooff = 0;
    }

    if( FD_UNLIKELY( rc==0UL ) ) {
      /* Flush any remaining tail of data at the end of the file */
      if( FD_LIKELY( ooff ) ) {
        FD_TEST( ooff<MTU );
        FD_TEST( ochunk<=owmark );
        fd_mcache_publish( ctx->dm, D_DEPTH, oseq, 0UL, ochunk, ooff, 0UL, 0UL, 0UL );
        oseq = fd_seq_inc( oseq, 1UL );
      }
      break;
    }
  }

  for(;;) {
    ulong cred_avail = (ulong)fd_long_max( (long)D_DEPTH - fd_long_max( fd_seq_diff( oseq, fd_fseq_query( ctx->df ) ), 0L ), 0L );
    if( FD_UNLIKELY( cred_avail==0UL ) ) { continue; }
    fd_mcache_publish( ctx->dm, D_DEPTH, oseq, 1UL, 0UL, 0UL, 0UL, 0UL, 0UL );
    break;
  }

  FD_LOG_NOTICE(( "exiting dc thread decomp_sz %lu", decomp_sz ));

  return NULL;
}

void *
run_ck( void * _ctx ) {
  FD_CPUSET_DECL( cpu_set );
  fd_cpuset_insert( cpu_set, CPU_BASE+2UL );
  FD_TEST( !fd_cpuset_setaffinity( 0, cpu_set ) );
  FD_TEST( !prctl( PR_SET_NAME, "ck", 0, 0, 0 ) );

  FD_LOG_NOTICE(( "running ck thread" ));

  ctx_t * ctx = (ctx_t *)_ctx;

#if SHA256
  fd_sha256_t   _sha[1];
  fd_sha256_t * sha = fd_sha256_init( fd_sha256_join( fd_sha256_new( _sha ) ) );
#endif

  ulong  tot_sz = 0UL;
  ulong  seq    = fd_fseq_query( ctx->df );
  uchar  check  = 0UL;

  for(;;) {
    fd_frag_meta_t         meta[1];
    fd_frag_meta_t const * mline;
    ulong                  poll_max = ULONG_MAX;
    ulong                  tx_seq;
    long                   seq_diff;
    FD_MCACHE_WAIT( meta, mline, tx_seq, seq_diff, poll_max, ctx->dm, D_DEPTH, seq );
    (void)tx_seq;
    (void)mline;

    FD_TEST( !seq_diff );

    if( FD_UNLIKELY( meta->sig==1UL ) ) break;

#if SHA256
    fd_sha256_append( sha, fd_chunk_to_laddr_const( ctx->wksp, meta->chunk ), meta->sz );
#endif

    uchar const * data = fd_chunk_to_laddr_const( ctx->wksp, meta->chunk );
    ulong const   cnt  = meta->sz / sizeof(check);
    for( ulong i=0UL; i<cnt; i++) check ^= data[ i ];

    tot_sz += meta->sz;

    seq = fd_seq_inc( seq, 1UL );
    fd_fseq_update( ctx->df, seq );
  }

#if SHA256
  uchar hash[ 32 ];
  FD_TEST( hash==fd_sha256_fini( sha, hash ) );

  char hex[ 64+1 ];
  fd_hex_encode( hex, hash, 32 );
  hex[ 64 ] = '\0';
  FD_LOG_NOTICE(( "exiting ck thread tot_sz %lu check %hhu sha256(%s)", tot_sz, check, hex ));
#else
  FD_LOG_NOTICE(( "exiting ck thread tot_sz %lu check %hhu", tot_sz, check ));
#endif

  return NULL;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_TEST( -1!=setpriority( PRIO_PROCESS, 0, -19 ) );

  ulong       page_cnt  = 1;
  char *      _page_sz  = "gigantic";
  ulong       numa_idx  = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp      = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  ulong const csz = fd_dcache_req_data_sz( MTU, C_DEPTH, 1UL, 1 );
  ulong const dsz = fd_dcache_req_data_sz( MTU, D_DEPTH, 1UL, 1 );

  void *  _ctx  = fd_wksp_alloc_laddr( wksp, 64UL,              sizeof(ctx_t),                                  1UL );
  void *  _zstd = fd_wksp_alloc_laddr( wksp, 32UL,              ZSTD_estimateDStreamSize( ZSTD_WINDOW_SZ_MAX ), 1UL );
  void *  _cm   = fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( C_DEPTH, 0UL ),            1UL );
  void *  _dm   = fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( D_DEPTH, 0UL ),            1UL );
  void *  _cd   = fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( csz, 0UL ),                1UL );
  void *  _dd   = fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( dsz, 0UL ),                1UL );
  void *  _cf   = fd_wksp_alloc_laddr( wksp, fd_fseq_align(),   fd_fseq_footprint(),                            1UL );
  void *  _df   = fd_wksp_alloc_laddr( wksp, fd_fseq_align(),   fd_fseq_footprint(),                            1UL );
  FD_TEST( _ctx && _zstd && _cm && _dm && _cd && _dd && _cf && _df );

  ctx_t * ctx = (ctx_t *)_ctx;
  ctx->fname = argv[ 1 ];
  ctx->wksp  = wksp;
  ctx->zstd  = ZSTD_initStaticDStream( _zstd, ZSTD_estimateDStreamSize( ZSTD_WINDOW_SZ_MAX ) );
  FD_TEST( ctx->zstd );

  ctx->cm = fd_mcache_join( fd_mcache_new( _cm, C_DEPTH, 0UL, 1UL ) );
  ctx->dm = fd_mcache_join( fd_mcache_new( _dm, D_DEPTH, 0UL, 1UL ) );
  ctx->cd = fd_dcache_join( fd_dcache_new( _cd, csz, 0UL ) );
  ctx->dd = fd_dcache_join( fd_dcache_new( _dd, dsz, 0UL ) );
  ctx->cf = fd_fseq_join( fd_fseq_new( _cf, fd_mcache_seq0( ctx->cm ) ) );
  ctx->df = fd_fseq_join( fd_fseq_new( _df, fd_mcache_seq0( ctx->dm ) ) );
  FD_TEST( ctx->cm && ctx->dm && ctx->cd && ctx->dd && ctx->cf && ctx->df );

  long const start = fd_log_wallclock();

  pthread_t ld, dc, ck;
  FD_TEST( 0==pthread_create( &ld, NULL, run_ld, _ctx ) );
  FD_TEST( 0==pthread_create( &dc, NULL, run_dc, _ctx ) );
  FD_TEST( 0==pthread_create( &ck, NULL, run_ck, _ctx ) );

  /* consume electrons */

  FD_TEST( 0==pthread_join( ld, NULL ) );
  FD_TEST( 0==pthread_join( dc, NULL ) );
  FD_TEST( 0==pthread_join( ck, NULL ) );

  long const end = fd_log_wallclock();
  double const elapsed_sec = (double)(end-start) / 1.0e9;
  FD_LOG_NOTICE(( "FINISHED in %.3f sec, comp %.1f MBps", elapsed_sec, (double)ctx->fsize / 1024.0 / 1024.0 / elapsed_sec ));

  return 0;
}
