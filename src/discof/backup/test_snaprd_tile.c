/* Drives after_credit on a hand-built snaprd context with pread
   replaced by an in-memory accounts.db.  Every read must be 4 KiB
   aligned in offset, length and buffer (O_DIRECT), must stay inside
   the partition it started in, and every frag must carry exactly the
   partition bytes in order. */

#define _GNU_SOURCE
#include <unistd.h>
static long test_pread( int fd, void * buf, size_t len, off_t off );
#define pread test_pread
#pragma GCC diagnostic ignored "-Wunused-function"
#include "fd_snaprd_tile.c"
#include "../../flamenco/accdb/fd_accdb_private.h"

#include <stdlib.h>
#include <sys/mman.h>

#define DIRECT_FD    (777)
#define PART_FULL_SZ (1UL<<30) /* accdb allocates whole partitions */
#define DEPTH        (4UL)
#define MTU          FD_BACKUP_RD_MTU
#define READ_MAX     (5UL<<20) /* short reads, still block multiples */

/* the fake file holds word hash(w) at byte offset 8*w */

static void
image_fill( uchar * buf,
            ulong   off,
            ulong   len ) {
  for( ulong i=0UL; i<len; i+=8UL ) FD_STORE( ulong, buf+i, fd_ulong_hash( (off+i)>>3 ) );
}

static void
image_check( uchar const * buf,
             ulong         off,
             ulong         len ) {
  ulong i;
  for( i=0UL; i+8UL<=len; i+=8UL ) FD_TEST( FD_LOAD( ulong, buf+i )==fd_ulong_hash( (off+i)>>3 ) );
  ulong tail = fd_ulong_hash( (off+i)>>3 );
  for( ulong j=0UL; i+j<len; j++ ) FD_TEST( buf[ i+j ]==(uchar)( tail>>(8UL*j) ) );
}

static ulong read_cnt;
static ulong read_bytes;

static long
test_pread( int    fd,
            void * buf,
            size_t len,
            off_t  off ) {
  FD_TEST( fd==DIRECT_FD );
  FD_TEST( fd_ulong_is_aligned( (ulong)off, 4096UL ) );
  FD_TEST( fd_ulong_is_aligned( len,        4096UL ) );
  FD_TEST( fd_ulong_is_aligned( (ulong)buf, 4096UL ) );
  FD_TEST( len && len<=MTU );
  FD_TEST( ((ulong)off % PART_FULL_SZ)+len<=PART_FULL_SZ );
  len = fd_ulong_min( len, READ_MAX );
  image_fill( buf, (ulong)off, len );
  read_cnt++;
  read_bytes += len;
  return (long)len;
}

static fd_snaprd_t       ctx[1];
static fd_stem_context_t stem[1];
static fd_frag_meta_t *  mcache;
static ulong             seqs[1];
static ulong             depths[1] = { DEPTH };
static ulong             cr_avail[1];
static ulong             min_cr_avail;
static int               out_reliable[1] = { 1 };

static void
setup( void ) {
  ulong data_sz = fd_dcache_req_data_sz( MTU, DEPTH, 1UL, 1 );
  FD_TEST( data_sz );
  ulong  dcache_fp = fd_dcache_footprint( data_sz, 0UL );
  void * mem       = mmap( NULL, dcache_fp, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0 );
  FD_TEST( mem!=MAP_FAILED );
  uchar * dcache = fd_dcache_join( fd_dcache_new( mem, data_sz, 0UL ) );
  FD_TEST( dcache );

  void * mcache_mem = aligned_alloc( fd_mcache_align(), fd_mcache_footprint( DEPTH, 0UL ) );
  mcache = fd_mcache_join( fd_mcache_new( mcache_mem, DEPTH, 0UL, 0UL ) );
  FD_TEST( mcache );

  /* the read path only looks at accdb's snapshot sync word */
  ulong shmem_fp = fd_accdb_shmem_footprint( 1024UL, 16UL, 128UL, 32UL, 32UL<<20, 2UL, 1UL, 0UL, 0UL );
  FD_TEST( shmem_fp );
  void * shmem_mem = aligned_alloc( fd_accdb_shmem_align(), shmem_fp );
  fd_accdb_shmem_t * shmem = fd_accdb_shmem_join(
      fd_accdb_shmem_new( shmem_mem, 1024UL, 16UL, 128UL, 32UL, 32UL<<20,
                          32UL<<20, 2UL, 0, 42UL, 1UL, 0UL, 0UL ) );
  FD_TEST( shmem );
  shmem->snapshot_sync = FD_ACCDB_SNAPSHOT_SYNC_RUNNING;

  ctx->accdb           = shmem;
  ctx->accdb_direct_fd = DIRECT_FD;
  ctx->out.mem         = mem;
  ctx->out.chunk0      = fd_dcache_compact_chunk0( mem, dcache );
  ctx->out.wmark       = fd_dcache_compact_wmark( mem, dcache, MTU );
  ctx->out.chunk       = ctx->out.chunk0;
  ctx->out.mtu         = MTU;

  stem[0] = (fd_stem_context_t) {
    .mcaches             = &mcache,
    .seqs                = seqs,
    .depths              = depths,
    .cr_avail            = cr_avail,
    .min_cr_avail        = &min_cr_avail,
    .cr_decrement_amount = 1UL,
    .out_reliable        = out_reliable,
  };
}

/* run_read reads ctx->part[] to the end, one frag per after_credit
   like stem does with STEM_BURST 1, checking each frag against the
   file as snapmk would see it.  Returns the number of frags. */

static ulong
run_read( void ) {
  ctx->state    = SNAPRD_STATE_READ;
  ctx->part_idx = 0UL;
  next_partition( ctx );
  memset( &ctx->metrics, 0, sizeof(ctx->metrics) );
  read_bytes = 0UL;

  ulong expect_total = 0UL;
  for( ulong i=0UL; i<ctx->part_cnt; i++ ) expect_total += ctx->part[ i ].sz;

  ulong expect_idx  = 0UL;
  ulong expect_cur  = 0UL;
  ulong expect_read = 0UL;
  ulong frag_cnt    = 0UL;
  ulong seq0        = seqs[0];
  for(;;) {
    while( expect_idx<ctx->part_cnt && expect_cur==ctx->part[ expect_idx ].sz ) {
      expect_idx++;
      expect_cur = 0UL;
    }
    ulong expect_sz = expect_idx<ctx->part_cnt ? ctx->part[ expect_idx ].sz : 0UL;
    ulong frag_sz   = fd_ulong_min( MTU, expect_sz-expect_cur );

    cr_avail[0] = 1UL;
    int poll_in = 1;
    int busy    = 0;
    after_credit( ctx, stem, &poll_in, &busy );
    FD_TEST( busy && !poll_in && !cr_avail[0] );

    fd_frag_meta_t const * m = mcache + fd_mcache_line_idx( seq0+frag_cnt, DEPTH );
    FD_TEST( m->seq==seq0+frag_cnt );
    FD_TEST( m->tspub==frag_sz );
    FD_TEST( m->sz==fd_ulong_min( frag_sz, USHORT_MAX ) );
    FD_TEST( fd_frag_meta_ctl_orig( m->ctl )==FD_BACKUP_ORIG_DISK_FRAG );
    FD_TEST( m->chunk>=ctx->out.chunk0 && m->chunk<=ctx->out.wmark );
    if( frag_sz ) {
      FD_TEST( m->sig==ctx->part[ expect_idx ].file_off+expect_cur );
      image_check( fd_chunk_to_laddr_const( ctx->out.mem, m->chunk ), m->sig, frag_sz );
      expect_read += fd_ulong_align_up( frag_sz, 4096UL );
    }
    expect_cur += frag_sz;
    frag_cnt++;

    if( fd_frag_meta_ctl_eom( m->ctl ) ) break;
  }

  while( expect_idx<ctx->part_cnt && expect_cur==ctx->part[ expect_idx ].sz ) {
    expect_idx++;
    expect_cur = 0UL;
  }
  FD_TEST( expect_idx==ctx->part_cnt );
  FD_TEST( ctx->state==SNAPRD_STATE_DONE );
  FD_TEST( ctx->metrics.bytes_read==expect_read );
  FD_TEST( read_bytes==expect_read );
  FD_TEST( ctx->metrics.export_progress_bytes==expect_total );
  return frag_cnt;
}

static void
part_set( ulong idx,
          ulong sz ) {
  ctx->part[ idx ].file_off = idx*PART_FULL_SZ;
  ctx->part[ idx ].sz       = sz;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  setup();

  /* a 1234 byte tail, an exact frag, a sub-block partition, empty
     partitions at both ends; 9 frags wrap the 4 deep ring twice */
  part_set( 0UL, 0UL );
  part_set( 1UL, 6UL*MTU+1234UL );
  part_set( 2UL, MTU );
  part_set( 3UL, 4095UL );
  part_set( 4UL, 0UL );
  ctx->part_cnt = 5UL;
  FD_TEST( run_read()==9UL );
  /* 7 full frags take 4 short reads each, the two tails one each */
  FD_TEST( read_cnt==7UL*4UL+2UL );

  /* no data on disk: one empty frag carrying eom, no read */
  ctx->part_cnt = 0UL;
  ulong read_cnt0 = read_cnt;
  FD_TEST( run_read()==1UL );
  FD_TEST( read_cnt==read_cnt0 );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
