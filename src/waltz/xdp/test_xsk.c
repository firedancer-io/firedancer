/* test_xsk_unit: Unit tests for fd_xsk_t and fd_xsk_aio_t. Runs without
   actual AF_XDP configuration and mocks the kernel's interactions with
   shared memory data structures.  Thus runs without special permissions
   or heap. */

#include "fd_xsk_private.h"
#include "fd_xsk_aio_private.h"
#include "../../util/fd_util.h"

/* Static assertions **************************************************/

FD_STATIC_ASSERT( alignof(fd_xsk_frame_meta_t)==alignof(fd_aio_pkt_info_t), alignment );
FD_STATIC_ASSERT( alignof(fd_xsk_frame_meta_t)>=8UL,                        alignment );

/* fd_xsk_t testing ***************************************************/

/* fd_xsk_t memory region */

static uchar _xsk[ 262144UL ] __attribute__((aligned(FD_XSK_ALIGN)));

/* Mock mmap'ed rings provided by kernel */

#define TEST_XSK_RING_DEPTH (8UL)

struct test_xsk_ring_desc {
  uint flags;
  uint prod;
  uint cons;
  union {
    struct xdp_desc packets   [ TEST_XSK_RING_DEPTH ];
    ulong           frame_idxs[ TEST_XSK_RING_DEPTH ];
  };
};
typedef struct test_xsk_ring_desc test_xsk_ring_desc_t;

static test_xsk_ring_desc_t test_xsk_ring_rx;
static test_xsk_ring_desc_t test_xsk_ring_tx;
static test_xsk_ring_desc_t test_xsk_ring_fr;
static test_xsk_ring_desc_t test_xsk_ring_cr;


static void
setup_xsk_rings( fd_xsk_t * xsk ) {
  memset( &test_xsk_ring_rx, 0, sizeof(test_xsk_ring_desc_t) );
  memset( &test_xsk_ring_tx, 0, sizeof(test_xsk_ring_desc_t) );
  memset( &test_xsk_ring_fr, 0, sizeof(test_xsk_ring_desc_t) );
  memset( &test_xsk_ring_cr, 0, sizeof(test_xsk_ring_desc_t) );

  ulong umem_off = fd_ulong_align_up( sizeof(fd_xsk_t), FD_XSK_UMEM_ALIGN );

  xsk->umem.headroom   = 0U; /* TODO no need for headroom for now */
  xsk->umem.addr       = (ulong)xsk + umem_off;
  xsk->umem.chunk_size = (uint)xsk->params.frame_sz;
  xsk->umem.len        =       xsk->params.umem_sz;

  /* Ignore xsk->{mem,mem_sz} as those are only accessed during
     join/leave. */

  xsk->ring_rx.packet_ring = test_xsk_ring_rx.packets;
  xsk->ring_tx.packet_ring = test_xsk_ring_tx.packets;
  xsk->ring_fr.frame_ring  = test_xsk_ring_fr.frame_idxs;
  xsk->ring_cr.frame_ring  = test_xsk_ring_cr.frame_idxs;

  xsk->ring_rx.flags       = &test_xsk_ring_rx.flags;
  xsk->ring_tx.flags       = &test_xsk_ring_tx.flags;
  xsk->ring_fr.flags       = &test_xsk_ring_fr.flags;
  xsk->ring_cr.flags       = &test_xsk_ring_cr.flags;

  xsk->ring_rx.prod        = &test_xsk_ring_rx.prod;
  xsk->ring_tx.prod        = &test_xsk_ring_tx.prod;
  xsk->ring_fr.prod        = &test_xsk_ring_fr.prod;
  xsk->ring_cr.prod        = &test_xsk_ring_cr.prod;

  xsk->ring_rx.cons        = &test_xsk_ring_rx.cons;
  xsk->ring_tx.cons        = &test_xsk_ring_tx.cons;
  xsk->ring_fr.cons        = &test_xsk_ring_fr.cons;
  xsk->ring_cr.cons        = &test_xsk_ring_cr.cons;

  xsk->ring_rx.depth       = TEST_XSK_RING_DEPTH;
  xsk->ring_tx.depth       = TEST_XSK_RING_DEPTH;
  xsk->ring_fr.depth       = TEST_XSK_RING_DEPTH;
  xsk->ring_cr.depth       = TEST_XSK_RING_DEPTH;

  xsk->ring_rx.cached_prod = 0UL;
  xsk->ring_tx.cached_prod = 0UL;
  xsk->ring_fr.cached_prod = 0UL;
  xsk->ring_cr.cached_prod = 0UL;

  xsk->ring_rx.cached_cons = 0UL;
  xsk->ring_tx.cached_cons = 0UL;
  xsk->ring_fr.cached_cons = 0UL;
  xsk->ring_cr.cached_cons = 0UL;
}


void
test_xsk( void ) {
  /* Alignment checks */

  FD_TEST( fd_xsk_align()==FD_XSK_ALIGN );
  FD_TEST( fd_xsk_align()>=4096UL       ); /* at least normal page sz alignment */

  /* Invalid footprint params */

  FD_TEST( 0UL==fd_xsk_footprint( 0UL,    1UL, 1UL, 1UL, 1UL ) ); /* zero frame_sz  */
  FD_TEST( 0UL==fd_xsk_footprint( 1UL,    1UL, 1UL, 1UL, 1UL ) ); /* inval frame_sz */
  FD_TEST( 0UL==fd_xsk_footprint( 8192UL, 1UL, 1UL, 1UL, 1UL ) ); /* inval frame_sz */
  FD_TEST( 0UL==fd_xsk_footprint( 2048UL, 0UL, 1UL, 1UL, 1UL ) ); /* zero fr_depth  */
  FD_TEST( 0UL==fd_xsk_footprint( 2048UL, 1UL, 0UL, 1UL, 1UL ) ); /* zero fr_depth  */
  FD_TEST( 0UL==fd_xsk_footprint( 2048UL, 1UL, 1UL, 0UL, 1UL ) ); /* zero fr_depth  */
  FD_TEST( 0UL==fd_xsk_footprint( 2048UL, 1UL, 1UL, 1UL, 0UL ) ); /* zero fr_depth  */

  /* Invalid new params */

  FD_TEST( NULL==fd_xsk_new( NULL,               2048UL, 1UL, 1UL, 1UL, 1UL, 0 ) ); /* NULL shmem     */
  FD_TEST( NULL==fd_xsk_new( (void *)(_xsk+1UL), 2048UL, 1UL, 1UL, 1UL, 1UL, 0 ) ); /* unalign shmem  */
  FD_TEST( NULL==fd_xsk_new( _xsk,               0UL,    1UL, 1UL, 1UL, 1UL, 0 ) ); /* zero frame_sz  */
  FD_TEST( NULL==fd_xsk_new( _xsk,               1UL,    1UL, 1UL, 1UL, 1UL, 0 ) ); /* inval frame_sz */
  FD_TEST( NULL==fd_xsk_new( _xsk,               8192UL, 1UL, 1UL, 1UL, 1UL, 0 ) ); /* inval frame_sz */
  FD_TEST( NULL==fd_xsk_new( _xsk,               2048UL, 0UL, 1UL, 1UL, 1UL, 0 ) ); /* zero fr_depth  */
  FD_TEST( NULL==fd_xsk_new( _xsk,               2048UL, 1UL, 0UL, 1UL, 1UL, 0 ) ); /* zero fr_depth  */
  FD_TEST( NULL==fd_xsk_new( _xsk,               2048UL, 1UL, 1UL, 0UL, 1UL, 0 ) ); /* zero fr_depth  */
  FD_TEST( NULL==fd_xsk_new( _xsk,               2048UL, 1UL, 1UL, 1UL, 0UL, 0 ) ); /* zero fr_depth  */

  /* Create new XSK */

  FD_TEST( fd_xsk_footprint( 2048UL, 8UL, 8UL, 8UL, 8UL )==69632UL );

  void * shxsk = fd_xsk_new( _xsk, 2048UL, 8UL, 8UL, 8UL, 8UL, 0 );
  FD_TEST( shxsk );

  /* Invalid magic */

  fd_xsk_t * xsk = (fd_xsk_t *)shxsk;
  xsk->magic++;

  FD_TEST( NULL==fd_xsk_join  ( shxsk ) );
  FD_TEST( NULL==fd_xsk_bind  ( shxsk, "app",  "lo", 0U ) );
  FD_TEST( NULL==fd_xsk_delete( shxsk ) );

  xsk->magic--;

  /* Invalid bind params */

  FD_TEST( NULL==fd_xsk_bind( NULL,  "app", "lo", 0U ) ); /* NULL shxsk    */
  FD_TEST( NULL==fd_xsk_bind( shxsk, NULL,  "lo", 0U ) ); /* NULL app_name */
  FD_TEST( NULL==fd_xsk_bind( shxsk, "app", NULL, 0U ) ); /* NULL ifname   */

  FD_TEST( NULL==fd_xsk_bind( shxsk,
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "lo", 0U ) ); /* oversz app_name */
  FD_TEST( NULL==fd_xsk_bind( shxsk, "app", "AAAAAAAAAAAAAAAA", 0U ) ); /* oversz ifname */

  FD_TEST( NULL==fd_xsk_bind( (void *)((ulong)shxsk+1UL), "app", "lo", 0U ) ); /* unalign shxsk */

  /* Mock join */

  FD_TEST( fd_xsk_bind( shxsk, "app", "lo", 0U ) );

  FD_TEST( strcmp( fd_xsk_app_name( xsk ), "app" )==0  );
  FD_TEST( strcmp( fd_xsk_ifname  ( xsk ), "lo"  )==0  );
  FD_TEST(         fd_xsk_ifqueue ( xsk )         ==0  );

  /* Ensure fields are properly null-initialized */

  FD_TEST( fd_xsk_umem_laddr( xsk )==NULL );
  FD_TEST( fd_xsk_fd        ( xsk )==-1   );
  FD_TEST( fd_xsk_ifidx     ( xsk )==0U   );

  /* Get parameters */

  FD_TEST( fd_xsk_get_params( xsk )==&xsk->params );
  FD_TEST( xsk->params.fr_depth==    8UL );
  FD_TEST( xsk->params.rx_depth==    8UL );
  FD_TEST( xsk->params.tx_depth==    8UL );
  FD_TEST( xsk->params.cr_depth==    8UL );
  FD_TEST( xsk->params.frame_sz== 2048UL );
  FD_TEST( xsk->params.umem_sz ==65536UL );

  /* Mock kernel side (XSK descriptor rings) */

  setup_xsk_rings( xsk );

  /* Check fd_xsk_{rx,tx}_need_wakeup */

  FD_TEST( fd_xsk_rx_need_wakeup( xsk )==0 );
  FD_TEST( fd_xsk_tx_need_wakeup( xsk )==0 );

  *xsk->ring_rx.flags = XDP_RING_NEED_WAKEUP;
  FD_TEST( fd_xsk_rx_need_wakeup( xsk )==0 );
  FD_TEST( fd_xsk_tx_need_wakeup( xsk )==0 );
  *xsk->ring_rx.flags = 0UL;

  *xsk->ring_fr.flags = XDP_RING_NEED_WAKEUP;
  FD_TEST( fd_xsk_rx_need_wakeup( xsk )==1 );
  FD_TEST( fd_xsk_tx_need_wakeup( xsk )==0 );
  *xsk->ring_fr.flags = 0UL;

  *xsk->ring_tx.flags = XDP_RING_NEED_WAKEUP;
  FD_TEST( fd_xsk_rx_need_wakeup( xsk )==0 );
  FD_TEST( fd_xsk_tx_need_wakeup( xsk )==1 );
  *xsk->ring_tx.flags = 0UL;

  *xsk->ring_cr.flags = XDP_RING_NEED_WAKEUP;
  FD_TEST( fd_xsk_rx_need_wakeup( xsk )==0 );
  FD_TEST( fd_xsk_tx_need_wakeup( xsk )==0 );
  *xsk->ring_cr.flags = 0UL;

  /* Test fd_xsk_rx_enqueue (fill ring) */

  FD_TEST( fd_xsk_rx_enqueue( xsk, NULL, 0UL )==0UL );

  {
    ulong offsets[ 3UL ] = { 0UL*2048UL, 1UL*2048UL, 2UL*2048UL };
    FD_TEST( fd_xsk_rx_enqueue( xsk, offsets, 3UL )==3UL );
    FD_TEST( test_xsk_ring_fr.prod==3UL );
  }
  {
    ulong offsets[ 6UL ] = { 3UL*2048UL, 4UL*2048UL, 5UL*2048UL, 6UL*2048UL, 7UL*2048UL, 8UL*2048UL };
    FD_TEST( fd_xsk_rx_enqueue( xsk, offsets, 6UL )==5UL );
    FD_TEST( test_xsk_ring_fr.prod==8UL );
  }

  for( ulong i=0UL; i<8UL; i++ )
    FD_TEST( test_xsk_ring_fr.frame_idxs[ i ]==i*2048UL );

  test_xsk_ring_fr.cons = 1UL;

  {
    ulong offsets[ 3UL ] = { 8UL*2048UL, 9UL*2048UL, 10UL*2048UL };
    FD_TEST( fd_xsk_rx_enqueue( xsk, offsets, 3UL )==1UL );
    FD_TEST( test_xsk_ring_fr.prod==9UL );
  }

  FD_TEST  ( test_xsk_ring_fr.frame_idxs[ 0UL ]==8UL*2048UL );
  for( ulong i=1UL; i<8UL; i++ )
    FD_TEST( test_xsk_ring_fr.frame_idxs[ i   ]==i*2048UL   );

  /* Reset fill ring */

  fd_memset( &test_xsk_ring_fr, 0, sizeof(test_xsk_ring_desc_t) );
  xsk->ring_fr.cached_prod = xsk->ring_fr.cached_cons = 0UL;

  /* Test fd_xsk_rx_enqueue2 (fill ring) */

  FD_TEST( fd_xsk_rx_enqueue2( xsk, NULL, 0UL )==0UL );

  {
    fd_xsk_frame_meta_t metas[ 3UL ] =
      { {.off=0UL*2048UL}, {.off=1U*2048UL}, {.off=2UL*2048UL} };
    FD_TEST( fd_xsk_rx_enqueue2( xsk, metas, 3UL )==3UL );
    FD_TEST( test_xsk_ring_fr.prod==3UL );
  }
  {
    fd_xsk_frame_meta_t metas[ 6UL ] =
      { {.off=3UL*2048UL}, {.off=4UL*2048UL}, {.off=5UL*2048UL}, {.off=6UL*2048UL}, {.off=7UL*2048UL},
        {.off=8UL*2048UL} };
    FD_TEST( fd_xsk_rx_enqueue2( xsk, metas, 6UL )==5UL );
    FD_TEST( test_xsk_ring_fr.prod==8UL );
    FD_TEST( fd_xsk_rx_enqueue2( xsk, metas, 6UL )==0UL );
  }

  for( ulong i=0UL; i<8UL; i++ )
    FD_TEST( test_xsk_ring_fr.frame_idxs[ i ]==i*2048UL );

  test_xsk_ring_fr.cons = 1UL;

  {
    fd_xsk_frame_meta_t metas[ 3UL ] =
      { {.off=8UL*2048UL}, {.off=9UL*2048UL}, {.off=10UL*2048UL} };
    FD_TEST( fd_xsk_rx_enqueue2( xsk, metas, 3UL )==1UL );
    FD_TEST( test_xsk_ring_fr.prod==9UL );
  }

  FD_TEST  ( test_xsk_ring_fr.frame_idxs[ 0UL ]==8UL*2048UL );
  for( ulong i=1UL; i<8UL; i++ )
    FD_TEST( test_xsk_ring_fr.frame_idxs[ i   ]==i  *2048UL );

  /* Test fd_xsk_tx_enqueue */

  FD_TEST( fd_xsk_tx_enqueue( xsk, NULL, 0UL, 1 )==0UL );

  {
    fd_xsk_frame_meta_t metas[ 3UL ] =
      { {.off=0UL, .sz=0U, .flags=0U},
        {.off=1UL, .sz=1U, .flags=1U},
        {.off=2UL, .sz=2U, .flags=2U} };
    FD_TEST( fd_xsk_tx_enqueue( xsk, metas, 3UL, 1 )==3UL );
    FD_TEST( test_xsk_ring_tx.prod==3UL );
  }

  {
    fd_xsk_frame_meta_t metas[ 6UL ] =
      { {.off=3UL, .sz=3U, .flags=3U},
        {.off=4UL, .sz=4U, .flags=4U},
        {.off=5UL, .sz=5U, .flags=5U},
        {.off=6UL, .sz=6U, .flags=6U},
        {.off=7UL, .sz=7U, .flags=7U},
        {.off=8UL, .sz=8U, .flags=8U} };
    FD_TEST( fd_xsk_tx_enqueue( xsk, metas, 6UL, 1 )==5UL );
    FD_TEST( test_xsk_ring_tx.prod==8UL );
    FD_TEST( fd_xsk_tx_enqueue( xsk, metas, 6UL, 1 )==0UL );
  }

  /* Test fd_xsk_rx_complete */

  {
    fd_xsk_frame_meta_t metas[ 8UL ] = {0};
    FD_TEST( fd_xsk_rx_complete( xsk, metas, 8UL )==0UL );

    test_xsk_ring_rx.packets[ 0 ] =
      (struct xdp_desc) { .addr = 42UL, .len=42U, .options=42U };
    test_xsk_ring_rx.packets[ 1 ] =
      (struct xdp_desc) { .addr = 43UL, .len=43U, .options=43U };
    test_xsk_ring_rx.packets[ 2 ] =
      (struct xdp_desc) { .addr = 44UL, .len=44U, .options=44U };
    test_xsk_ring_rx.prod = 3UL;

    FD_TEST( fd_xsk_rx_complete( xsk, metas, 8UL )==3UL );

    for( uint i=0U; i<3U; i++)
      FD_TEST( metas[i].off==42U+i && metas[i].sz==42U+i && metas[i].flags==0 );

    test_xsk_ring_rx.packets[ 3 ] =
      (struct xdp_desc) { .addr = 45UL, .len=45U, .options=45U };
    test_xsk_ring_rx.packets[ 4 ] =
      (struct xdp_desc) { .addr = 46UL, .len=46U, .options=46U };
    test_xsk_ring_rx.packets[ 5 ] =
      (struct xdp_desc) { .addr = 47UL, .len=47U, .options=47U };
    test_xsk_ring_rx.packets[ 6 ] =
      (struct xdp_desc) { .addr = 48UL, .len=48U, .options=48U };
    test_xsk_ring_rx.packets[ 7 ] =
      (struct xdp_desc) { .addr = 49UL, .len=49U, .options=49U };
    test_xsk_ring_rx.packets[ 0 ] =
      (struct xdp_desc) { .addr = 50UL, .len=50U, .options=50U };
    test_xsk_ring_rx.prod = 9UL;

    FD_TEST( fd_xsk_rx_complete( xsk, metas, 8UL )==6UL );

    for( uint i=0U; i<6U; i++)
      FD_TEST( metas[i].off==45U+i && metas[i].sz==45U+i && metas[i].flags==0 );

    test_xsk_ring_rx.prod = 100UL;
    FD_TEST( fd_xsk_rx_complete( xsk, metas, 8UL )==8UL );
  }

  /* Test fd_xsk_tx_complete */

  {
    ulong offsets[ 8UL ] = {0};
    FD_TEST( fd_xsk_tx_complete( xsk, offsets, 8UL )==0UL );

    test_xsk_ring_cr.frame_idxs[ 0 ] = 42UL;
    test_xsk_ring_cr.frame_idxs[ 1 ] = 43UL;
    test_xsk_ring_cr.frame_idxs[ 2 ] = 44UL;
    test_xsk_ring_cr.prod = 3UL;

    FD_TEST( fd_xsk_tx_complete( xsk, offsets, 8UL )==3UL );
    FD_TEST( test_xsk_ring_cr.cons==3UL );

    for( uint i=0U; i<3U; i++)
      FD_TEST( offsets[i]==42U+i );

    test_xsk_ring_cr.frame_idxs[ 3 ] = 45UL;
    test_xsk_ring_cr.frame_idxs[ 4 ] = 46UL;
    test_xsk_ring_cr.frame_idxs[ 5 ] = 47UL;
    test_xsk_ring_cr.frame_idxs[ 6 ] = 48UL;
    test_xsk_ring_cr.frame_idxs[ 7 ] = 49UL;
    test_xsk_ring_cr.frame_idxs[ 0 ] = 50UL;
    test_xsk_ring_cr.prod = 9UL;

    FD_TEST( fd_xsk_tx_complete( xsk, offsets, 8UL )==6UL );
    FD_TEST( test_xsk_ring_cr.cons==9UL );

    for( uint i=0U; i<6U; i++)
      FD_TEST( offsets[i]==45U+i );

    test_xsk_ring_cr.prod = 100UL;
    FD_TEST( fd_xsk_tx_complete( xsk, offsets, 8UL )==8UL );
  }

  /* Reset completion ring */

  fd_memset( &test_xsk_ring_cr, 0, sizeof(test_xsk_ring_desc_t) );
  xsk->ring_cr.cached_prod = xsk->ring_cr.cached_cons = 0UL;

  /* Test fd_xsk_tx_complete2 */

  {
    fd_xsk_frame_meta_t metas[ 8UL ] = {0};
    FD_TEST( fd_xsk_tx_complete2( xsk, metas, 8UL )==0UL );

    test_xsk_ring_cr.frame_idxs[ 0 ] = 42UL;
    test_xsk_ring_cr.frame_idxs[ 1 ] = 43UL;
    test_xsk_ring_cr.frame_idxs[ 2 ] = 44UL;
    test_xsk_ring_cr.prod = 3UL;

    FD_TEST( fd_xsk_tx_complete2( xsk, metas, 8UL )==3UL );
    FD_TEST( test_xsk_ring_cr.cons==3UL );

    for( uint i=0U; i<3U; i++)
      FD_TEST( metas[i].off==42U+i );

    test_xsk_ring_cr.frame_idxs[ 3 ] = 45UL;
    test_xsk_ring_cr.frame_idxs[ 4 ] = 46UL;
    test_xsk_ring_cr.frame_idxs[ 5 ] = 47UL;
    test_xsk_ring_cr.frame_idxs[ 6 ] = 48UL;
    test_xsk_ring_cr.frame_idxs[ 7 ] = 49UL;
    test_xsk_ring_cr.frame_idxs[ 0 ] = 50UL;
    test_xsk_ring_cr.prod = 9UL;

    FD_TEST( fd_xsk_tx_complete2( xsk, metas, 8UL )==6UL );
    FD_TEST( test_xsk_ring_cr.cons==9UL );

    for( uint i=0U; i<6U; i++)
      FD_TEST( metas[i].off==45U+i );

    test_xsk_ring_cr.prod = 100UL;
    FD_TEST( fd_xsk_tx_complete2( xsk, metas, 8UL )==8UL );
  }

  /* Clean up */

  FD_TEST( fd_xsk_delete( shxsk ) );
}

/* fd_xsk_aio_t testing ***********************************************/

/* fd_xsk_t memory region */

static uchar _xsk_aio[ 16384UL ] __attribute__((aligned(FD_XSK_AIO_ALIGN)));

/* fd_xsk_aio_t mock fd_aio_t receiver */

static fd_aio_pkt_info_t const * _rx_batch;
static ulong                     _rx_batch_cnt;
static ulong                     _rx_call_cnt;

static fd_aio_t _rx;

static int
test_xsk_aio_rx( void *                    ctx,
                 fd_aio_pkt_info_t const * batch,
                 ulong                     batch_cnt,
                 ulong *                   opt_batch_idx,
                 int                       flush ) {
  (void)ctx;
  (void)opt_batch_idx;
  (void)flush;

  _rx_call_cnt++;
  FD_LOG_INFO(( "serving fd_xsk_aio callback" ));

  /* Per fd_aio spec, the lifetime of the buffer at batch ends after
     this function returns.  So technically, this is unsound code.
     For unit testing, this is fine though. */

  _rx_batch     = batch;
  _rx_batch_cnt = batch_cnt;

  return FD_AIO_SUCCESS;
}

void
test_xsk_aio( void ) {
  /* Alignment checks */

  FD_TEST( fd_xsk_aio_align()==32UL                         );
  FD_TEST( fd_xsk_aio_align()==alignof(fd_xsk_aio_t       ) );
  FD_TEST( fd_xsk_aio_align()>=alignof(fd_xsk_frame_meta_t) );
  FD_TEST( fd_xsk_aio_align()>=alignof(fd_aio_pkt_info_t  ) );

  /* Invalid new params */

  FD_TEST( NULL==fd_xsk_aio_new( NULL,                   1UL, 1UL ) ); /* NULL mem       */
  FD_TEST( NULL==fd_xsk_aio_new( (void *)(_xsk_aio+1UL), 1UL, 1UL ) ); /* unalign mem    */
  FD_TEST( NULL==fd_xsk_aio_new( _xsk_aio,               0UL, 1UL ) ); /* zero tx_depth  */
  FD_TEST( NULL==fd_xsk_aio_new( _xsk_aio,               1UL, 0UL ) ); /* zero batch_cnt */

  /* Invalid footprint params */

  FD_TEST( 0UL==fd_xsk_aio_footprint( 0UL, 1UL ) ); /* zero tx_depth  */
  FD_TEST( 0UL==fd_xsk_aio_footprint( 1UL, 0UL ) ); /* zero batch_cnt */

  /* Create new XSK aio */

  FD_TEST( fd_xsk_aio_footprint( 8UL, 8UL )==480UL            );
  FD_TEST( fd_xsk_aio_footprint( 8UL, 8UL )<=sizeof(_xsk_aio) );
  void * shxsk_aio = fd_xsk_aio_new( _xsk_aio, 8UL, 8UL );
  FD_TEST( shxsk_aio );

  /* Mock XSK */

  FD_TEST( fd_xsk_footprint( 2048UL, 8UL, 8UL, 8UL, 8UL )<=sizeof(_xsk) );
  void * shxsk = fd_xsk_new( _xsk, 2048UL, 8UL, 8UL, 8UL, 8UL, 1 );
  FD_TEST( shxsk );

  fd_xsk_t * xsk = (fd_xsk_t *)shxsk;
  setup_xsk_rings( xsk );

  ulong umem_off = xsk->umem.addr;

  /* Invalid magic */

  fd_xsk_aio_t * xsk_aio = (fd_xsk_aio_t *)shxsk_aio;
  xsk_aio->magic++;
  FD_TEST( NULL==fd_xsk_aio_join  ( shxsk_aio, xsk ) );
  FD_TEST( NULL==fd_xsk_aio_delete( shxsk_aio      ) );
  xsk_aio->magic--;

  /* Invalid join params */

  FD_TEST( NULL==fd_xsk_aio_join( shxsk_aio, NULL ) ); /* NULL xsk */

  /* Join xsk_aio */

  xsk_aio = fd_xsk_aio_join( shxsk_aio, xsk );
  FD_TEST( xsk_aio );

  fd_aio_t const * aio_tx = fd_xsk_aio_get_tx( xsk_aio );
  FD_TEST( aio_tx );

  /* Fill ring should be populated on join */

  FD_TEST( test_xsk_ring_fr.prod==8UL );
  for( uint i=0U; i<8U; i++ )
    FD_TEST( test_xsk_ring_fr.frame_idxs[i]==i*2048U );

  /* Check alignment */

  FD_TEST( ( (ulong)fd_xsk_aio_meta    ( xsk_aio ) % alignof( fd_xsk_frame_meta_t ) )==0UL );
  FD_TEST( ( (ulong)fd_xsk_aio_pkts    ( xsk_aio ) % alignof( fd_aio_pkt_info_t   ) )==0UL );
  FD_TEST( ( (ulong)fd_xsk_aio_tx_stack( xsk_aio ) % alignof( ulong               ) )==0UL );

  /* Send packets */

  FD_TEST( fd_aio_send( aio_tx, NULL, 0UL, NULL, 1 )==FD_AIO_SUCCESS );
  FD_TEST( xsk_aio->tx_top==8UL );

  {
    fd_aio_pkt_info_t pkts[ 3UL ] = {
      { .buf="a",   .buf_sz=1UL },
      { .buf="bb",  .buf_sz=2UL },
      { .buf="ccc", .buf_sz=3UL }
    };
    FD_TEST( fd_aio_send( aio_tx, pkts, 3UL, NULL, 1 )==FD_AIO_SUCCESS );
    FD_TEST( xsk_aio->tx_top==5UL );

    FD_TEST( test_xsk_ring_tx.prod          ==3UL );
    FD_TEST( test_xsk_ring_tx.packets[0].len==1UL );
    FD_TEST( test_xsk_ring_tx.packets[1].len==2UL );
    FD_TEST( test_xsk_ring_tx.packets[2].len==3UL );

    FD_TEST( 0==memcmp( (void *)(umem_off+test_xsk_ring_tx.packets[0].addr), pkts[0].buf, pkts[0].buf_sz ) );
    FD_TEST( 0==memcmp( (void *)(umem_off+test_xsk_ring_tx.packets[1].addr), pkts[1].buf, pkts[1].buf_sz ) );
    FD_TEST( 0==memcmp( (void *)(umem_off+test_xsk_ring_tx.packets[2].addr), pkts[2].buf, pkts[2].buf_sz ) );
  }

  {
    fd_aio_pkt_info_t pkts[ 6UL ] = {
      { .buf="dd", .buf_sz=2UL },
      { .buf="ee", .buf_sz=2UL },
      { .buf="ff", .buf_sz=2UL },
      { .buf="gg", .buf_sz=2UL },
      { .buf="hh", .buf_sz=2UL },
      { .buf="ii", .buf_sz=2UL }
    };
    ulong batch_idx;
    FD_TEST( fd_aio_send( aio_tx, pkts, 6UL, &batch_idx, 1 )==FD_AIO_ERR_AGAIN );
    FD_TEST( batch_idx==5UL );
    FD_TEST( xsk_aio->tx_top==0UL );

    FD_TEST( test_xsk_ring_tx.prod==8UL );
    for( ulong i=3UL; i<8UL; i++ ) {
      FD_TEST( test_xsk_ring_tx.packets[i].len==2UL );
      FD_TEST( 0==memcmp( (void *)(umem_off+test_xsk_ring_tx.packets[i].addr), pkts[i-3UL].buf, 2UL ) );
    }
  }

  /* Receive tx completion */

  for( uint i=0U; i<8U; i++ )
    test_xsk_ring_cr.frame_idxs[ i ]=i*2048U;
  test_xsk_ring_cr.prod = 8U;

  fd_xsk_aio_service( xsk_aio );

  FD_TEST( xsk_aio->tx_top==8UL );
  for( uint i=0U; i<8U; i++ )
    FD_TEST( xsk_aio->tx_stack[i]==i*2048U );

  /* Connect fd_aio_t rx */

  fd_aio_t * rx = fd_aio_new( &_rx, NULL, test_xsk_aio_rx );
  FD_TEST( rx );

  fd_xsk_aio_set_rx( xsk_aio, rx );

  /* Receive packets */

  FD_TEST( _rx_call_cnt==0UL );

  test_xsk_ring_fr.cons = 4U;
  for( uint i=0U; i<4U; i++ )
    test_xsk_ring_rx.packets[i] =
      (struct xdp_desc) { .addr=i*2048U, .len=3U };
  test_xsk_ring_rx.prod = 4U;

  fd_xsk_aio_service( xsk_aio );

  FD_TEST( _rx_call_cnt==1UL );
  FD_TEST( test_xsk_ring_rx.cons== 4U );
  FD_TEST( test_xsk_ring_fr.prod==12U );

  /* Receive packets */

  test_xsk_ring_fr.cons = 10U;
  for( uint i=4U; i<10U; i++ )
    test_xsk_ring_rx.packets[i%8UL] =
      (struct xdp_desc) { .addr=(i%8)*2048U, .len=3U };
  test_xsk_ring_rx.prod = 10U;

  fd_xsk_aio_service( xsk_aio );

  FD_TEST( _rx_call_cnt==2UL );
  FD_TEST( test_xsk_ring_rx.cons==10U );
  FD_TEST( test_xsk_ring_fr.prod==18U );

  FD_TEST( _rx_batch    ==fd_xsk_aio_pkts( xsk_aio ) );
  FD_TEST( _rx_batch_cnt==6UL );

  ulong umem_laddr = (ulong)fd_xsk_umem_laddr( xsk );
  for( uint i=0U; i<6U; i++ ) {
    FD_TEST( _rx_batch[i].buf   ==(void *)( umem_laddr + ((i+4U)%8)*2048U ) );
    FD_TEST( _rx_batch[i].buf_sz==3U );
  }

  /* Clean up */

  FD_TEST( fd_xsk_aio_leave ( xsk_aio   ) );
  FD_TEST( fd_xsk_delete    ( shxsk     ) );
  FD_TEST( fd_xsk_aio_delete( shxsk_aio ) );
}


int main( int     argc,
          char ** argv ) {
  fd_boot( &argc, &argv );

  test_xsk();
  test_xsk_aio();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
}

