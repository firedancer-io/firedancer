/* test_xsk_unit: Unit tests for fd_xsk_t. Runs without actual AF_XDP
   configuration and mocks the kernel's interactions. */

#include "fd_xsk.h"
#include "fd_xsk_private.h"
#include "../../util/fd_util.h"

/* Static assertions **************************************************/

FD_STATIC_ASSERT( alignof(fd_xsk_frame_meta_t)>=8UL, alignment );

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


int main( int     argc,
          char ** argv ) {
  fd_boot( &argc, &argv );
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

  FD_TEST( NULL==fd_xsk_new( NULL,               2048UL, 1UL, 1UL, 1UL, 1UL ) ); /* NULL shmem     */
  FD_TEST( NULL==fd_xsk_new( (void *)(_xsk+1UL), 2048UL, 1UL, 1UL, 1UL, 1UL ) ); /* unalign shmem  */
  FD_TEST( NULL==fd_xsk_new( _xsk,               0UL,    1UL, 1UL, 1UL, 1UL ) ); /* zero frame_sz  */
  FD_TEST( NULL==fd_xsk_new( _xsk,               1UL,    1UL, 1UL, 1UL, 1UL ) ); /* inval frame_sz */
  FD_TEST( NULL==fd_xsk_new( _xsk,               8192UL, 1UL, 1UL, 1UL, 1UL ) ); /* inval frame_sz */
  FD_TEST( NULL==fd_xsk_new( _xsk,               2048UL, 0UL, 1UL, 1UL, 1UL ) ); /* zero fr_depth  */
  FD_TEST( NULL==fd_xsk_new( _xsk,               2048UL, 1UL, 0UL, 1UL, 1UL ) ); /* zero fr_depth  */
  FD_TEST( NULL==fd_xsk_new( _xsk,               2048UL, 1UL, 1UL, 0UL, 1UL ) ); /* zero fr_depth  */
  FD_TEST( NULL==fd_xsk_new( _xsk,               2048UL, 1UL, 1UL, 1UL, 0UL ) ); /* zero fr_depth  */

  /* Create new XSK */

  FD_TEST( fd_xsk_footprint( 2048UL, 8UL, 8UL, 8UL, 8UL )==69632UL );

  void * shxsk = fd_xsk_new( _xsk, 2048UL, 8UL, 8UL, 8UL, 8UL );
  FD_TEST( shxsk );

  /* Invalid magic */

  fd_xsk_t * xsk = (fd_xsk_t *)shxsk;
  xsk->magic++;

  FD_TEST( NULL==fd_xsk_join  ( shxsk ) );
  FD_TEST( NULL==fd_xsk_delete( shxsk ) );

  xsk->magic--;

  xsk = fd_xsk_join( shxsk );
  FD_TEST( xsk );

  /* Invalid bind params */

  FD_TEST( NULL==fd_xsk_init( NULL, 1U, 0U, 0U ) ); /* NULL xsk    */

  /* Ensure fields are properly null-initialized */

  FD_TEST( fd_xsk_umem_laddr( xsk )==NULL );
  FD_TEST( fd_xsk_fd        ( xsk )==-1   );
  FD_TEST( fd_xsk_ifidx     ( xsk )==0U   );
  FD_TEST( fd_xsk_ifqueue   ( xsk )==0U   );

  /* Mock join */

  xsk->if_idx      = 0x41414143U;
  xsk->if_queue_id = 0x42424245U;
  FD_TEST( fd_xsk_ifidx   ( xsk )==0x41414143U );
  FD_TEST( fd_xsk_ifqueue ( xsk )==0x42424245U );

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

  /* Clean up */

  FD_TEST( fd_xsk_delete( shxsk ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
}
