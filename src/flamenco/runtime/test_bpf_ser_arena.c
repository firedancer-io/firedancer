#include "fd_runtime.h"
#include "program/fd_bpf_loader_serialization.h"

#include <stdlib.h>

/* Tests the pooled BPF serialization scheme: FIFO ticket semantics of
   the shared overflow arena, the window->arena promotion state machine
   in the fd_runtime_bpf_ser_* helpers, and the serializer's exact
   bounds check (FD_BPF_LOADER_SERIALIZE_FULL). */

static void *
alloc_aligned( ulong align, ulong sz ) {
  void * mem = aligned_alloc( align, fd_ulong_align_up( sz, align ) );
  FD_TEST( mem );
  return mem;
}

static void
test_arena_fifo( void ) {
  ulong bundle_cnt = 2UL;
  ulong slot_sz    = FD_BPF_SER_ARENA_BUNDLE_FOOTPRINT( FD_MAX_INSTRUCTION_STACK_DEPTH-1UL );
  void * mem = alloc_aligned( fd_bpf_ser_arena_align(), fd_bpf_ser_arena_footprint( bundle_cnt, slot_sz ) );
  fd_bpf_ser_arena_t * arena = fd_bpf_ser_arena_join( fd_bpf_ser_arena_new( mem, bundle_cnt, slot_sz ) );
  FD_TEST( arena );

  /* First bundle_cnt tickets acquire immediately */
  ulong t0 = fd_bpf_ser_arena_ticket( arena );
  ulong t1 = fd_bpf_ser_arena_ticket( arena );
  FD_TEST( fd_bpf_ser_arena_ready( arena, t0 ) );
  FD_TEST( fd_bpf_ser_arena_ready( arena, t1 ) );
  uchar * b0 = fd_bpf_ser_arena_wait( arena, t0 );
  uchar * b1 = fd_bpf_ser_arena_wait( arena, t1 );
  FD_TEST( b0 && b1 && b0!=b1 );
  FD_TEST( fd_ulong_is_aligned( (ulong)b0, FD_RUNTIME_EBPF_HOST_ALIGN ) );
  FD_TEST( fd_ulong_is_aligned( (ulong)b1, FD_RUNTIME_EBPF_HOST_ALIGN ) );

  /* Later tickets gate FIFO: one release admits exactly the next */
  ulong t2 = fd_bpf_ser_arena_ticket( arena );
  ulong t3 = fd_bpf_ser_arena_ticket( arena );
  FD_TEST( !fd_bpf_ser_arena_ready( arena, t2 ) );
  FD_TEST( !fd_bpf_ser_arena_ready( arena, t3 ) );

  fd_bpf_ser_arena_release( arena, b0 );
  FD_TEST(  fd_bpf_ser_arena_ready( arena, t2 ) );
  FD_TEST( !fd_bpf_ser_arena_ready( arena, t3 ) );

  fd_bpf_ser_arena_release( arena, b1 );
  FD_TEST(  fd_bpf_ser_arena_ready( arena, t3 ) );

  uchar * b2 = fd_bpf_ser_arena_wait( arena, t2 );
  uchar * b3 = fd_bpf_ser_arena_wait( arena, t3 );
  FD_TEST( b2 && b3 && b2!=b3 );
  fd_bpf_ser_arena_release( arena, b2 );
  fd_bpf_ser_arena_release( arena, b3 );

  /* Full bundle write: every frame slot addressable at full footprint */
  uchar * b = fd_bpf_ser_arena_acquire( arena );
  memset( b, 0x5a, slot_sz );
  fd_bpf_ser_arena_release( arena, b );

  free( mem );
  FD_LOG_NOTICE(( "test_arena_fifo: pass" ));
}

static void
test_window_promotion( void ) {
  fd_runtime_t * runtime = (fd_runtime_t *)alloc_aligned( 4096UL, sizeof(fd_runtime_t) );

  ulong  window_cap = FD_BPF_SER_WINDOW_FOOTPRINT( FD_BPF_SER_WINDOW_CU_MAX_RP );
  void * window     = alloc_aligned( FD_RUNTIME_EBPF_HOST_ALIGN, window_cap );
  void * frame1     = alloc_aligned( FD_RUNTIME_EBPF_HOST_ALIGN, BPF_LOADER_SERIALIZATION_FOOTPRINT );
  void * mem = alloc_aligned( fd_bpf_ser_arena_align(), fd_bpf_ser_arena_footprint( 1UL, FD_BPF_SER_ARENA_BUNDLE_FOOTPRINT( FD_MAX_INSTRUCTION_STACK_DEPTH-1UL ) ) );
  fd_bpf_ser_arena_t * arena = fd_bpf_ser_arena_join( fd_bpf_ser_arena_new( mem, 1UL, FD_BPF_SER_ARENA_BUNDLE_FOOTPRINT( FD_MAX_INSTRUCTION_STACK_DEPTH-1UL ) ) );
  fd_runtime_bpf_ser_init( runtime, arena, frame1, BPF_LOADER_SERIALIZATION_FOOTPRINT, window, window_cap );
  FD_TEST( runtime->bpf_loader_serialization.bundle_first_depth==2UL );

  uchar * buf; ulong cap;

  /* Depth 1 always gets the fully provisioned frame1 */
  fd_runtime_bpf_ser_frame_begin( runtime, 1UL, &buf, &cap );
  FD_TEST( buf==runtime->bpf_loader_serialization.frame1 );
  FD_TEST( cap==BPF_LOADER_SERIALIZATION_FOOTPRINT );

  /* Depth 2 bumps out of the window */
  fd_runtime_bpf_ser_frame_begin( runtime, 2UL, &buf, &cap );
  FD_TEST( buf==runtime->bpf_loader_serialization.window );
  FD_TEST( cap==window_cap );
  ulong d2_sz = window_cap-4096UL;
  fd_runtime_bpf_ser_frame_commit( runtime, 2UL, d2_sz );
  FD_TEST( runtime->bpf_loader_serialization.window_watermark==fd_ulong_align_up( d2_sz, FD_RUNTIME_EBPF_HOST_ALIGN ) );

  /* Depth 3 sees only the leftover window */
  fd_runtime_bpf_ser_frame_begin( runtime, 3UL, &buf, &cap );
  FD_TEST( cap==window_cap-fd_ulong_align_up( d2_sz, FD_RUNTIME_EBPF_HOST_ALIGN ) );
  FD_TEST( cap<4096UL+FD_RUNTIME_EBPF_HOST_ALIGN );

  /* ...and promotes to the arena bundle when that is too small */
  uchar * b3 = fd_runtime_bpf_ser_frame_promote( runtime, 3UL );
  FD_TEST( runtime->bpf_loader_serialization.bundle );
  FD_TEST( b3==runtime->bpf_loader_serialization.bundle+1UL*BPF_LOADER_SERIALIZATION_FOOTPRINT );

  /* Once the bundle is held deeper frames use it directly at full cap */
  fd_runtime_bpf_ser_frame_begin( runtime, 4UL, &buf, &cap );
  FD_TEST( buf==runtime->bpf_loader_serialization.bundle+2UL*BPF_LOADER_SERIALIZATION_FOOTPRINT );
  FD_TEST( cap==BPF_LOADER_SERIALIZATION_FOOTPRINT );

  /* LIFO pops: bundle depths are no-ops, window depth restores space */
  fd_runtime_bpf_ser_frame_pop( runtime, 4UL );
  fd_runtime_bpf_ser_frame_pop( runtime, 3UL );
  FD_TEST( runtime->bpf_loader_serialization.window_top==fd_ulong_align_up( d2_sz, FD_RUNTIME_EBPF_HOST_ALIGN ) );
  fd_runtime_bpf_ser_frame_pop( runtime, 2UL );
  FD_TEST( runtime->bpf_loader_serialization.window_top==0UL );

  /* Txn end releases the bundle so the (sole) bundle is reacquirable */
  fd_runtime_bpf_ser_reset( runtime );
  FD_TEST( !runtime->bpf_loader_serialization.bundle );
  uchar * b = fd_bpf_ser_arena_acquire( arena );
  FD_TEST( b );
  fd_bpf_ser_arena_release( arena, b );

  /* Sequential same-depth frames reuse the space of the popped one */
  fd_runtime_bpf_ser_frame_begin( runtime, 2UL, &buf, &cap );
  fd_runtime_bpf_ser_frame_commit( runtime, 2UL, 1000UL );
  fd_runtime_bpf_ser_frame_pop( runtime, 2UL );
  fd_runtime_bpf_ser_frame_begin( runtime, 2UL, &buf, &cap );
  FD_TEST( buf==runtime->bpf_loader_serialization.window );
  FD_TEST( cap==window_cap );
  fd_runtime_bpf_ser_reset( runtime );

  FD_TEST( runtime->bpf_loader_serialization.promote_cnt==1UL );

  free( mem );
  free( frame1 );
  free( window );
  free( runtime );
  FD_LOG_NOTICE(( "test_window_promotion: pass" ));
}

static void
test_depth1_promote( void ) {
  fd_runtime_t * runtime = (fd_runtime_t *)alloc_aligned( 4096UL, sizeof(fd_runtime_t) );

  /* Replay-tile shape: windowed frame1, 5-frame single-bundle arena */
  ulong  frame1_cap = FD_BPF_SER_FRAME1_WINDOW_FOOTPRINT;
  void * frame1     = alloc_aligned( FD_RUNTIME_EBPF_HOST_ALIGN, frame1_cap );
  ulong  window_cap = FD_BPF_SER_WINDOW_FOOTPRINT( FD_BPF_SER_WINDOW_CU_MAX_RP );
  void * window     = alloc_aligned( FD_RUNTIME_EBPF_HOST_ALIGN, window_cap );
  void * mem = alloc_aligned( fd_bpf_ser_arena_align(), fd_bpf_ser_arena_footprint( 1UL, FD_BPF_SER_ARENA_BUNDLE_FOOTPRINT( FD_MAX_INSTRUCTION_STACK_DEPTH ) ) );
  fd_bpf_ser_arena_t * arena = fd_bpf_ser_arena_join( fd_bpf_ser_arena_new( mem, 1UL, FD_BPF_SER_ARENA_BUNDLE_FOOTPRINT( FD_MAX_INSTRUCTION_STACK_DEPTH ) ) );
  fd_runtime_bpf_ser_init( runtime, arena, frame1, frame1_cap, window, window_cap );
  FD_TEST( runtime->bpf_loader_serialization.bundle_first_depth==1UL );

  uchar * buf; ulong cap;

  /* Depth 1 serializes into the windowed frame1 */
  fd_runtime_bpf_ser_frame_begin( runtime, 1UL, &buf, &cap );
  FD_TEST( buf==runtime->bpf_loader_serialization.frame1 );
  FD_TEST( cap==frame1_cap );

  /* An oversized top-level instruction promotes to bundle frame 0 */
  uchar * b1 = fd_runtime_bpf_ser_frame_promote( runtime, 1UL );
  FD_TEST( runtime->bpf_loader_serialization.bundle );
  FD_TEST( b1==runtime->bpf_loader_serialization.bundle );
  FD_TEST( runtime->bpf_loader_serialization.promote_cnt==1UL );

  /* A held bundle is preferred at every depth, depth 1 included */
  fd_runtime_bpf_ser_frame_begin( runtime, 1UL, &buf, &cap );
  FD_TEST( buf==runtime->bpf_loader_serialization.bundle );
  FD_TEST( cap==BPF_LOADER_SERIALIZATION_FOOTPRINT );
  fd_runtime_bpf_ser_frame_begin( runtime, 3UL, &buf, &cap );
  FD_TEST( buf==runtime->bpf_loader_serialization.bundle+2UL*BPF_LOADER_SERIALIZATION_FOOTPRINT );
  FD_TEST( cap==BPF_LOADER_SERIALIZATION_FOOTPRINT );
  uchar * b5 = fd_runtime_bpf_ser_frame_promote( runtime, FD_MAX_INSTRUCTION_STACK_DEPTH );
  FD_TEST( b5==runtime->bpf_loader_serialization.bundle+(FD_MAX_INSTRUCTION_STACK_DEPTH-1UL)*BPF_LOADER_SERIALIZATION_FOOTPRINT );
  FD_TEST( runtime->bpf_loader_serialization.promote_cnt==1UL ); /* no re-promote */

  /* Sole bundle held: the next txn's ticket queues until txn end */
  ulong t = fd_bpf_ser_arena_ticket( arena );
  FD_TEST( !fd_bpf_ser_arena_ready( arena, t ) );
  fd_runtime_bpf_ser_reset( runtime );
  FD_TEST( !runtime->bpf_loader_serialization.bundle );
  FD_TEST( fd_bpf_ser_arena_ready( arena, t ) );
  uchar * b = fd_bpf_ser_arena_wait( arena, t );
  memset( b, 0x5a, FD_BPF_SER_ARENA_BUNDLE_FOOTPRINT( FD_MAX_INSTRUCTION_STACK_DEPTH ) );
  fd_bpf_ser_arena_release( arena, b );

  /* Next txn starts back in the windowed frame1 */
  fd_runtime_bpf_ser_frame_begin( runtime, 1UL, &buf, &cap );
  FD_TEST( buf==runtime->bpf_loader_serialization.frame1 );
  FD_TEST( cap==frame1_cap );

  free( mem );
  free( window );
  free( frame1 );
  free( runtime );
  FD_LOG_NOTICE(( "test_depth1_promote: pass" ));
}

static void
test_serialize_full( void ) {
  /* Minimal 0-account instruction: serializer writes acct_cnt,
     instr_data_len, data, program id only.  An undersized frame must
     return FD_BPF_LOADER_SERIALIZE_FULL before writing out of bounds;
     a right-sized frame must succeed. */
  static fd_instr_info_t info[1];
  static fd_txn_out_t    txn_out[1];
  fd_instr_info_new( info );
  info->program_id = 0;
  info->data_sz    = 100;
  for( ulong i=0UL; i<100UL; i++ ) info->data[ i ] = (uchar)i;
  memset( txn_out->accounts.keys[ 0 ].key, 0x11, 32UL );

  fd_exec_instr_ctx_t ctx[1]; memset( ctx, 0, sizeof(fd_exec_instr_ctx_t) );
  ctx->instr   = info;
  ctx->txn_out = txn_out;

  ulong                   pre_lens[ FD_TXN_INSTR_ACCT_MAX ];
  fd_vm_input_region_t    regions[ 4 ];
  uint                    region_cnt;
  fd_vm_acc_region_meta_t metas[ FD_TXN_INSTR_ACCT_MAX ];
  ulong                   idata_off;
  ulong                   sz;

  static uchar frame[ 4096 ] __attribute__((aligned(FD_RUNTIME_EBPF_HOST_ALIGN)));
  ulong need = sizeof(ulong) + sizeof(ulong) + 100UL + sizeof(fd_pubkey_t); /* 148 */

  for( int deprecated=0; deprecated<2; deprecated++ ) {
    for( ulong cap=0UL; cap<need; cap+=8UL ) {
      region_cnt = 0U;
      memset( frame, 0xee, sizeof(frame) );
      int err = fd_bpf_loader_input_serialize_parameters( ctx, frame, cap, pre_lens, regions, &region_cnt,
                                                          metas, 0, 0, 0, (uchar)deprecated, &idata_off, &sz );
      FD_TEST( err==FD_BPF_LOADER_SERIALIZE_FULL );
      for( ulong i=cap; i<sizeof(frame); i++ ) FD_TEST( frame[ i ]==0xee ); /* no write past cap */
    }
    region_cnt = 0U;
    int err = fd_bpf_loader_input_serialize_parameters( ctx, frame, need, pre_lens, regions, &region_cnt,
                                                        metas, 0, 0, 0, (uchar)deprecated, &idata_off, &sz );
    FD_TEST( !err );
    FD_TEST( sz==need );
    FD_TEST( FD_LOAD( ulong, frame )==0UL );                        /* acct_cnt */
    FD_TEST( FD_LOAD( ulong, frame+8 )==100UL );                    /* data len */
    FD_TEST( !memcmp( frame+16, info->data, 100UL ) );              /* data */
    FD_TEST( !memcmp( frame+116, txn_out->accounts.keys[ 0 ].key, 32UL ) ); /* program id */
  }

  FD_LOG_NOTICE(( "test_serialize_full: pass" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_arena_fifo();
  test_window_promotion();
  test_depth1_promote();
  test_serialize_full();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
