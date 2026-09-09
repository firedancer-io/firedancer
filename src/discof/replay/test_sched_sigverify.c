#include "fd_sched.h"
#include "fd_execrp.h"
#include "../../tango/dcache/fd_dcache.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../flamenco/txn/fd_txn_generate.h"
#include "../../flamenco/leaders/fd_leaders_base.h"
#include <stdlib.h>

/* Complete execution and PoH but hold sigverify groups.  This leaves
   transactions in rdisp's ZOMBIE state.  Retire groups and members in
   reverse order, optionally abandoning their bank while outstanding. */
static void
run_group_case( ulong txn_cnt, ulong const * sizes, int abandon, int hold_exec ) {
  ulong footprint = fd_sched_footprint( FD_SCHED_MIN_DEPTH, 4UL, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT );
  void * mem = aligned_alloc( fd_sched_align(), footprint );
  FD_TEST( mem );
  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  fd_sched_t * sched = fd_sched_join( fd_sched_new( mem, rng, FD_SCHED_MIN_DEPTH, 4UL, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT, 4UL, 0 ) );
  FD_TEST( sched );
  fd_sched_set_bypass_poh_verify( sched, 1 );
  fd_sched_block_add_done( sched, 1UL, ULONG_MAX, 1000UL );

  fd_pubkey_t payer[1] = {{ .ul = { 1UL } }};
  fd_pubkey_t program[1] = {{ .ul = { 2UL } }};
  fd_txn_accounts_t accounts = {
    .signature_cnt = 1U, .readonly_unsigned_cnt = 1U,
    .acct_cnt = 2U, .signers_w = payer, .non_signers_r = program
  };
  uchar meta[ FD_TXN_MAX_SZ ] __attribute__((aligned(alignof(fd_txn_t))));
  uchar payload[ FD_TXN_MTU ] = {0};
  fd_txn_base_generate( meta, payload, 1UL, &accounts, NULL );
  uchar acct = 0U;
  uchar data = 0U;
  ulong txn_sz = fd_txn_add_instr( meta, payload, 1U, &acct, 1UL, &data, 1UL );
  fd_txn_t const * txn = fd_type_pun_const( meta );

  uchar encoded[ 32768 ];
  ulong payload_szs[ 17 ];
  FD_STORE( ulong, encoded, 2UL );
  fd_microblock_hdr_t hdr = { .hash_cnt = 1UL, .txn_cnt = txn_cnt };
  fd_memcpy( encoded+sizeof(ulong), &hdr, sizeof(hdr) );
  ulong encoded_sz = sizeof(ulong)+sizeof(hdr);
  for( ulong i=0UL; i<txn_cnt; i++ ) {
    if( sizes ) {
      txn_sz = sizes[i];
      fd_memset( payload, 0, sizeof(payload) );
      if( txn_sz>FD_TXN_MTU_V0 ) {
        /* V1: message first, signatures last; one instruction whose
           data fills the requested wire size. */
        FD_TEST( txn_sz>=174UL && txn_sz<=FD_TXN_MTU );
        payload[0] = 0x81U; payload[1] = 1U; payload[3] = 1U;
        payload[40] = 1U; payload[41] = 2U;
        payload[42] = 1U; payload[74] = 2U;
        payload[106] = 1U;
        FD_STORE( ushort, payload+108UL, (ushort)(txn_sz-174UL) );
      } else {
        ulong base = fd_txn_base_generate( meta, payload, 1UL, &accounts, NULL );
        ulong data_sz = txn_sz-base-5UL;
        if( data_sz>=128UL ) data_sz--;
        uchar instr_data[ FD_TXN_MTU_V0 ] = {0};
        FD_TEST( fd_txn_add_instr( meta, payload, 1U, &acct, 1UL, instr_data, data_sz )==txn_sz );
      }
      FD_TEST( fd_txn_parse( payload, txn_sz, meta, NULL ) );
    }
    payload_szs[i] = txn_sz;
    FD_STORE( ulong, payload+txn->signature_off, i );
    fd_memcpy( encoded+encoded_sz, payload, txn_sz );
    encoded_sz += txn_sz;
  }
  FD_TEST( encoded_sz<=sizeof(encoded) );
  fd_store_fec_t store[1] = {0};
  store->data_sz = encoded_sz;
  store->shred_offs[0] = (uint)encoded_sz;
  fd_sched_fec_t fec[1] = {{
    .bank_idx = 2UL, .parent_bank_idx = 1UL, .slot = 1001UL, .parent_slot = 1000UL,
    .fec = store, .data = encoded, .shred_cnt = 1U, .is_first_in_block = 1U
  }};
  FD_TEST( fd_sched_fec_can_ingest( sched, fec ) );
  FD_TEST( fd_sched_fec_ingest( sched, fec ) );
  fd_hash_t poh[1] = {0};
  fd_sched_set_poh_params( sched, 2UL, 0UL, 1UL, 64UL, poh );

  fd_sched_txn_sigverify_t groups[3];
  ulong group_cnt = 0UL;
  ulong dispatched_cnt = 0UL;
  ulong exec_cnt = 0UL;
  fd_sched_txn_exec_t held_exec = {0};
  for( ulong step=0UL; step<100UL; step++ ) {
    fd_sched_task_t task[1];
    if( !fd_sched_task_next_ready( sched, task ) ) {
      if( held_exec.txn_idx ) {
        FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_TXN_EXEC, held_exec.txn_idx, held_exec.exec_idx, NULL ) );
        held_exec.txn_idx = 0UL;
        continue;
      }
      break;
    }
    switch( task->task_type ) {
      case FD_SCHED_TT_BLOCK_START:
        FD_TEST( !fd_sched_task_done( sched, task->task_type, ULONG_MAX, ULONG_MAX, NULL ) );
        break;
      case FD_SCHED_TT_TXN_EXEC:
        if( hold_exec && !exec_cnt ) held_exec = *task->txn_exec;
        else FD_TEST( !fd_sched_task_done( sched, task->task_type, task->txn_exec->txn_idx, task->txn_exec->exec_idx, NULL ) );
        exec_cnt++;
        break;
      case FD_SCHED_TT_POH_HASH: {
        fd_execrp_poh_hash_done_msg_t done[1];
        done->cnt = task->poh_hash->cnt;
        for( ulong i=0UL; i<done->cnt; i++ )
          fd_sha256_hash_32_repeated( task->poh_hash->hash+i, done->hash+i, task->poh_hash->hashcnt );
        FD_TEST( !fd_sched_task_done( sched, task->task_type, ULONG_MAX, task->poh_hash->exec_idx, done ) );
        break;
      }
      case FD_SCHED_TT_TXN_SIGVERIFY: {
        FD_TEST( group_cnt<3UL );
        fd_sched_txn_sigverify_t * group = task->txn_sigverify;
        ulong expected_cnt = 0UL;
        ulong expected_bytes = 0UL;
        while( expected_cnt<FD_SCHED_SIGVERIFY_MAX && dispatched_cnt+expected_cnt<txn_cnt ) {
          ulong sz = payload_szs[dispatched_cnt+expected_cnt];
          if( sz>FD_SCHED_SIGVERIFY_BYTES-expected_bytes ) break;
          expected_bytes += sz;
          expected_cnt++;
        }
        FD_TEST( group->cnt==expected_cnt );
        fd_execrp_txn_sigverify_msg_t msg[1] = {{0}};
        FD_TEST( group->bank_idx==2UL );
        for( ulong j=0UL; j<group_cnt; j++ ) FD_TEST( group->exec_idx!=groups[j].exec_idx );
        for( ulong i=0UL; i<group->cnt; i++ ) {
          fd_txn_p_t * txn_p = fd_sched_get_txn( sched, group->txn_idx[i] );
          FD_TEST( FD_LOAD( ulong, txn_p->payload+TXN(txn_p)->signature_off )==dispatched_cnt++ );
          fd_execrp_sigverify_add( msg, group->txn_idx[i], txn_p );
          FD_TEST( msg->txn[i].message_sz==fd_txn_msg_sz( TXN(txn_p), txn_p->payload_sz ) );
          FD_TEST( !memcmp( msg->payload+msg->txn[i].payload_off, txn_p->payload, txn_p->payload_sz ) );
          fd_sched_txn_info_t * info = fd_sched_get_txn_info( sched, group->txn_idx[i] );
          FD_TEST( info->tick_sigverify_disp!=LONG_MAX );
          FD_TEST( info->sigverify_exec_tile_idx==group->exec_idx );
          if( !hold_exec ) FD_TEST( info->flags&FD_SCHED_TXN_EXEC_DONE );
          FD_TEST( !(info->flags&FD_SCHED_TXN_SIGVERIFY_DONE) );
        }
        FD_TEST( msg->payload_used==expected_bytes );
        if( hold_exec==2 ) {
          for( ulong i=group->cnt; i; i-- )
            FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_TXN_SIGVERIFY, group->txn_idx[i-1UL], group->exec_idx, NULL ) );
        } else groups[group_cnt++] = *group;
        break;
      }
      default: FD_LOG_ERR(( "unexpected task %lu", task->task_type ));
    }
  }
  FD_TEST( exec_cnt==txn_cnt && dispatched_cnt==txn_cnt );
  /* Incomplete block: tails dispatched without another FEC or EOS. */
  FD_TEST( fd_sched_pruned_block_next( sched )==ULONG_MAX );
  if( abandon ) fd_sched_block_abandon( sched, 2UL, FD_SCHED_ABANDON_INVALID );
  ulong remaining = hold_exec==2 ? 0UL : txn_cnt;
  for( ulong g=group_cnt; g; g-- ) {
    fd_sched_txn_sigverify_t * group = groups+g-1UL;
    for( ulong i=group->cnt; i; i-- ) {
      FD_TEST( fd_sched_pruned_block_next( sched )==ULONG_MAX );
      ulong idx = group->txn_idx[i-1UL];
      FD_TEST( !fd_sched_task_done( sched, FD_SCHED_TT_TXN_SIGVERIFY, idx, group->exec_idx, NULL ) );
      remaining--;
      FD_TEST( fd_sched_get_txn_info( sched, idx )->flags&FD_SCHED_TXN_SIGVERIFY_DONE );
      if( remaining || !abandon ) FD_TEST( fd_sched_pruned_block_next( sched )==ULONG_MAX );
    }
  }
  if( !abandon ) fd_sched_block_abandon( sched, 2UL, FD_SCHED_ABANDON_DISCARDED );
  FD_TEST( fd_sched_pruned_block_next( sched )==2UL );
  FD_TEST( fd_sched_pruned_block_next( sched )==ULONG_MAX );
  fd_sched_cancel( sched, 2UL );
  FD_TEST( fd_sched_is_drained( sched ) );
  fd_sched_delete( fd_sched_leave( sched ) );
  free( mem );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  ulong counts[] = { 1UL, 3UL, 8UL, 11UL, 17UL };
  for( ulong i=0UL; i<sizeof(counts)/sizeof(counts[0]); i++ ) {
    run_group_case( counts[i], NULL, 0, 0 );
    run_group_case( counts[i], NULL, 1, 0 );
  }
  ulong singleton[] = { 4096UL };
  ulong exact[]     = { 4096UL, 4096UL, 1664UL, 256UL };
  ulong overflow[]  = { 4096UL, 4096UL, 1665UL, 256UL };
  ulong mixed[]     = { 1232UL, 4096UL, 1232UL, 4096UL, 1232UL };
  for( int abandon=0; abandon<2; abandon++ ) {
    run_group_case( 1UL, singleton, abandon, 0 );
    run_group_case( 4UL, exact,     abandon, 0 );
    run_group_case( 4UL, overflow,  abandon, 0 );
    run_group_case( 5UL, mixed,     abandon, 0 );
  }
  /* Hold the head of the conflicting execution chain while groups are
     dispatched.  Either keep signatures outstanding during subsequent
     execution or complete them before execution has started. */
  run_group_case( 17UL, NULL, 0, 1 );
  run_group_case( 17UL, NULL, 1, 1 );
  run_group_case( 17UL, NULL, 0, 2 );
  FD_LOG_NOTICE(( "scheduler footprint %lu, dispatch MTU %lu, completion MTU %lu",
                 fd_sched_footprint( 65536UL, 2048UL, FD_SHRED_BLK_MAX, FD_MAX_TXN_PER_SLOT ),
                 sizeof(fd_execrp_task_msg_t), sizeof(fd_execrp_task_done_msg_t) ));
  FD_LOG_NOTICE(( "replay_execrp dcache bytes (depth 16384, compact burst 1): baseline %lu, grouped %lu",
                 fd_dcache_req_data_sz( sizeof(fd_execrp_txn_exec_msg_t), 16384UL, 1UL, 1 ),
                 fd_dcache_req_data_sz( sizeof(fd_execrp_task_msg_t), 16384UL, 1UL, 1 ) ));
  FD_LOG_NOTICE(( "replay_epoch dcache bytes (compact burst 1): depth 16 %lu, depth 32 %lu",
                 fd_dcache_req_data_sz( FD_EPOCH_OUT_MTU, 16UL, 1UL, 1 ),
                 fd_dcache_req_data_sz( FD_EPOCH_OUT_MTU, 32UL, 1UL, 1 ) ));
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
