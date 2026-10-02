#include "fd_shred_batch.h"
#include "../../flamenco/runtime/fd_slot_params.h"
#include "../../util/fd_util.h"

/* The shred tile's include/close rule as it was written inline before
   fd_shred_batch_step. */

static int
step_ref( ulong pos,
          ulong entry_sz,
          int   block_complete,
          int   new_slot ) {
  ulong pending_batch_wmark = FD_SHRED_BATCH_WMARK_CHAINED;
  int is_marker                = block_complete==-1;
  int forced_end_batch         = block_complete | new_slot;
  int batch_would_exceed_wmark = ( pos + entry_sz ) > pending_batch_wmark;
  int include_in_current_batch = !is_marker && ( forced_end_batch | ( !batch_would_exceed_wmark ) );
  int process_current_batch    = is_marker ? !!pos : ( forced_end_batch | batch_would_exceed_wmark );
  return include_in_current_batch | (process_current_batch<<1);
}

static void
test_step( void ) {
  ulong const W = FD_SHRED_BATCH_WMARK_CHAINED;
  ulong const pos_tbl[] = { 0UL, 1UL, 48UL, W-4144UL, W-49UL, W-48UL, W-47UL, W-1UL, W };
  ulong const sz_tbl [] = { 48UL, 49UL, 1280UL, 4144UL, 8192UL, 20528UL, 28768UL };
  for( ulong i=0UL; i<sizeof(pos_tbl)/sizeof(pos_tbl[0]); i++ ) {
    for( ulong j=0UL; j<sizeof(sz_tbl)/sizeof(sz_tbl[0]); j++ ) {
      for( int bc=-1; bc<=1; bc++ ) {
        for( int ns=0; ns<=1; ns++ ) {
          ulong pos = pos_tbl[ i ];
          ulong sz  = sz_tbl [ j ];
          int   ref = step_ref( pos, sz, bc, ns );
          FD_TEST( fd_shred_batch_step( pos, sz, bc, ns )==ref );

          ulong next = fd_shred_batch_pos( pos, sz, bc, ns );
          if(      ref==FD_SHRED_BATCH_INCLUDE                 ) FD_TEST( next==pos+sz );
          else if( ref==FD_SHRED_BATCH_SHRED && bc!=-1         ) FD_TEST( next==sz     );
          else                                                   FD_TEST( next==0UL    );
        }
      }
    }
  }

  /* The edges */
  FD_TEST( fd_shred_batch_step( W-48UL, 48UL, 0, 0 )==FD_SHRED_BATCH_INCLUDE );
  FD_TEST( fd_shred_batch_step( W-47UL, 48UL, 0, 0 )==FD_SHRED_BATCH_SHRED   );
  FD_TEST( fd_shred_batch_step( W,      48UL, 1, 0 )==(FD_SHRED_BATCH_INCLUDE|FD_SHRED_BATCH_SHRED) );
  FD_TEST( fd_shred_batch_step( 0UL,    48UL, 0, 1 )==(FD_SHRED_BATCH_INCLUDE|FD_SHRED_BATCH_SHRED) );
  FD_TEST( fd_shred_batch_step( 0UL,    54UL,-1, 1 )==0                      );
  FD_TEST( fd_shred_batch_step( 1UL,    54UL,-1, 0 )==FD_SHRED_BATCH_SHRED   );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_step();

  /* One-txn microblocks (SMALL_MICROBLOCKS): largest shred-tile entry
     is header + FD_TPU_MTU. */
  ulong const M = sizeof(fd_entry_batch_header_t) + FD_TPU_MTU;
  FD_TEST( M==4144UL );

  /* Helper must fail closed on impossible inputs. */
  FD_TEST( !fd_shred_batch_pack_data_max( 0UL, M ) );
  FD_TEST( !fd_shred_batch_pack_data_max( 96UL, M ) ); /* 3 FEC, less than first+last reserve */
  FD_TEST( !fd_shred_batch_pack_data_max( 128UL, 31000UL ) ); /* 4 FEC; last batch needs 4 */
  FD_TEST( !fd_shred_batch_pack_data_max( 24576UL, FD_SHRED_BATCH_WMARK_CHAINED ) );

  /* Helper is nonzero at every slot-time shred count.  Fewer shreds
     must yield a strictly smaller byte budget.  shred_safe is below
     the no-padding payload (every data shred full). */
  fd_slot_params_t const stages[] = {
    FD_SLOT_PARAMS_400MS,
    FD_SLOT_PARAMS_350MS,
    FD_SLOT_PARAMS_300MS,
    FD_SLOT_PARAMS_250MS,
    FD_SLOT_PARAMS_200MS,
  };
  ulong prev = ULONG_MAX;
  for( ulong i=0UL; i<sizeof(stages)/sizeof(stages[0]); i++ ) {
    ulong shreds                        = stages[i].max_shred_idx;
    ulong max_stage_data_shred_capacity = ( shreds / 32UL ) * FD_SHREDDER_CHAINED_FEC_SET_PAYLOAD_SZ;
    ulong shred_safe                    = fd_shred_batch_pack_data_max( shreds, M );
    FD_TEST( shred_safe );
    FD_TEST( shred_safe<prev );
    FD_TEST( shred_safe<max_stage_data_shred_capacity );
    prev = shred_safe;
  }

  /* Large microblocks pad more, so the same shred count yields
     fewer entry bytes.  Last batch can need 3 or 4 resigned FEC
     sets. */
  ulong const M_large                       = 30000UL;
  ulong const shreds_300                    = FD_SLOT_PARAMS_300MS.max_shred_idx;
  ulong const max_stage_data_shred_capacity = ( shreds_300 / 32UL ) * FD_SHREDDER_CHAINED_FEC_SET_PAYLOAD_SZ;
  ulong       shred_large                   = fd_shred_batch_pack_data_max( shreds_300, M_large );
  FD_TEST( shred_large );
  FD_TEST( shred_large<fd_shred_batch_pack_data_max( shreds_300, M ) );
  FD_TEST( shred_large<max_stage_data_shred_capacity );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
