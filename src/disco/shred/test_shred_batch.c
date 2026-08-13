#include "fd_shred_batch.h"
#include "../../flamenco/runtime/fd_slot_params.h"
#include "../../util/fd_util.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* One-txn microblocks (SMALL_MICROBLOCKS): largest shred-tile entry
     is header + FD_TPU_MTU. */
  ulong const M = sizeof(fd_entry_batch_header_t) + FD_TPU_MTU;
  FD_TEST( M==4144UL );

  /* Helper must fail closed on impossible inputs. */
  FD_TEST( !fd_shred_batch_pack_data_max( 0UL, M ) );
  FD_TEST( !fd_shred_batch_pack_data_max( 96UL, M ) ); /* 3 FEC, less than first+last reserve */
  FD_TEST( !fd_shred_batch_pack_data_max( 128UL, 30000UL ) ); /* 4 FEC; last batch needs 4 */
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
