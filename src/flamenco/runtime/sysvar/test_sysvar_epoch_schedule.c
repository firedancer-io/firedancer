#include "fd_sysvar_epoch_schedule.h"

#include <stddef.h>

FD_STATIC_ASSERT( alignof ( fd_epoch_schedule_t                              )==0x08UL, layout );
FD_STATIC_ASSERT( offsetof( fd_epoch_schedule_t, slots_per_epoch             )==0x00UL, layout );
FD_STATIC_ASSERT( offsetof( fd_epoch_schedule_t, leader_schedule_slot_offset )==0x08UL, layout );
FD_STATIC_ASSERT( offsetof( fd_epoch_schedule_t, warmup                      )==0x10UL, layout );
FD_STATIC_ASSERT( offsetof( fd_epoch_schedule_t, first_normal_epoch          )==0x18UL, layout );
FD_STATIC_ASSERT( offsetof( fd_epoch_schedule_t, first_normal_slot           )==0x20UL, layout );
FD_STATIC_ASSERT( sizeof  ( fd_epoch_schedule_t                              )==0x28UL, layout );

static fd_epoch_schedule_t const
fd_epoch_schedule_test_vectors[] = {
  { .slots_per_epoch=  32, .first_normal_epoch=0, .first_normal_slot=   0 },
  { .slots_per_epoch=  33, .first_normal_epoch=1, .first_normal_slot=  32 },
  { .slots_per_epoch=  65, .first_normal_epoch=2, .first_normal_slot=  96 },
  { .slots_per_epoch= 129, .first_normal_epoch=3, .first_normal_slot= 224 },
  { .slots_per_epoch= 257, .first_normal_epoch=4, .first_normal_slot= 480 },
  { .slots_per_epoch= 513, .first_normal_epoch=5, .first_normal_slot= 992 },
  { .slots_per_epoch=1025, .first_normal_epoch=6, .first_normal_slot=2016 },
  { .slots_per_epoch=2049, .first_normal_epoch=7, .first_normal_slot=4064 },
  {0}
};

void
test_epoch_schedule_derive( fd_epoch_schedule_t const * t ) {

  ulong epoch_len = t[0].slots_per_epoch;

  while( epoch_len < t[1].slots_per_epoch ) {
    /* With warmup */

    fd_epoch_schedule_t schedule;
    fd_epoch_schedule_derive(  &schedule,
        /* epoch length     */ epoch_len,
        /* leader sched off */ epoch_len / 2,
        /* warmup           */ 1 );

    FD_TEST( schedule.slots_per_epoch             == epoch_len             );
    FD_TEST( schedule.leader_schedule_slot_offset == epoch_len / 2UL       );
    FD_TEST( schedule.first_normal_epoch          == t->first_normal_epoch );
    FD_TEST( schedule.first_normal_slot           == t->first_normal_slot  );
    FD_TEST( schedule.warmup                      == 1                     );

    /* Without warmup */

    fd_epoch_schedule_derive(  &schedule,
        /* epoch length     */ epoch_len,
        /* leader sched off */ epoch_len / 2,
        /* warmup           */ 0 );

    FD_TEST( schedule.slots_per_epoch             == epoch_len       );
    FD_TEST( schedule.leader_schedule_slot_offset == epoch_len / 2UL );
    FD_TEST( schedule.first_normal_epoch          == 0UL             );
    FD_TEST( schedule.first_normal_slot           == 0UL             );
    FD_TEST( schedule.warmup                      == 0               );

    epoch_len++;
  }
}

void
test_epoch_schedule( fd_epoch_schedule_t const * t ) {

  ulong last_epoch    = 0UL;
  ulong last_slot_idx = ULONG_MAX;

  ulong slot;
  for( slot=0UL; slot < t->first_normal_slot; slot++ ) {
    ulong slot_idx;
    ulong epoch = fd_slot_to_epoch( t, slot, &slot_idx );

    FD_TEST( /* Epoch number increases monotonically */
             (   epoch    >= last_epoch             )
             /* Epoch number increases max by one */
           & (   epoch    <= last_epoch + 1UL       )
             /* Slot index must increment within epoch */
           & ( ( epoch    >  last_epoch           )
             | ( slot_idx == last_slot_idx + 1UL  ) ) );

    if( epoch > last_epoch ) {
      /* Correctly calculates first epoch slot */
      FD_TEST( fd_epoch_slot0( t, epoch )==slot );
      /* Correctly calculates epoch length */
      FD_TEST( fd_epoch_slot_cnt( t, epoch )
               == ( fd_epoch_slot0( t, epoch+1UL )
                  - fd_epoch_slot0( t, epoch     ) ) );
    }

    /* Wind up for next iteration */
    last_epoch    = epoch;
    last_slot_idx = (epoch>last_epoch) ? 0UL : slot_idx;
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  for( fd_epoch_schedule_t const * vec = fd_epoch_schedule_test_vectors;
       vec->slots_per_epoch;       vec++ ) {

    test_epoch_schedule_derive( vec );
    test_epoch_schedule       ( vec );

  }

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
