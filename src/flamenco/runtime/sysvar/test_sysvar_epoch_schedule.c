#include "fd_sysvar_epoch_schedule.h"

#include <stddef.h>

FD_STATIC_ASSERT( alignof ( fd_epoch_schedule_t                              )==0x08UL, layout );
FD_STATIC_ASSERT( offsetof( fd_epoch_schedule_t, slots_per_epoch             )==0x00UL, layout );
FD_STATIC_ASSERT( offsetof( fd_epoch_schedule_t, leader_schedule_slot_offset )==0x08UL, layout );
FD_STATIC_ASSERT( offsetof( fd_epoch_schedule_t, warmup                      )==0x10UL, layout );
FD_STATIC_ASSERT( offsetof( fd_epoch_schedule_t, first_normal_epoch          )==0x18UL, layout );
FD_STATIC_ASSERT( offsetof( fd_epoch_schedule_t, first_normal_slot           )==0x20UL, layout );
FD_STATIC_ASSERT( sizeof  ( fd_epoch_schedule_t                              )==0x28UL, layout );

static void
test_sysvar_epoch_schedule_bounds( void ) {
  /* Real sysvar account observed on-chain */
  static uchar const data[] = {
    0x80, 0x97, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x80, 0x97, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00
  };
  FD_TEST( sizeof(data)==FD_SYSVAR_EPOCH_SCHEDULE_BINCODE_SZ );
  fd_bincode_decode_ctx_t ctx = { .data=data, .dataend=data+sizeof(data) };
  ulong obj_sz = 0UL;
  FD_TEST( fd_epoch_schedule_decode_footprint( &ctx, &obj_sz )==FD_BINCODE_SUCCESS );
  FD_TEST( obj_sz==FD_SYSVAR_EPOCH_SCHEDULE_FOOTPRINT );
  FD_TEST( fd_epoch_schedule_align()==FD_SYSVAR_EPOCH_SCHEDULE_ALIGN );
}

static void
test_sysvar_epoch_schedule_edge_case( void ) {
  fd_epoch_schedule_t schedule = { .slots_per_epoch=0UL };
  FD_TEST( fd_slot_to_epoch( &schedule, 0UL, NULL )==0UL );

  FD_TEST( fd_epoch_schedule_derive( &schedule, 31UL, 31UL, 0 )==NULL );
}

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

static void
test_sysvar_epoch_schedule_testnet( void ) {
  fd_epoch_schedule_t const schedule = {
    .slots_per_epoch             = 432000,
    .leader_schedule_slot_offset = 432000,
    .warmup                      =      1,
    .first_normal_epoch          =     14,
    .first_normal_slot           = 524256
  };

  FD_TEST( fd_slot_to_leader_schedule_epoch( &schedule,      1UL )== 1UL );
  FD_TEST( fd_slot_to_leader_schedule_epoch( &schedule, 524256UL )==15UL );
  FD_TEST( fd_slot_to_leader_schedule_epoch( &schedule, 956255UL )==15UL );
  FD_TEST( fd_slot_to_leader_schedule_epoch( &schedule, 956256UL )==16UL );

  ulong offset = 9UL;
  FD_TEST( fd_slot_to_epoch( &schedule, 524256UL, &offset )==14UL && offset==0UL );
  FD_TEST( fd_slot_to_epoch( &schedule, 524257UL, &offset )==14UL && offset==1UL );
  for( ulong off=0UL; off<432000UL; off++ ) {
    FD_TEST( fd_slot_to_epoch( &schedule, 524256UL+off, &offset )==14UL && offset==off );
  }
  FD_TEST( fd_slot_to_epoch( &schedule, 956256UL, &offset )==15UL && offset==0UL );

  FD_TEST( fd_epoch_slot0( &schedule,  0UL )==     0UL );
  FD_TEST( fd_epoch_slot0( &schedule,  1UL )==    32UL );
  FD_TEST( fd_epoch_slot0( &schedule, 14UL )==524256UL );
  FD_TEST( fd_epoch_slot0( &schedule, 15UL )==956256UL );

  FD_TEST( fd_epoch_slot_cnt( &schedule, 14UL )==432000UL );
}

void
test_sysvar_epoch_schedule( void ) {
  test_sysvar_epoch_schedule_bounds();
  test_sysvar_epoch_schedule_edge_case();
  for( fd_epoch_schedule_t const * vec = fd_epoch_schedule_test_vectors;
       vec->slots_per_epoch;       vec++ ) {
    test_epoch_schedule_derive( vec );
    test_epoch_schedule       ( vec );
  }
  test_sysvar_epoch_schedule_testnet();
}
