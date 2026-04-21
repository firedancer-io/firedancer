#include "fd_sysvar_epoch_rewards.h"
#include "../../types/fd_types.h"

FD_STATIC_ASSERT( alignof ( fd_sysvar_epoch_rewards_t                                     )==0x10UL, layout );
FD_STATIC_ASSERT( offsetof( fd_sysvar_epoch_rewards_t, distribution_starting_block_height )==0x00UL, layout );
FD_STATIC_ASSERT( offsetof( fd_sysvar_epoch_rewards_t, num_partitions                     )==0x08UL, layout );
FD_STATIC_ASSERT( offsetof( fd_sysvar_epoch_rewards_t, parent_blockhash                   )==0x10UL, layout );
FD_STATIC_ASSERT( offsetof( fd_sysvar_epoch_rewards_t, total_points                       )==0x30UL, layout );
FD_STATIC_ASSERT( offsetof( fd_sysvar_epoch_rewards_t, total_rewards                      )==0x40UL, layout );
FD_STATIC_ASSERT( offsetof( fd_sysvar_epoch_rewards_t, distributed_rewards                )==0x48UL, layout );
FD_STATIC_ASSERT( offsetof( fd_sysvar_epoch_rewards_t, active                             )==0x50UL, layout );
FD_STATIC_ASSERT( sizeof  ( fd_sysvar_epoch_rewards_t                                     )==0x60UL, layout );

static void
test_sysvar_epoch_rewards_bounds( void ) {
  /* Real sysvar account observed on-chain */
  static uchar const data[] = {
    0x24, 0x1e, 0xd7, 0x13, 0x00, 0x00, 0x00, 0x00,
    0xfb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x22, 0xc7, 0x32, 0x75, 0xb1, 0x43, 0xba, 0x37,
    0xac, 0x29, 0xf2, 0x25, 0x1a, 0xae, 0x87, 0x2f,
    0x2d, 0x9d, 0x38, 0x62, 0x94, 0x8d, 0xdc, 0xd5,
    0x33, 0x18, 0xe1, 0x43, 0xc2, 0x25, 0x7f, 0x4c,
    0xc6, 0x38, 0xa8, 0x7c, 0x28, 0xb3, 0xcb, 0x95,
    0x5b, 0x48, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x4f, 0x3a, 0xbf, 0x62, 0xae, 0x84, 0x00, 0x00,
    0xc7, 0xb8, 0xad, 0x62, 0xae, 0x84, 0x00, 0x00,
    0x00
  };
  FD_TEST( sizeof(data)==FD_SYSVAR_EPOCH_REWARDS_BINCODE_SZ );
}

static void
test_sysvar_epoch_rewards( void ) {
  test_sysvar_epoch_rewards_bounds();
  /* FIXME more tests here ... */
}
