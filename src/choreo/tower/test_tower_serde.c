#include "fd_tower.h"
#include "fd_tower_serde.h"

void
test_serde( void ) {
  // fd_tower_sync_serde_t serde;
  // serde.root = 359716198;
  // serde.lockouts_cnt = 31;
  // for( ushort i=0; i<31; i++ ) {
  //   serde.lockouts[i].offset             = 1;
  //   serde.lockouts[i].confirmation_count = (uchar)(31-i);
  // }
  // serde.hash             = (fd_hash_t){{42}};
  // serde.timestamp_option = 1;
  // serde.timestamp        = 1758832061;
  // serde.block_id         = (fd_hash_t){{42}};
  // FD_LOG_NOTICE(( "serde->timestamp_option %u", serde.timestamp_option ));

  // uchar ser[2048];
  // ulong sz; fd_tower_sync_serialize( &serde, ser, sizeof(ser), &sz );
  // FD_LOG_NOTICE(( "sz %lu", sz ));
  // /* 136 bytes */

  // // uchar const pubkey[32] = { 0x32, 0x73, 0x61, 0x45, 0x02, 0x2d, 0x33, 0x72, 0x48, 0x01, 0x79, 0x11, 0x0d, 0x30, 0x71, 0x7e, 0xef, 0xf4, 0xf2, 0x84, 0xca, 0xe7, 0x6a, 0xbe, 0x4c, 0xaa, 0x77, 0x38, 0xda, 0xad, 0x06, 0x2b };

  // // fd_tower_file_serde_t serde = { 0 };
  // // fd_tower_deserialize( restore, sizeof(restore), &serde );

  // // uchar checkpt[sizeof(restore)];
  // // ulong checkpt_sz;
  // // fd_tower_serialize( &serde, checkpt, sizeof(checkpt), &checkpt_sz );

  // // FD_TEST( sizeof(restore) == checkpt_sz );
  // // FD_TEST( fd_uint_load_4( restore ) == fd_uint_load_4( checkpt ) );

  // // ulong off = sizeof(uint) + FD_ED25519_SIG_SZ + sizeof(ulong);
  // // FD_TEST( fd_uint_load_4_fast( restore )==fd_uint_load_4_fast( checkpt ) ); /* kind */
  // // /* skip comparing sig and data_sz (populated outside serialize) */
  // // FD_TEST( 0==memcmp( restore + off, checkpt + off, sizeof(restore) - off ) );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  test_serde();

  fd_halt();
  return 0;
}
