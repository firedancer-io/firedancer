#include "../../ballet/fd_ballet_base.h"
#include "../../ballet/base58/fd_base58.h"
#include "fd_pack_tip_prog_blacklist.h"

static inline void
test( char const * base58_pubkey,
      int          banned_for_bundles,
      int          banned_for_nonbundles ) {
  fd_acct_addr_t pubkey[1];
  FD_TEST( fd_base58_decode_32( base58_pubkey, pubkey->b ) );
  int expected = (banned_for_bundles ? 2 : 0 ) | (banned_for_nonbundles ? 1 : 0 );
  FD_TEST( fd_pack_tip_prog_check_blacklist( pubkey )==expected );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* mainnet, testnet programs */
  test( "T1pyyaTNZsKv2WcRAB8oVnk93mLJw2XzjtVYqCsaHqt",  1, 1 );
  test( "DCN82qDxJAQuSqHhv2BJuAgi41SPeKZB5ioBCTMNDrCC", 1, 1 );
  /* tip payment accounts */
  test( "96gYZGLnJYVFmbjzopPSU6QiEV5fGqZNyN9nmNhvrZU5", 0, 1 );
  test( "HFqU5x63VTqvQss8hp11i4wVV8bD44PvwucfZ2bU7gRe", 0, 1 );
  test( "Cw8CFyM9FkoMi7K7Crf6HNQqf4uEMzpKw6QNghXLvLkY", 0, 1 );
  test( "ADaUMid9yfUytqMBgopwjb2DTLSokTSzL1zt6iGPaS49", 0, 1 );
  test( "DfXygSm4jCyNCybVYYK6DwvWqjKee8pbDmJGcLWNDXjh", 0, 1 );
  test( "ADuUkR4vqLUMWXxW9gh6D6L8pMSawimctcNZ5pGwDcEt", 0, 1 );
  test( "DttWaMuVvTiduZRnguLF7jNxTgiMBZ1hyAumKUiL2KRL", 0, 1 );
  test( "3AVi9Tg9Uo68tJfuvoKvqKNWKkC5wPdSSdeBnizKZ6jT", 0, 1 );
  /* testnet tip payment accounts */
  test( "BkMx5bRzQeP6tUZgzEs3xeDWJfQiLYvNDqSgmGZKYJDq", 0, 1 );
  test( "CwWZzvRgmxj9WLLhdoWUVrHZ1J8db3w2iptKuAitHqoC", 0, 1 );
  test( "4uRnem4BfVpZBv7kShVxUYtcipscgZMSHi3B9CSL6gAA", 0, 1 );
  test( "AzfhMPcx3qjbvCK3UUy868qmc5L451W341cpFqdL3EBe", 0, 1 );
  test( "84DrGKhycCUGfLzw8hXsUYX9SnWdh2wW3ozsTPrC5xyg", 0, 1 );
  test( "7aewvu8fMf1DK4fKoMXKfs3h3wpAQ7r7D8T1C71LmMF",  0, 1 );
  test( "G2d63CEgKBdgtpYT2BuheYQ9HFuFCenuHLNyKVpqAuSD", 0, 1 );
  test( "F7ThiQUBYiEcyaxpmMuUeACdoiSLKg4SZZ8JSfpFNwAf", 0, 1 );
  /* tip payment config account */
  test( "HgzT81VF1xZ3FT9Eq1pHhea7Wcfq2bv4tWTP3VvJ8Y9D", 0, 1 );
  test( "AXaHLTKzVyRUccE8bPskqsnc1YcTd648PjmMwKWS7R6N", 0, 1 );

  /* Some arbitrary accounts that are okay */
  test( "ComputeBudget111111111111111111111111111111",  0, 0 );
  test( "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL", 0, 0 );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
