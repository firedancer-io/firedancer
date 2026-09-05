#include "../../util/fd_util_base.h"
#include "fd_borrowed_account.h"
#include <string.h>

/* Helper to invoke fd_borrowed_account_is_zeroed on a (data,data_len) pair. */
static int
is_zeroed( uchar const * data, ulong data_len ) {
  fd_acc_t              acc[1] = {0};
  fd_borrowed_account_t ba [1] = {0};
  acc->data     = (uchar *)data;
  acc->data_len = data_len;
  ba->acc       = acc;
  return fd_borrowed_account_is_zeroed( ba );
}

static uchar scratch[ 8192 ] __attribute__((aligned(4096)));
static ulong const test_sz[] = { 0UL, 1UL, 63UL, 64UL, 65UL, 255UL, 256UL, 257UL,
                                 300UL, 511UL, 512UL, 513UL, 700UL, 1023UL, 1024UL,
                                 1025UL, 1536UL, 2048UL };
#define TEST_SZ_CNT (sizeof(test_sz)/sizeof(test_sz[0]))

/* Start offsets mimic account data that is not 64-byte aligned. */
static ulong const test_off[] = { 0UL, 1UL, 8UL, 24UL, 40UL, 63UL };
#define TEST_OFF_CNT (sizeof(test_off)/sizeof(test_off[0]))

static void
test_is_zeroed( void ) {
  FD_LOG_NOTICE(( "Testing fd_borrowed_account_is_zeroed" ));

  /* Test case 1: an empty account (data==NULL, len==0) is zeroed. */
  FD_TEST( is_zeroed( NULL, 0UL )==1 );

  /* Test case 2: sweep size and start offset. */
  for( ulong oi=0UL; oi<TEST_OFF_CNT; oi++ ) {
    for( ulong si=0UL; si<TEST_SZ_CNT; si++ ) {
      uchar * data = scratch + test_off[ oi ];
      ulong   sz   = test_sz[ si ];

      memset( data, 0, sz );
      FD_TEST( is_zeroed( data, sz )==1 );

      for( ulong pos=0UL; pos<sz; pos++ ) {
        data[ pos ] = 0xff; FD_TEST( is_zeroed( data, sz )==0 );
        data[ pos ] = 0x00; FD_TEST( is_zeroed( data, sz )==1 );
      }
    }
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_is_zeroed();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
