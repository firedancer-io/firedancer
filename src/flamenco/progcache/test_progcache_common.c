
#include "fd_progcache_admin.h"
#include "fd_progcache_user.h"
#include "../accdb/fd_accdb.h"

FD_FN_UNUSED static fd_pubkey_t
test_key( ulong x ) {
  fd_pubkey_t key = {0};
  key.ul[0] = x;
  return key;
}

#define TEST_ACCOUNT_DATA_MAX (1UL<<20)
struct test_account {
  fd_accdb_entry_t entry[1];
  uchar            buf[ TEST_ACCOUNT_DATA_MAX ];
};
typedef struct test_account test_account_t;

FD_FN_UNUSED static test_account_t *
test_account_init( test_account_t * acc,
                   void const *     address,
                   void const *     owner,
                   _Bool            executable,
                   void const *     data,
                   ulong            data_sz ) {
  if( data_sz > TEST_ACCOUNT_DATA_MAX ) FD_LOG_ERR(( "test_account_init: data_sz %lu exceeds max %lu", data_sz, TEST_ACCOUNT_DATA_MAX ));
  memset( acc->entry, 0, sizeof(fd_accdb_entry_t) );
  memcpy( acc->entry->pubkey, address, 32 );
  memcpy( acc->entry->owner, owner, 32 );
  acc->entry->lamports   = 42UL;
  acc->entry->executable = executable;
  acc->entry->data_len   = data_sz;
  acc->entry->data       = acc->buf;
  if( data_sz ) memcpy( acc->entry->data, data, data_sz );
  return acc;
}

struct test_case {
  char const * name;
  void      (* fn)( fd_wksp_t * wksp );
};

FD_FN_UNUSED static int
match_test_name( char const * test_name,
                 int          argc,
                 char **      argv ) {
  if( argc<=1 ) return 1;
  for( int i=1; i<argc; i++ ) {
    if( argv[ i ][ strspn( argv[ i ], " \t\n\r" ) ]=='\0' ) continue;
    if( strstr( test_name, argv[ i ] ) ) return 1;
  }
  return 0;
}
