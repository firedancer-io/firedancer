
#include "fd_progcache_admin.h"
#include "fd_progcache_user.h"

FD_FN_UNUSED static fd_pubkey_t
test_key( ulong x ) {
  fd_pubkey_t key = {0};
  key.ul[0] = x;
  return key;
}

struct test_account {
  fd_account_meta_t meta[1];
  fd_accdb_ro_t     ro[1];
};
typedef struct test_account test_account_t;

FD_FN_UNUSED static test_account_t *
test_account_init( test_account_t * acc,
                   void const *     address,
                   void const *     owner,
                   _Bool            executable,
                   void const *     data,
                   ulong            data_sz ) {
  memcpy( acc->meta->owner, owner, 32 );
  acc->meta->lamports   = 42UL;
  acc->meta->slot       = 0UL;
  acc->meta->dlen       = (uint)data_sz;
  acc->meta->executable = executable;
  fd_accdb_ro_init_nodb_oob( acc->ro, address, acc->meta, data );
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
