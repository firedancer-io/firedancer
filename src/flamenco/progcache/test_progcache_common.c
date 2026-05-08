
#include "fd_progcache_admin.h"
#include "fd_progcache_user.h"
#include "../runtime/fd_system_ids.h"
#include "../runtime/program/fd_bpf_loader_program.h"
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

FD_FN_UNUSED static test_account_t *
test_account_init_v3( test_account_t * acc,
                      uchar *          buf,
                      ulong            buf_max,
                      void const *     address,
                      void const *     progdata_address ) {

  struct __attribute__((packed)) {
    uint        kind;
    fd_pubkey_t progdata_address;
  } v3_state = {
    .kind             = FD_BPF_STATE_PROGRAM,
    .progdata_address = FD_LOAD( fd_pubkey_t, progdata_address )
  };
  FD_TEST( buf_max>=sizeof(v3_state) );
  fd_memcpy( buf, &v3_state, sizeof(v3_state) );

  memset( acc->entry, 0, sizeof(fd_accdb_entry_t) );
  memcpy( acc->entry->pubkey, address, 32 );
  memcpy( acc->entry->owner, &fd_solana_bpf_loader_upgradeable_program_id, 32 );
  acc->entry->lamports   = 42UL;
  acc->entry->executable = 1;
  acc->entry->data_len   = sizeof(v3_state);
  acc->entry->data       = buf;
  return acc;
}

FD_FN_UNUSED static test_account_t *
test_account_init_v3_data( test_account_t * acc,
                           uchar *          buf,
                           ulong            buf_max,
                           void const *     address,
                           void const *     data,
                           ulong            data_sz,
                           ulong            slot ) {
  struct __attribute__((packed)) {
    uint  kind;
    ulong slot;
    uchar has_upgrade_authority;
  } v3_state = {
    .kind                  = FD_BPF_STATE_PROGRAM_DATA,
    .slot                  = slot,
    .has_upgrade_authority = 0
  };
  FD_TEST( buf_max>=PROGRAMDATA_METADATA_SIZE+data_sz );
  fd_memset( buf, 0, PROGRAMDATA_METADATA_SIZE );
  fd_memcpy( buf, &v3_state, sizeof(v3_state) );
  fd_memcpy( buf+PROGRAMDATA_METADATA_SIZE, data, data_sz );

  memset( acc->entry, 0, sizeof(fd_accdb_entry_t) );
  memcpy( acc->entry->pubkey, address, 32 );
  memcpy( acc->entry->owner, &fd_solana_bpf_loader_upgradeable_program_id, 32 );
  acc->entry->lamports   = 42UL;
  acc->entry->executable = 0;
  acc->entry->data_len   = PROGRAMDATA_METADATA_SIZE+data_sz;
  acc->entry->data       = buf;
  (void)slot;
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
