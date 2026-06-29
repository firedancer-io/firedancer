#include "../../../shared/commands/configure/configure.h"

#include "../../../platform/fd_file_util.h"

#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

#define NAME "keys"

void FD_FN_SENSITIVE
generate_keypair( char const *     keyfile,
                  uint             uid,
                  uint             gid,
                  int              use_grnd_random );

static int
path_parent( char const * path,
             char *       parent,
             ulong        parent_sz ) {
  char * last_slash = strrchr( path, '/' );

  if( FD_UNLIKELY( !last_slash ) ) return -1;

  ulong len = (ulong)(last_slash - path);
  if( FD_UNLIKELY( len>=parent_sz ) ) return -1;

  fd_memcpy( parent, path, len );
  parent[ len ] = '\0';
  return 0;
}

static void
init( config_t const * config ) {
  char identity_key_parent[ PATH_MAX ];
  if( FD_LIKELY( strrchr( config->paths.identity_key, '/' ) ) ) {
    if( FD_UNLIKELY( -1==path_parent( config->paths.identity_key, identity_key_parent, sizeof(identity_key_parent) ) ) )
      FD_LOG_ERR(( "failed to get parent directory of `%s`", config->paths.identity_key ));

    if( FD_UNLIKELY( -1==fd_file_util_mkdir_all( identity_key_parent, config->uid, config->gid, 1 ) ) )
      FD_LOG_ERR(( "could not create identity directory `%s` (%i-%s)", identity_key_parent, errno, fd_io_strerror( errno ) ));
  }

  struct stat st;
  if( FD_UNLIKELY( stat( config->paths.identity_key, &st ) && errno==ENOENT ) )
    generate_keypair( config->paths.identity_key, config->uid, config->gid, 0 );

  char vote_account_parent[ PATH_MAX ];
  if( FD_LIKELY( strrchr( config->paths.vote_account, '/' ) ) ) {
    if( FD_UNLIKELY( -1==path_parent( config->paths.vote_account, vote_account_parent, sizeof(vote_account_parent) ) ) )
      FD_LOG_ERR(( "failed to get parent directory of `%s`", config->paths.vote_account ));

    if( FD_UNLIKELY( -1==fd_file_util_mkdir_all( vote_account_parent, config->uid, config->gid, 1 ) ) )
      FD_LOG_ERR(( "could not create vote account directory `%s` (%i-%s)", vote_account_parent, errno, fd_io_strerror( errno ) ));
  }

  if( FD_LIKELY( strcmp( config->paths.vote_account, "" ) ) ) {
    if( FD_UNLIKELY( stat( config->paths.vote_account, &st ) && errno==ENOENT ) )
      generate_keypair( config->paths.vote_account, config->uid, config->gid, 0 );
  }

  if( FD_UNLIKELY( -1==fd_file_util_mkdir_all( config->paths.base, config->uid, config->gid, 1 ) ) )
    FD_LOG_ERR(( "could not create scratch directory `%s` (%i-%s)", config->paths.base, errno, fd_io_strerror( errno ) ));

  char faucet[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( faucet, PATH_MAX, NULL, "%s/faucet.json", config->paths.base ) );
  if( FD_UNLIKELY( stat( faucet, &st ) && errno==ENOENT ) )
    generate_keypair( faucet, config->uid, config->gid, 0 );

  char stake[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( stake, PATH_MAX, NULL, "%s/stake-account.json", config->paths.base ) );
  if( FD_UNLIKELY( stat( stake, &st ) && errno==ENOENT ) )
    generate_keypair( stake, config->uid, config->gid, 0 );
}

static configure_result_t
check( config_t const * config,
       int              check_type FD_PARAM_UNUSED ) {
  char faucet[ PATH_MAX ], stake[ PATH_MAX ];

  FD_TEST( fd_cstr_printf_check( faucet, PATH_MAX, NULL, "%s/faucet.json", config->paths.base ) );
  FD_TEST( fd_cstr_printf_check( stake,  PATH_MAX, NULL, "%s/stake-account.json", config->paths.base ) );

  char const * paths[] = {
    config->paths.identity_key,
    config->paths.vote_account,
    faucet,
    stake,
  };

  struct stat st;

  int all_exist = 1;
  for( ulong i=0UL; i<4UL; i++ ) {
    if( FD_UNLIKELY( !strcmp( "", paths[ i ] ) ) ) continue;
    if( FD_UNLIKELY( stat( paths[ i ], &st ) && errno==ENOENT ) ) {
      all_exist = 0;
      continue;
    }
    CHECK( check_file( paths[ i ], config->uid, config->gid, S_IFREG | S_IRUSR | S_IWUSR ) );
  }

  if( FD_UNLIKELY( !all_exist ) ) NOT_CONFIGURED( " identity.json, vote-account.json, faucet.json, or stake-account.json does not exist" );
  else                         CONFIGURE_OK();
}

configure_stage_t fd_cfg_stage_keys = {
  .name            = NAME,
  .always_recreate = 0,
  .enabled         = NULL,
  .init_perm       = NULL,
  .fini_perm       = NULL,
  .init            = init,
  .fini            = NULL,
  .check           = check,
};

#undef NAME
