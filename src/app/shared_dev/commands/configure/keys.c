#include "../../../shared/commands/configure/configure.h"

#include "../../../shared/fd_file_util.h"

#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

#define NAME "keys"

void FD_FN_SENSITIVE
generate_keypair( char const *     keyfile,
                  uint             uid,
                  uint             gid,
                  int              use_grnd_random );

static void
init( config_t const * config ) {
  if( FD_UNLIKELY( -1==fd_file_util_mkdir_all( config->consensus.identity_path, config->uid, config->gid ) ) )
    FD_LOG_ERR(( "could not create identity directory `%s` (%i-%s)", config->consensus.identity_path, errno, fd_io_strerror( errno ) ));

  struct stat st;
  if( FD_UNLIKELY( stat( config->consensus.identity_path, &st ) && errno==ENOENT ) )
    generate_keypair( config->consensus.identity_path, config->uid, config->gid, 0 );

  if( FD_UNLIKELY( -1==fd_file_util_mkdir_all( config->consensus.vote_account_path, config->uid, config->gid ) ) )
    FD_LOG_ERR(( "could not create vote account directory `%s` (%i-%s)", config->consensus.vote_account_path, errno, fd_io_strerror( errno ) ));

  if( FD_LIKELY( !strcmp( config->consensus.vote_account_path, "" ) ) ) {
    if( FD_UNLIKELY( stat( config->consensus.vote_account_path, &st ) && errno==ENOENT ) )
      generate_keypair( config->consensus.vote_account_path, config->uid, config->gid, 0 );
  }

  if( FD_UNLIKELY( -1==fd_file_util_mkdir_all( config->scratch_directory, config->uid, config->gid ) ) )
    FD_LOG_ERR(( "could not create scratch directory `%s` (%i-%s)", config->scratch_directory, errno, fd_io_strerror( errno ) ));

  char faucet[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( faucet, PATH_MAX, NULL, "%s/faucet.json", config->scratch_directory ) );
  generate_keypair( faucet, config->uid, config->gid, 0 );

  char stake[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( stake, PATH_MAX, NULL, "%s/stake-account.json", config->scratch_directory ) );
  generate_keypair( stake, config->uid, config->gid, 0 );
}

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

static configure_result_t
check( config_t const * config ) {
  char faucet[ PATH_MAX ], stake[ PATH_MAX ];

  FD_TEST( fd_cstr_printf_check( faucet, PATH_MAX, NULL, "%s/faucet.json", config->scratch_directory ) );
  FD_TEST( fd_cstr_printf_check( stake,  PATH_MAX, NULL, "%s/stake-account.json", config->scratch_directory ) );

  struct stat st;
  if( FD_UNLIKELY( stat( config->consensus.identity_path, &st ) && errno == ENOENT &&
                   stat( config->consensus.vote_account_path, &st ) && errno == ENOENT &&
                   stat( faucet, &st ) && errno == ENOENT &&
                   stat( stake,  &st ) && errno == ENOENT ) )
    NOT_CONFIGURED( "none of identity.json, vote-account.json, faucet.json, or stake-account.json exist" );

  char parent[ PATH_MAX ];
  if( FD_UNLIKELY( -1==path_parent( config->consensus.identity_path, parent, sizeof(parent) ) ) )
    FD_LOG_ERR(( "failed to get parent directory of `%s`", config->consensus.identity_path ));
  CHECK( check_dir( parent, config->uid, config->gid, S_IFDIR | S_IRUSR | S_IWUSR | S_IXUSR ) );

  if( FD_UNLIKELY( -1==path_parent( config->consensus.vote_account_path, parent, sizeof(parent) ) ) )
    FD_LOG_ERR(( "failed to get parent directory of `%s`", config->consensus.vote_account_path ));
  CHECK( check_dir( parent, config->uid, config->gid, S_IFDIR | S_IRUSR | S_IWUSR | S_IXUSR ) );

  CHECK( check_dir( config->scratch_directory, config->uid, config->gid, S_IFDIR | S_IRUSR | S_IWUSR | S_IXUSR ) );
  CHECK( check_dir( config->scratch_directory, config->uid, config->gid, S_IFDIR | S_IRUSR | S_IWUSR | S_IXUSR ) );

  CHECK( check_file( config->consensus.identity_path, config->uid, config->gid, S_IFREG | S_IRUSR | S_IWUSR ) );
  CHECK( check_file( config->consensus.vote_account_path, config->uid, config->gid, S_IFREG | S_IRUSR | S_IWUSR ) );
  CHECK( check_file( faucet, config->uid, config->gid, S_IFREG | S_IRUSR | S_IWUSR ) );
  CHECK( check_file( stake,  config->uid, config->gid, S_IFREG | S_IRUSR | S_IWUSR ) );

  CONFIGURE_OK();
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
