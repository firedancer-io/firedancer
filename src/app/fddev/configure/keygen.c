#include "../../fdctl/configure/configure.h"

#include <sys/stat.h>

#define NAME "keygen"


static void
init( config_t * const config ) {
  mkdir_all( config->scratch_directory, config->uid, config->gid );

  struct stat st;
  if( FD_UNLIKELY( stat( config->consensus.identity_path, &st ) && errno == ENOENT ) )
    generate_keypair( config->consensus.identity_path, config );

  char faucet[ PATH_MAX ];
  snprintf1( faucet, PATH_MAX, "%s/faucet.json", config->scratch_directory );
  generate_keypair( faucet, config );

  char stake[ PATH_MAX ];
  snprintf1( stake, PATH_MAX, "%s/stake-account.json", config->scratch_directory );
  generate_keypair( stake, config );

  char vote[ PATH_MAX ];
  snprintf1( vote, PATH_MAX, "%s/vote-account.json", config->scratch_directory );
  generate_keypair( vote, config );
}


static void
fini( config_t * const config ) {
  char path[ PATH_MAX ];
  snprintf1( path, PATH_MAX, "%s/faucet.json", config->scratch_directory );
  if( FD_UNLIKELY( unlink( path ) && errno != ENOENT ) )
    FD_LOG_ERR(( "could not remove cluster file `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  snprintf1( path, PATH_MAX, "%s/stake-account.json", config->scratch_directory );
  if( FD_UNLIKELY( unlink( path ) && errno != ENOENT ) )
    FD_LOG_ERR(( "could not remove cluster file `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  snprintf1( path, PATH_MAX, "%s/vote-account.json", config->scratch_directory );
  if( FD_UNLIKELY( unlink( path ) && errno != ENOENT ) )
    FD_LOG_ERR(( "could not remove cluster file `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
}


static configure_result_t
check( config_t * const config ) {
  char faucet[ PATH_MAX ], stake[ PATH_MAX ], vote[ PATH_MAX ];

  snprintf1( faucet, PATH_MAX, "%s/faucet.json", config->scratch_directory );
  snprintf1( stake, PATH_MAX, "%s/stake-account.json", config->scratch_directory );
  snprintf1( vote, PATH_MAX, "%s/vote-account.json", config->scratch_directory );

  struct stat st;
  if( FD_UNLIKELY( stat( faucet, &st ) && errno == ENOENT &&
                   stat( stake,  &st ) && errno == ENOENT &&
                   stat( vote,   &st ) && errno == ENOENT ) )
    NOT_CONFIGURED( "not all of faucet.json, stake-account.json, and vote-account.json exist" );

  CHECK( check_dir( config->scratch_directory, config->uid, config->gid, S_IFDIR | S_IRUSR | S_IWUSR | S_IXUSR ) );

  CHECK( check_file( faucet, config->uid, config->gid, S_IFREG | S_IRUSR | S_IWUSR ) );
  CHECK( check_file( stake,  config->uid, config->gid, S_IFREG | S_IRUSR | S_IWUSR ) );
  CHECK( check_file( vote,   config->uid, config->gid, S_IFREG | S_IRUSR | S_IWUSR ) );
  CONFIGURE_OK();
}

configure_stage_t keygen = {
  .name            = NAME,
  .always_recreate = 0,
  .enabled         = NULL,
  .init_perm       = NULL,
  .fini_perm       = NULL,
  .init            = init,
  .fini            = fini,
  .check           = check,
};

#undef NAME
