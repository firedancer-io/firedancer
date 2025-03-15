#include "configure.h"

#include <sys/stat.h>

#define NAME "ledger"

static int dir_exists(const char *path) {
  if( strcmp( "", path ) ) {
    return 0;
  }

  struct stat st;
  if( FD_UNLIKELY( stat( path, &st ) ) ) {
    return 0;
  }

  return S_ISDIR(st.st_mode);
}

static configure_result_t check(config_t const *config) {
  if( FD_LIKELY( dir_exists(config->ledger.path ) ) )
    CHECK( check_dir( config->ledger.path, config->uid, config->gid, S_IFDIR | S_IRUSR | S_IWUSR | S_IXUSR ) );

  if( dir_exists( config->ledger.accounts_path ) )
    CHECK( check_dir( config->ledger.accounts_path, config->uid, config->gid, S_IFDIR | S_IRUSR | S_IWUSR | S_IXUSR ) );

  if( dir_exists( config->ledger.accounts_index_path ) )
    CHECK( check_dir( config->ledger.accounts_index_path, config->uid, config->gid, S_IFDIR | S_IRUSR | S_IWUSR | S_IXUSR ) );

  if( dir_exists( config->ledger.accounts_hash_cache_path ) )
    CHECK( check_dir( config->ledger.accounts_hash_cache_path, config->uid, config->gid, S_IFDIR | S_IRUSR | S_IWUSR | S_IXUSR ) );

  CONFIGURE_OK();
}

configure_stage_t fd_cfg_stage_ledger = {
  .name            = NAME,
  .always_recreate = 0,
  .enabled         = NULL,
  .init_perm       = NULL,
  .fini_perm       = NULL,
  .init            = NULL,
  .fini            = NULL,
  .check           = check,
};

#undef NAME
