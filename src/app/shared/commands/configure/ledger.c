#include "configure.h"

#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

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

static void apply_dir_permissions(const char *path, uid_t uid, gid_t gid) {
  if (!dir_exists(path))
    return;

  if (FD_UNLIKELY(-1 == chown(path, uid, gid)))
    FD_LOG_ERR(("failed to chown '%s' to uid:%u gid:%u: %s", path, uid, gid,
                strerror(errno)));
  if (FD_UNLIKELY(-1 == chmod(path, S_IRUSR | S_IWUSR | S_IXUSR)))
    FD_LOG_ERR(("failed to chmod '%s' to 0700: %s", path, strerror(errno)));
}

static void init_perm(fd_cap_chk_t *chk,
                      config_t const *config FD_PARAM_UNUSED) {
  fd_cap_chk_root(chk, NAME, "need to chown directories");
}

static void init(config_t const *config) {
  apply_dir_permissions(config->ledger.path, config->uid, config->gid);
  apply_dir_permissions(config->ledger.accounts_path, config->uid, config->gid);
  apply_dir_permissions(config->ledger.accounts_index_path, config->uid,
                        config->gid);
  apply_dir_permissions(config->ledger.accounts_hash_cache_path, config->uid,
                        config->gid);
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
    .name = NAME,
    .always_recreate = 0,
    .enabled = NULL,
    .init_perm = init_perm,
    .fini_perm = NULL,
    .init = init,
    .fini = NULL,
    .check = check,
};

#undef NAME
