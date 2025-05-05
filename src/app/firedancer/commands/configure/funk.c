#include "../../../shared/commands/configure/configure.h"
#include "../../../../funk/fd_funk_filemap.h"

#define NAME "funk"

static int
enabled( config_t const * config ) {
  (void)config;
  return 1;
}

static void
funk_init_file( config_t const * config ) {

}

static void
funk_init_mem( config_t const * config ) {

}

static void
init( config_t const * config ) {
  if( config->firedancer.funk.filemap.enabled ) funk_init_file( config );
  else                                          funk_init_mem ( config );
}

static void
fini( config_t const * config,
      int              pre_init ) {
  (void)pre_init;
}

static void
funk_check_file( config_t const * config ) {
  fd_funk_open_file( funk, funk_path, 1UL,  )
}

static void
funk_check_mem( config_t const * config ) {

}

static configure_result_t
check( config_t const * config ) {
  if( config->firedancer.funk.filemap.enabled ) funk_check_file( config );
  else                                          funk_check_mem ( config );
}

configure_stage_t fd_cfg_stage_funk = {
  .name            = NAME,
  .always_recreate = 0,
  .enabled         = enabled,
  .init            = init,
  .fini            = fini,
  .check           = check,
};

#undef NAME
