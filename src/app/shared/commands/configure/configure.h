#ifndef HEADER_fd_src_app_shared_commands_configure_configure_h
#define HEADER_fd_src_app_shared_commands_configure_configure_h

#include "../../../platform/fd_cap_chk.h"
#include "../../fd_config.h"
#include "../../fd_action.h"

#include <stdarg.h>

#define CONFIGURE_NR_OPEN_FILES (1024000U)

enum {
  CONFIGURE_NOT_CONFIGURED,
  CONFIGURE_PARTIALLY_CONFIGURED,
  CONFIGURE_OK,
};

typedef struct {
  int  result;
  char message[ 256 ];
} configure_result_t;

#define CHECK(x) do {                                    \
    configure_result_t result = (x);                     \
    if( FD_UNLIKELY( result.result != CONFIGURE_OK ) ) { \
      return result;                                     \
    }                                                    \
  } while( 0 )

#define NOT_CONFIGURED(...) do {                             \
    configure_result_t result;                               \
    result.result = CONFIGURE_NOT_CONFIGURED;                \
    FD_TEST( fd_cstr_printf_check( result.message,           \
                                   sizeof( result.message ), \
                                   NULL,                     \
                                   __VA_ARGS__ ) );          \
    return result;                                           \
  } while( 0 )

#define PARTIALLY_CONFIGURED(...) do {                       \
    configure_result_t result;                               \
    result.result = CONFIGURE_PARTIALLY_CONFIGURED;          \
    FD_TEST( fd_cstr_printf_check( result.message,           \
                                   sizeof( result.message ), \
                                   NULL,                     \
                                   __VA_ARGS__ ) );          \
    return result;                                           \
  } while( 0 )

#define CONFIGURE_OK() do {       \
    configure_result_t result;    \
    result.result = CONFIGURE_OK; \
    result.message[ 0 ] = '\0';   \
    return result;                \
  } while( 0 )

#define FD_CONFIGURE_CHECK_TYPE_INIT_PERM (0)
#define FD_CONFIGURE_CHECK_TYPE_FINI_PERM (1)
#define FD_CONFIGURE_CHECK_TYPE_PRE_INIT  (2)
#define FD_CONFIGURE_CHECK_TYPE_UNDO_INIT (3)
#define FD_CONFIGURE_CHECK_TYPE_POST_INIT (4)
#define FD_CONFIGURE_CHECK_TYPE_CHECK     (5)
#define FD_CONFIGURE_CHECK_TYPE_PRE_FINI  (6)
#define FD_CONFIGURE_CHECK_TYPE_POST_FINI (7)
#define FD_CONFIGURE_CHECK_TYPE_RUN       (8)

/* fini() returns whether or not it took any actions. */

typedef struct configure_stage {
  const char *       name;
  int                always_recreate;
  int                (*enabled)  ( config_t const * config );
  void               (*init_perm)( fd_cap_chk_t * chk, config_t const * config );
  void               (*fini_perm)( fd_cap_chk_t * chk, config_t const * config );
  void               (*init)     ( config_t const * config );
  int                (*fini)     ( config_t const * config, int pre_init );
  configure_result_t (*check)    ( config_t const * config, int check_type );
} configure_stage_t;

extern configure_stage_t fd_cfg_stage_hugetlbfs;
extern configure_stage_t fd_cfg_stage_sysctl;
extern configure_stage_t fd_cfg_stage_hyperthreads;
extern configure_stage_t fd_cfg_stage_bonding;
extern configure_stage_t fd_cfg_stage_ethtool_channels;
extern configure_stage_t fd_cfg_stage_ethtool_offloads;
extern configure_stage_t fd_cfg_stage_ethtool_loopback;
extern configure_stage_t fd_cfg_stage_sysfs_poll;
extern configure_stage_t fd_cfg_stage_snapshots;

extern configure_stage_t * STAGES[];

typedef enum {
  CONFIGURE_CMD_INIT,
  CONFIGURE_CMD_CHECK,
  CONFIGURE_CMD_FINI,
} configure_cmd_t;

typedef struct {
  configure_cmd_t      command;
  configure_stage_t ** stages;
} configure_args_t;

/* Checks if a directory exists and is configured with the given uid,
   gid, and access mode. */
configure_result_t
check_dir( const char * path,
           uint         uid,
           uint         gid,
           uint         mode );

/* Checks if a file exists and is configured with the given uid, gid,
   and access mode. */
configure_result_t
check_file( const char * path,
            uint         uid,
            uint         gid,
            uint         mode );

int
configure_stage( configure_stage_t * stage,
                 configure_cmd_t     command,
                 config_t const *    config );

void configure_cmd_args( int * pargc, char *** pargv, args_t * args );
void configure_cmd_perm( args_t * args, fd_cap_chk_t * chk, config_t const * config );
void configure_cmd_fn  ( args_t * args, config_t * config );

extern action_t fd_action_configure;

#endif /* HEADER_fd_src_app_shared_commands_configure_configure_h */
