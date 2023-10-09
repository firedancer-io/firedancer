#ifndef HEADER_fd_src_app_fdctl_configure_configure_h
#define HEADER_fd_src_app_fdctl_configure_configure_h

#include "../fdctl.h"

#include <stdarg.h>

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

#define NOT_CONFIGURED(...) do {              \
    configure_result_t result;                \
    result.result = CONFIGURE_NOT_CONFIGURED; \
    snprintf1( result.message,                \
               sizeof( result.message ),      \
               __VA_ARGS__ );                 \
    return result;                            \
  } while( 0 )

#define PARTIALLY_CONFIGURED(...) do {              \
    configure_result_t result;                      \
    result.result = CONFIGURE_PARTIALLY_CONFIGURED; \
    snprintf1( result.message,                      \
               sizeof( result.message ),            \
               __VA_ARGS__ );                       \
    return result;                                  \
  } while( 0 )

#define CONFIGURE_OK() do {       \
    configure_result_t result;    \
    result.result = CONFIGURE_OK; \
    result.message[ 0 ] = '\0';   \
    return result;                \
  } while( 0 )

typedef struct configure_stage {
  const char *       name;
  int                always_recreate;
  int                (*enabled)  ( config_t * const config );
  void               (*init_perm)( security_t * security, config_t * const config );
  void               (*fini_perm)( security_t * security, config_t * const config );
  void               (*init)     ( config_t * const config );
  void               (*fini)     ( config_t * const config );
  configure_result_t (*check)    ( config_t * const config );
} configure_stage_t;

extern configure_stage_t large_pages;
extern configure_stage_t shmem;
extern configure_stage_t sysctl;
extern configure_stage_t xdp;
extern configure_stage_t xdp_leftover;
extern configure_stage_t ethtool;
extern configure_stage_t workspace_leftover;
extern configure_stage_t workspace;

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

/* read_uint_file() reads a uint from the given path, or exits the
   program with an error if any error was encountered.  If the path
   cannot be opened due to ENOENT, the error message is prefixed
   with the string provided in errmsg_enoent. */
uint
read_uint_file( const char * path,
                const char * errmsg_enoent );

/* write_uint_file() writes a uint to the given path, or exits the
   program with an error if any error was encountered. */
void
write_uint_file( const char * path,
                 uint         value );

/* try_defragment_memory() tells the operating system to defragment
   memory allocations, it it is hint, and can be useful to call before
   trying to request large contiguous memory to be mapped. */
void try_defragment_memory( void );

/* Enter the network namespace given in the configuration in this
   process. If this call succeeds the process is now inside the
   namespace. */
void enter_network_namespace( const char * interface );

void leave_network_namespace( void );

void close_network_namespace_original_fd( void );

void
expected_pages( config_t * const  config, uint out[2] );

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

#endif /* HEADER_fd_src_app_fdctl_configure_configure_h */
