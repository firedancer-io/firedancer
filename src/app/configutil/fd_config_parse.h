#ifndef HEADER_fd_src_app_shared_fd_config_parse_h
#define HEADER_fd_src_app_shared_fd_config_parse_h

#include "../../util/fd_util.h"
// #include "../../util/fd_util_base.h"
#include "../../util/pod/fd_pod.h"

/* Pod query utils ****************************************************/

int
fdctl_cfg_get_cstr_( char *                out,
                     ulong                 out_sz,
                     fd_pod_info_t const * info,
                     char const *          path );

#define fdctl_cfg_get_cstr( out, out_sz, info, path ) \
  fdctl_cfg_get_cstr_( *out, out_sz, info, path )

int
fdctl_cfg_get_ulong( ulong *               out,
                     ulong                 out_sz FD_PARAM_UNUSED,
                     fd_pod_info_t const * info,
                     char const *          path );

int
fdctl_cfg_get_uint( uint *                out,
                    ulong                 out_sz FD_PARAM_UNUSED,
                    fd_pod_info_t const * info,
                    char const *          path );

int
fdctl_cfg_get_ushort( ushort *              out,
                      ulong                 out_sz FD_PARAM_UNUSED,
                      fd_pod_info_t const * info,
                      char const *          path );

int
fdctl_cfg_get_bool( int *                 out,
                    ulong                 out_sz FD_PARAM_UNUSED,
                    fd_pod_info_t const * info,
                    char const *          path );

/* Find leftover ******************************************************/

/* fdctl_pod_find_leftover recursively searches for non-subpod keys in
   pod.  Prints to the warning log if it finds any.  Used to detect
   config keys that were not recognized by fdctl.  Returns 0 if no
   leftover key was found.  Otherwise, returns a non-zero number of
   segments of the leftover key.  The key can be reassembled by joining
   stack[0] .. stack[depth-1].

   Not thread safe (uses global buffer). */

ulong
fdctl_pod_find_leftover_recurse( uchar *       pod,
                                 char const ** stack,
                                 ulong         depth );

int
fdctl_pod_find_leftover( uchar * pod );

/* Converter **********************************************************/

#define CFG_POP( type, cfg_path )                                      \
  do {                                                                 \
    char const * key = #cfg_path;                                      \
    fd_pod_info_t info[1];                                             \
    if( fd_pod_query( pod, key, info ) ) break;                        \
    if( FD_UNLIKELY( !fdctl_cfg_get_##type( &config->cfg_path, sizeof(config->cfg_path), \
        info, key ) ) )                                                \
      return NULL;                                                     \
    fd_pod_remove( pod, key );                                         \
  } while(0)

#define CFG_POP1( type, toml_path, cfg_path )                          \
  do {                                                                 \
    char const * key = #toml_path;                                      \
    fd_pod_info_t info[1];                                             \
    if( fd_pod_query( pod, key, info ) ) break;                        \
    if( FD_UNLIKELY( !fdctl_cfg_get_##type( &config->cfg_path, sizeof(config->cfg_path), \
        info, key ) ) )                                                \
      return NULL;                                                     \
    fd_pod_remove( pod, key );                                         \
  } while(0)

#define CFG_POP_ARRAY( type, cfg_path )                                \
  do {                                                                 \
    char const * key = #cfg_path;                                      \
    fd_pod_info_t info[1];                                             \
    if( fd_pod_query( pod, key, info ) ) break;                        \
    if( FD_UNLIKELY( info->val_type!=FD_POD_VAL_TYPE_SUBPOD ) ) {      \
      FD_LOG_WARNING(( "`%s`: expected array", key ));                 \
      return NULL;                                                     \
    }                                                                  \
    ulong  arr_len = sizeof( config->cfg_path ) / sizeof( config->cfg_path[ 0 ] ); \
    ulong  j       = 0UL;                                              \
    for( fd_pod_iter_t iter = fd_pod_iter_init( info->val ); !fd_pod_iter_done( iter ); iter = fd_pod_iter_next( iter ) ) { \
      if( FD_UNLIKELY( j>=arr_len ) ) {                                \
        FD_LOG_WARNING(( "`%s`: too many values (max %lu)", key, arr_len )); \
        return NULL;                                                   \
      }                                                                \
      fd_pod_info_t sub_info = fd_pod_iter_info( iter );               \
      fdctl_cfg_get_##type( &config->cfg_path[j], sizeof(config->cfg_path[j]), &sub_info, key ); \
      j++;                                                             \
    }                                                                  \
    config->cfg_path ## _cnt = j;                                      \
    fd_pod_remove( pod, key );                                         \
  } while(0)

#define CFG_POP1_ARRAY( type, toml_path, cfg_path )                    \
  do {                                                                 \
    char const * key = #toml_path;                                     \
    fd_pod_info_t info[1];                                             \
    if( fd_pod_query( pod, key, info ) ) break;                        \
    if( FD_UNLIKELY( info->val_type!=FD_POD_VAL_TYPE_SUBPOD ) ) {      \
      FD_LOG_WARNING(( "`%s`: expected array", key ));                 \
      return NULL;                                                     \
    }                                                                  \
    ulong  arr_len = sizeof( config->cfg_path ) / sizeof( config->cfg_path[ 0 ] ); \
    ulong  j       = 0UL;                                              \
    for( fd_pod_iter_t iter = fd_pod_iter_init( info->val ); !fd_pod_iter_done( iter ); iter = fd_pod_iter_next( iter ) ) { \
      if( FD_UNLIKELY( j>=arr_len ) ) {                                \
        FD_LOG_WARNING(( "`%s`: too many values (max %lu)", key, arr_len )); \
        return NULL;                                                   \
      }                                                                \
      fd_pod_info_t sub_info = fd_pod_iter_info( iter );               \
      fdctl_cfg_get_##type( &config->cfg_path[j], sizeof(config->cfg_path[j]), &sub_info, key ); \
      j++;                                                             \
    }                                                                  \
    config->cfg_path ## _cnt = j;                                      \
    fd_pod_remove( pod, key );                                         \
  } while(0)


#endif /* HEADER_fd_src_app_shared_fd_config_parse_h */
