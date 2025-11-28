/* Macros for extracting config values out of a pod */

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

#define CFG_POP_TABLE( type, toml_path, cfg_path, cfg_field, field_idx )              \
  do {                                                                                \
    char const * key = #toml_path;                                                    \
    fd_pod_info_t info[1];                                                            \
    if( fd_pod_query( pod, key, info ) ) break;                                       \
    if( FD_UNLIKELY( info->val_type!=FD_POD_VAL_TYPE_SUBPOD ) ) {                     \
      FD_LOG_WARNING(( "`%s`: expected table", key ));                                \
      return NULL;                                                                    \
    }                                                                                 \
    ulong table_len = fd_pod_cnt( info->val );                                        \
    ulong j         = 0UL;                                                            \
    for( fd_pod_iter_t iter = fd_pod_iter_init( info->val ); !fd_pod_iter_done( iter ); iter = fd_pod_iter_next( iter ) ) { \
      if( FD_UNLIKELY( j>=table_len ) ) {                                             \
        FD_LOG_WARNING(( "`%s`: too many values (max %lu)", key, table_len ));        \
        return NULL;                                                                  \
      }                                                                               \
      fd_pod_info_t sub_info = fd_pod_iter_info( iter );                              \
      if( FD_UNLIKELY( sub_info.val_type!=FD_POD_VAL_TYPE_SUBPOD ) ) continue;        \
      fd_pod_info_t list[ 256UL ];                                                    \
      ulong fields_cnt         = fd_pod_cnt( sub_info.val );                          \
      if( FD_UNLIKELY( fields_cnt>256UL ) ) {                                         \
        FD_LOG_WARNING(( "`%s`: Too many subpods (%lu) in table", sub_info.key, fields_cnt )); \
        return NULL;                                                                  \
      }                                                                               \
      fd_pod_info_t * fields   = fd_pod_list( sub_info.val, list );                   \
      FD_TEST( field_idx<fields_cnt );                                                \
      fd_pod_info_t field_info = fields[ field_idx ];                                 \
      char table_toml_path[ PATH_MAX ];                                               \
      char const * cfg_field_str = #cfg_field;                                        \
      FD_TEST( fd_cstr_printf_check( table_toml_path, PATH_MAX, NULL, "%s.%lu.%s", key, j, cfg_field_str ) ); \
      fdctl_cfg_get_##type( &config->cfg_path[j].cfg_field, sizeof(config->cfg_path[j].cfg_field), &field_info, table_toml_path ); \
      j++;                                                                            \
    }                                                                                 \
    config->cfg_path ## _cnt = j;                                                     \
  } while(0)

#define CFG_POP_TABLE_FINI( toml_path ) \
  do {                                  \
    fd_pod_remove( pod, #toml_path );   \
  } while(0)
