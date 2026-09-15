/* Macros for extracting config values out of a parsed TOML document.
   doc is the fd_toml_doc_t, config the struct being filled and cfg the
   fd_config_t that owns the string arena.  Strings are only bounded by
   the arena capacity (FD_CONFIG_STRS_SZ); any semantic length limit is
   checked by the consumer of the value. */

#define CFG_POP1( vtype, toml_path, cfg_path )                          \
  do {                                                                 \
    char const * key = #toml_path;                                     \
    fd_toml_node_t * node = fd_toml_get( doc, NULL, key );             \
    if( !node ) break;                                                 \
    if( FD_UNLIKELY( !fdctl_cfg_get_##vtype( &config->cfg_path, doc, node, key ) ) ) \
      return NULL;                                                     \
    fd_toml_node_consume( node );                                      \
  } while(0)

#define CFG_POP( vtype, cfg_path ) CFG_POP1( vtype, cfg_path, cfg_path )

#define CFG_POP1_ARRAY( vtype, toml_path, cfg_path )                    \
  do {                                                                 \
    char const * key = #toml_path;                                     \
    fd_toml_node_t * node = fd_toml_get( doc, NULL, key );             \
    if( !node ) break;                                                 \
    if( FD_UNLIKELY( node->type!=FD_TOML_NODE_ARRAY ) ) {              \
      FD_LOG_WARNING(( "`%s`: expected array", key ));                 \
      return NULL;                                                     \
    }                                                                  \
    ulong arr_len = sizeof( config->cfg_path ) / sizeof( config->cfg_path[ 0 ] ); \
    ulong j       = 0UL;                                               \
    for( fd_toml_node_t * elem=fd_toml_child_first( doc, node ); elem; elem=fd_toml_child_next( doc, elem ) ) { \
      if( FD_UNLIKELY( j>=arr_len ) ) {                                \
        FD_LOG_WARNING(( "`%s`: too many values (max %lu)", key, arr_len )); \
        return NULL;                                                   \
      }                                                                \
      if( FD_UNLIKELY( !fdctl_cfg_get_##vtype( &config->cfg_path[j], doc, elem, key ) ) ) \
        return NULL;                                                   \
      fd_toml_node_consume( elem );                                    \
      j++;                                                             \
    }                                                                  \
    config->cfg_path ## _cnt = j;                                      \
    fd_toml_node_consume( node );                                      \
  } while(0)

#define CFG_POP_ARRAY( vtype, cfg_path ) CFG_POP1_ARRAY( vtype, cfg_path, cfg_path )

#define CFG_POP1_STR( toml_path, cfg_path )                            \
  do {                                                                 \
    char const * key = #toml_path;                                     \
    fd_toml_node_t * node = fd_toml_get( doc, NULL, key );             \
    if( !node ) break;                                                 \
    if( FD_UNLIKELY( !fdctl_cfg_get_str( cfg, &config->cfg_path, doc, node, key ) ) ) \
      return NULL;                                                     \
    fd_toml_node_consume( node );                                      \
  } while(0)

#define CFG_POP_STR( cfg_path ) CFG_POP1_STR( cfg_path, cfg_path )

#define CFG_POP1_STR_ARRAY( toml_path, cfg_path )                      \
  do {                                                                 \
    char const * key = #toml_path;                                     \
    fd_toml_node_t * node = fd_toml_get( doc, NULL, key );             \
    if( !node ) break;                                                 \
    if( FD_UNLIKELY( node->type!=FD_TOML_NODE_ARRAY ) ) {              \
      FD_LOG_WARNING(( "`%s`: expected array", key ));                 \
      return NULL;                                                     \
    }                                                                  \
    ulong arr_len = sizeof( config->cfg_path ) / sizeof( config->cfg_path[ 0 ] ); \
    ulong j       = 0UL;                                               \
    for( fd_toml_node_t * elem=fd_toml_child_first( doc, node ); elem; elem=fd_toml_child_next( doc, elem ) ) { \
      if( FD_UNLIKELY( j>=arr_len ) ) {                                \
        FD_LOG_WARNING(( "`%s`: too many values (max %lu)", key, arr_len )); \
        return NULL;                                                   \
      }                                                                \
      if( FD_UNLIKELY( !fdctl_cfg_get_str( cfg, &config->cfg_path[j], doc, elem, key ) ) ) \
        return NULL;                                                   \
      fd_toml_node_consume( elem );                                    \
      j++;                                                             \
    }                                                                  \
    config->cfg_path ## _cnt = j;                                      \
    fd_toml_node_consume( node );                                      \
  } while(0)

#define CFG_POP_STR_ARRAY( cfg_path ) CFG_POP1_STR_ARRAY( cfg_path, cfg_path )
