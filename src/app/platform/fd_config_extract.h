#ifndef HEADER_fd_src_app_platform_fd_config_extract_h
#define HEADER_fd_src_app_platform_fd_config_extract_h

#include "../../util/fd_util.h"
#include "../../ballet/toml/fd_toml.h"

FD_PROTOTYPES_BEGIN

/* TOML node query utils **********************************************/

static inline int
fdctl_cfg_get_ulong( ulong *                out,
                     fd_toml_doc_t const *  doc FD_PARAM_UNUSED,
                     fd_toml_node_t const * node,
                     char const *           path ) {
  if( FD_UNLIKELY( node->type!=FD_TOML_NODE_INT ) ) {
    FD_LOG_WARNING(( "invalid value for `%s`", path ));
    return 0;
  }
  if( FD_UNLIKELY( node->i<0L ) ) {
    FD_LOG_WARNING(( "`%s` cannot be negative", path ));
    return 0;
  }
  *out = (ulong)node->i;
  return 1;
}

static inline int
fdctl_cfg_get_uint( uint *                 out,
                    fd_toml_doc_t const *  doc,
                    fd_toml_node_t const * node,
                    char const *           path ) {
  ulong num;
  if( FD_UNLIKELY( !fdctl_cfg_get_ulong( &num, doc, node, path ) ) ) return 0;
  if( num > UINT_MAX ) {
    FD_LOG_WARNING(( "`%s` is out of bounds (%lx)", path, num ));
    return 0;
  }
  *out = (uint)num;
  return 1;
}

static inline int
fdctl_cfg_get_ushort( ushort *               out,
                      fd_toml_doc_t const *  doc,
                      fd_toml_node_t const * node,
                      char const *           path ) {
  ulong num;
  if( FD_UNLIKELY( !fdctl_cfg_get_ulong( &num, doc, node, path ) ) ) return 0;
  if( num > USHORT_MAX ) {
    FD_LOG_WARNING(( "`%s` is out of bounds (%lx)", path, num ));
    return 0;
  }
  *out = (ushort)num;
  return 1;
}

static inline int
fdctl_cfg_get_bool( int *                  out,
                    fd_toml_doc_t const *  doc FD_PARAM_UNUSED,
                    fd_toml_node_t const * node,
                    char const *           path ) {
  if( FD_UNLIKELY( node->type!=FD_TOML_NODE_BOOL ) ) {
    FD_LOG_WARNING(( "invalid value for `%s`", path ));
    return 0;
  }
  *out = node->b;
  return 1;
}

/* Handles true, false, "true", "false" and "auto" */
static inline int
fdctl_cfg_get_boolau( int *                  out,
                      fd_toml_doc_t const *  doc,
                      fd_toml_node_t const * node,
                      char const *           path ) {
  if( node->type==FD_TOML_NODE_STRING ) {
    char const * val = fd_toml_node_str( doc, node );
    if( !strcmp( val, "auto"  ) ) {
      *out = 2;
      return 1;
    } else if( !strcmp( val, "true"  ) ) {
      *out = 1;
      return 1;
    } else if( !strcmp( val, "false" ) ) {
      *out = 0;
      return 1;
    }
    FD_LOG_WARNING(( "invalid value of `%s` entered for `%s`, must be true, false or auto. ",
                     val, path ));
    return 0;
  }
  return fdctl_cfg_get_bool( out, doc, node, path );
}

static inline int
fdctl_cfg_get_float( float *                out,
                     fd_toml_doc_t const *  doc FD_PARAM_UNUSED,
                     fd_toml_node_t const * node,
                     char const *           path ) {
  switch( node->type ) {
  case FD_TOML_NODE_INT:
    if( FD_UNLIKELY( node->i<0L ) ) {
      FD_LOG_WARNING(( "`%s` cannot be negative", path ));
      return 0;
    }
    *out = (float)node->i;
    return 1;
  case FD_TOML_NODE_FLOAT:
    *out = (float)node->f;
    return 1;
  default:
    FD_LOG_WARNING(( "invalid value for `%s`", path ));
    return 0;
  }
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_platform_fd_config_extract_h */
