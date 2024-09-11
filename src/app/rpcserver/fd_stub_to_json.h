#include "fd_webserver.h"
#include "../../flamenco/types/fd_types_meta.h"

struct fd_rpc_json;
typedef struct fd_rpc_json fd_rpc_json_t;

FD_PROTOTYPES_BEGIN

FD_FN_PURE ulong
fd_rpc_json_align( void );

FD_FN_PURE ulong
fd_rpc_json_footprint( void );

fd_rpc_json_t *
fd_rpc_json_new( void * mem );

void *
fd_rpc_json_delete( fd_rpc_json_t * json );

/* fd_rpc_json_init initializes a fd_rpc_json_t object.
   file is a (FILE *) handle or platform-specific equivalent. */

fd_rpc_json_t *
fd_rpc_json_init( fd_rpc_json_t * json, fd_webserver_t * ws );

/* fd_rpc_json_walk implements fd_rpc_walk_fn_t. */

void
fd_rpc_json_walk( void *       self,
                  void const * arg,
                  char const * name,
                  int          type,
                  char const * type_name,
                  uint         level );

FD_PROTOTYPES_END
