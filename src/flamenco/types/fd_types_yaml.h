#include "../fd_flamenco_base.h"

/* fd_flamenco_yaml_t implements the fd_flamenco_walk_fn_t virtual class
   interface. */

struct fd_flamenco_yaml;
typedef struct fd_flamenco_yaml fd_flamenco_yaml_t;

FD_PROTOTYPES_BEGIN

ulong
fd_flamenco_yaml_align( void );

ulong
fd_flamenco_yaml_footprint( void );

fd_flamenco_yaml_t *
fd_flamenco_yaml_new( void * mem );

void *
fd_flamenco_yaml_delete( fd_flamenco_yaml_t * yaml );

/* fd_flamenco_yaml_init initializes a fd_flamenco_yaml_t object.
   file is a (FILE *) handle or platform-specific equivalent. */

fd_flamenco_yaml_t *
fd_flamenco_yaml_init( fd_flamenco_yaml_t * yaml,
                       void *            file );

/* fd_flamenco_yaml_walk implements fd_flamenco_walk_fn_t. */

void
fd_flamenco_yaml_walk( void *       self,
                       void const * arg,
                       char const * name,
                       int          type,
                       uint         level );

FD_PROTOTYPES_END
