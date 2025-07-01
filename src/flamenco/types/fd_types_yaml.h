#ifndef HEADER_fd_src_flamenco_types_fd_types_yaml_h
#define HEADER_fd_src_flamenco_types_fd_types_yaml_h

#include "../fd_flamenco_base.h"

/* fd_flamenco_yaml_t implements the fd_flamenco_walk_fn_t virtual class
   interface. */

struct fd_flamenco_yaml;
typedef struct fd_flamenco_yaml fd_flamenco_yaml_t;

#define FD_FLAMENCO_YAML_MAX_INDENT (64UL)
#define FD_FLAMENCO_YAML_INDENT_BUFSZ (2UL*FD_FLAMENCO_YAML_MAX_INDENT+1UL)

struct fd_flamenco_yaml {
  void * file;   /* (FILE *) or platform equivalent */

  int  stack [ FD_FLAMENCO_YAML_MAX_INDENT   ];
  char indent[ FD_FLAMENCO_YAML_INDENT_BUFSZ ];
};

FD_PROTOTYPES_BEGIN

FD_FN_PURE static inline ulong
fd_flamenco_yaml_align( void ) {
  return alignof(fd_flamenco_yaml_t);
}

FD_FN_PURE static inline ulong
fd_flamenco_yaml_footprint( void ) {
  return sizeof(fd_flamenco_yaml_t);
}

fd_flamenco_yaml_t *
fd_flamenco_yaml_new( void * mem );

void *
fd_flamenco_yaml_delete( fd_flamenco_yaml_t * yaml );

/* fd_flamenco_yaml_init initializes a fd_flamenco_yaml_t object.
   file is a (FILE *) handle or platform-specific equivalent. */

fd_flamenco_yaml_t *
fd_flamenco_yaml_init( fd_flamenco_yaml_t * yaml,
                       void *               file );

void *
fd_flamenco_yaml_file( fd_flamenco_yaml_t * yaml );

/* fd_flamenco_yaml_walk implements fd_flamenco_walk_fn_t. */

void
fd_flamenco_yaml_walk( void *       self,
                       void const * arg,
                       char const * name,
                       int          type,
                       char const * type_name,
                       uint         level,
                       uint         varint );

fd_flamenco_yaml_t *
fd_get_types_yaml(void);

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_types_fd_types_yaml_h */
