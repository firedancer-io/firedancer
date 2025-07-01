#ifndef HEADER_fd_src_flamenco_types_fd_types_reflect_h
#define HEADER_fd_src_flamenco_types_fd_types_reflect_h

/* fd_types_reflect.h provides reflection logic for bincode types
   serializers. */

#include "fd_bincode.h"

/* fd_types_vt is a virtual interface for a type serializer. */

struct fd_types_vt_key {
  char const * name; /* type name (e.g. "vote") */
  ushort       name_len;
};
typedef struct fd_types_vt_key fd_types_vt_key_t;

struct fd_types_vt {
  union {
    fd_types_vt_key_t key; /* for fd_map.c */
    struct {
      char const * name; /* type name (e.g. "vote"), null-terminated */
      ushort       name_len;
      ushort       align;
      uint         hash;
    };
  };

  void *
  (* new_)( void * );

  int
  (* decode_footprint)( fd_bincode_decode_ctx_t * ctx,
                        ulong *                   total_sz );

  void *
  (* decode)( void *                    out,
              fd_bincode_decode_ctx_t * ctx );

  int
  (* encode)( void const *              self,
              fd_bincode_encode_ctx_t * ctx );

  ulong
  (* size)( void const * self );

  int
  (* walk)( void *             w,
            void *             self,
            fd_types_walk_fn_t callback,
            const char *       name,
            uint               depth,
            uint               varint );
};

typedef struct fd_types_vt fd_types_vt_t;

FD_PROTOTYPES_BEGIN

/* fd_types_vt_list is a table of fd_types_vt_t for each supported
   bincode type.  This list is null-terminated by ->name==NULL.

   fd_types_vt_list_cnt gives the number of records in fd_types_vt_list. */

extern fd_types_vt_t const fd_types_vt_list[];
extern ulong               fd_types_vt_list_cnt;

/* fd_types_vt_by_name gives a type class by name. */

fd_types_vt_t const *
fd_types_vt_by_name( char const * name,
                     ulong        name_len );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_types_fd_types_reflect_h */
