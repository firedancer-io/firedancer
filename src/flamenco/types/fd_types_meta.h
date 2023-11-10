#ifndef HEADER_fd_src_flamenco_types_fd_types_meta_h
#define HEADER_fd_src_flamenco_types_fd_types_meta_h

#include "../../util/fd_util_base.h"
#include "fd_bincode.h"

/* fd_types_meta.h provides reflection APIs for fd_types. */

/* FD_FLAMENCO_TYPE_{...} identifies kinds of nodes encountered in a
   bincode/borsh data structure graph. */

#define FD_FLAMENCO_TYPE_NULL      (0x00)
#define FD_FLAMENCO_TYPE_BOOL      (0x01)
#define FD_FLAMENCO_TYPE_UCHAR     (0x02)
#define FD_FLAMENCO_TYPE_SCHAR     (0x03)
#define FD_FLAMENCO_TYPE_USHORT    (0x04)
#define FD_FLAMENCO_TYPE_SSHORT    (0x05)
#define FD_FLAMENCO_TYPE_UINT      (0x06)
#define FD_FLAMENCO_TYPE_SINT      (0x07)
#define FD_FLAMENCO_TYPE_ULONG     (0x08)
#define FD_FLAMENCO_TYPE_SLONG     (0x09)
#if FD_HAS_INT128
#define FD_FLAMENCO_TYPE_UINT128   (0x0a)
#define FD_FLAMENCO_TYPE_SINT128   (0x0b)
#endif /* FD_HAS_INT128 */
#define FD_FLAMENCO_TYPE_FLOAT     (0x0c)
#define FD_FLAMENCO_TYPE_DOUBLE    (0x0d)
#define FD_FLAMENCO_TYPE_HASH256   (0x0e)  /* pubkey, account */
#define FD_FLAMENCO_TYPE_SIG512    (0x0f)
#define FD_FLAMENCO_TYPE_CSTR      (0x10)

#define FD_FLAMENCO_TYPE_ARR       (0x20)
#define FD_FLAMENCO_TYPE_ARR_END   (0x21)
#define FD_FLAMENCO_TYPE_MAP       (0x22)
#define FD_FLAMENCO_TYPE_MAP_END   (0x23)

FD_PROTOTYPES_BEGIN

/* fd_flamenco_type_is_primitive returns 1 if type does not contain
   any child nodes.  Returns 0 otherwise. */

FD_FN_CONST static inline int
fd_flamenco_type_is_primitive( int type ) {
  return (type&0xe0)==0x00;
}

/* fd_flamenco_type_is_collection returns 1 if node type marks the
   beginning or end of a collection.  Returns 0 otherwise. */

FD_FN_CONST static inline int
fd_flamenco_type_is_collection( int type ) {
  return (type&0xe0)==0x20;
}

/* fd_flamenco_type_is_collection_{begin,end} return 1 if collection
   type marks the beginning or end of a collection respectively. */

FD_FN_CONST static inline int
fd_flamenco_type_is_collection_begin( int type ) {
  return fd_flamenco_type_is_collection(type) && ((type&1)==0);
}

FD_FN_CONST static inline int
fd_flamenco_type_is_collection_end( int type ) {
  return fd_flamenco_type_is_collection(type) && ((type&1)!=0);
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_types_fd_types_meta_h */
