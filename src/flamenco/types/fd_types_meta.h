#ifndef HEADER_fd_src_flamenco_types_fd_types_meta_h
#define HEADER_fd_src_flamenco_types_fd_types_meta_h

/* fd_types_meta.h provides type reflection APIs fd_types. */

/* FD_FLAMENCO_TYPEMASK_{...} masks common kinds of type nodes.

   ...PRIMITIVE nodes contain individual types.
   ...STRUCTURAL nodes contain a sequence of sub-nodes.
      For each structural type, there is _BEGIN and _END node,
      identified by the least significant bit. */

#define FD_FLAMENCO_TYPEMASK_PRIMITIVE  (0x0f)
#define FD_FLAMENCO_TYPEMASK_STRUCTURAL (0xf0)

/* FD_FLAMENCO_TYPE_{...} identifies kinds of nodes */

#define FD_FLAMENCO_TYPE_BOOL      (0x01)
#define FD_FLAMENCO_TYPE_UCHAR     (0x02)
#define FD_FLAMENCO_TYPE_SCHAR     (0x03)
#define FD_FLAMENCO_TYPE_USHORT    (0x04)
#define FD_FLAMENCO_TYPE_SSHORT    (0x05)
#define FD_FLAMENCO_TYPE_UINT      (0x06)
#define FD_FLAMENCO_TYPE_SINT      (0x07)
#define FD_FLAMENCO_TYPE_ULONG     (0x08)
#define FD_FLAMENCO_TYPE_SLONG     (0x09)
#define FD_FLAMENCO_TYPE_UINT128   (0x0a)
#define FD_FLAMENCO_TYPE_SINT128   (0x0b)
#define FD_FLAMENCO_TYPE_FLOAT     (0x0c)
#define FD_FLAMENCO_TYPE_DOUBLE    (0x0d)
#define FD_FLAMENCO_TYPE_HASH256   (0x0e)  /* pubkey, account */
#define FD_FLAMENCO_TYPE_CSTR      (0x0f)

#define FD_FLAMENCO_TYPE_ARR_START (0x10)
#define FD_FLAMENCO_TYPE_ARR_END   (0x11)
#define FD_FLAMENCO_TYPE_OPT_START (0x12)
#define FD_FLAMENCO_TYPE_OPT_END   (0x13)
#define FD_FLAMENCO_TYPE_MAP_START (0x14)
#define FD_FLAMENCO_TYPE_MAP_END   (0x15)

#endif /* HEADER_fd_src_flamenco_types_fd_types_meta_h */
