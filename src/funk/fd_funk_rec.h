#ifndef HEADER_fd_src_funk_fd_funk_rec_h
#define HEADER_fd_src_funk_fd_funk_rec_h

/* This provides APIs for managing records.  It is generally not meant
   to be included directly.  Use fd_funk.h instead. */

#include "fd_funk_txn.h" /* Includes fd_funk_base.h */

/* A fd_funk_rec_t describes a funk record. */

struct fd_funk_rec {

  /* These fields are managed by the funk's rec_map */

  fd_funk_xid_key_pair_t pair;     /* transaction id and record key pair */
  ulong                  map_next; /* Internal use by map */

  /* Additional stuff goes here */

};

typedef struct fd_funk_rec fd_funk_rec_t;

/* fd_funk_rec_map allows for indexing records by their (xid,key) pair.
   It is used to store all records of the last published transaction and
   dirty records from transactions in-preparation. */

#define MAP_NAME              fd_funk_rec_map
#define MAP_T                 fd_funk_rec_t
#define MAP_KEY_T             fd_funk_xid_key_pair_t
#define MAP_KEY               pair
#define MAP_KEY_EQ(k0,k1)     fd_funk_xid_key_pair_eq((k0),(k1))
#define MAP_KEY_HASH(k0,seed) fd_funk_xid_key_pair_hash((k0),(seed))
#define MAP_KEY_COPY(kd,ks)   fd_funk_xid_key_pair_copy((kd),(ks))
#define MAP_NEXT              map_next
#define MAP_MAGIC             (0xf173da2ce77ecdb0UL) /* Firedancer rec db version 0 */
#define MAP_IMPL_STYLE        1
#include "../util/tmpl/fd_map_giant.c"

FD_PROTOTYPES_BEGIN

/* Accessors */

/* fd_funk_rec_cnt returns the number of transactions currently in
   preparation.  Assumes funk is a current local join,
   map==fd_funk_rec_map( funk, fd_funk_wksp( funk ) ).  See fd_funk.h
   for fd_funk_rec_max. */

FD_FN_PURE static inline ulong fd_funk_rec_cnt( fd_funk_rec_t const * map ) { return fd_funk_rec_map_key_cnt( map ); }

/* fd_funk_rec_is_full returns 1 if the transaction map is full (i.e.
   the maximum of transactions that can be in preparation has been
   reached) and 0 otherwise.  Assumes funk is a current local join,
   map==fd_funk_rec_map( funk, fd_funk_wksp( funk ) ). */

FD_FN_PURE static inline int fd_funk_rec_is_full( fd_funk_rec_t const * map ) { return fd_funk_rec_map_is_full( map ); }

/* Misc */

/* fd_funk_rec_verify verifies the record map.  Returns FD_FUNK_SUCCESS
   if the record map appears intact and FD_FUNK_ERR_INVAL if not (logs
   details).  Meant to be called as part of fd_funk_verify.  As such, it
   assumes funk is non-NULL, fd_funk_{wksp,txn_map,rec_map} have been
   verified to work and the txn_map has been verified. */

int
fd_funk_rec_verify( fd_funk_t * funk );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_funk_fd_funk_rec_h */
