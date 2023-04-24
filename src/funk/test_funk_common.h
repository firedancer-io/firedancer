#ifndef HEADER_fd_src_funk_test_funk_common_h
#define HEADER_fd_src_funk_test_funk_common_h

/* "Mini-funk" implementation for reference and testing purposes */

#include "fd_funk_base.h"

struct txn;
typedef struct txn txn_t;

struct rec;
typedef struct rec rec_t;

struct rec {
  txn_t * txn;
  ulong   key;
  rec_t * prev;
  rec_t * next;
  rec_t * map_prev;
  rec_t * map_next;
  int     erase;
  uint    val;
};

struct txn {
  ulong   xid;
  txn_t * parent;
  txn_t * child_head;
  txn_t * child_tail;
  txn_t * sibling_prev;
  txn_t * sibling_next;
  txn_t * map_prev;
  txn_t * map_next;
  rec_t * rec_head;
  rec_t * rec_tail;
};

struct funk {
  ulong   last_publish;
  txn_t * child_head;
  txn_t * child_tail;
  txn_t * txn_map_head;
  txn_t * txn_map_tail;
  ulong   txn_cnt;
  rec_t * rec_head;
  rec_t * rec_tail;
  rec_t * rec_map_head;
  rec_t * rec_map_tail;
  ulong   rec_cnt;
};

typedef struct funk funk_t;

FD_PROTOTYPES_BEGIN

/* Mini txn API */

FD_FN_PURE static inline int txn_is_frozen( txn_t * txn ) { return !!txn->child_head; }

FD_FN_PURE static inline int txn_is_only_child( txn_t * txn ) { return !txn->sibling_prev && !txn->sibling_next; }

FD_FN_PURE static inline txn_t *
txn_ancestor( txn_t * txn ) {
  for(;;) {
    if( !txn_is_only_child( txn ) ) break;
    if( !txn->parent ) return NULL;
    txn = txn->parent;
  }
  return txn;
}

FD_FN_PURE static inline txn_t *
txn_descendant( txn_t * txn ) {
  if( !txn_is_only_child( txn ) ) return NULL;
  for(;;) {
    if( !txn->child_head || !txn_is_only_child( txn->child_head ) ) break;
    txn = txn->child_head;
  }
  return txn;
}

txn_t *
txn_prepare( funk_t * funk,
             txn_t *  parent,
             ulong    xid );

void
txn_cancel( funk_t * funk,
            txn_t *  txn );

ulong
txn_publish( funk_t * funk,
             txn_t *  txn,
             ulong    cnt );

void
txn_merge( funk_t * funk,
           txn_t *  txn );

static inline txn_t *
txn_cancel_children( funk_t * funk,
                     txn_t *  txn ) {
  txn_t * child = txn ? txn->child_head : funk->child_head;
  while( child ) {
    txn_t * next = child->sibling_next;
    txn_cancel( funk, child );
    child = next;
  }
  return txn;
}

static inline txn_t *
txn_cancel_siblings( funk_t * funk,
                     txn_t *  txn ) {
  txn_t * child = txn->parent ? txn->parent->child_head : funk->child_head;
  while( child ) {
    txn_t * next = child->sibling_next;
    if( child!=txn ) txn_cancel( funk, child );
    child = next;
  }
  return txn;
}

/* Mini rec API */

FD_FN_PURE rec_t *
rec_query( funk_t * funk,
           txn_t *  txn,
           ulong    key );

FD_FN_PURE rec_t *
rec_query_global( funk_t * funk,
                  txn_t *  txn,
                  ulong    key );

rec_t *
rec_insert( funk_t * funk,
            txn_t *  txn,
            ulong    key );

void
rec_remove( funk_t * funk,
            rec_t *  rec,
            int      erase );

/* Mini funk API */

funk_t *
funk_new( void );

void
funk_delete( funk_t * funk );

static inline int funk_is_frozen( funk_t * funk ) { return !!funk->child_head; }

FD_FN_PURE static inline txn_t *
funk_descendant( funk_t * funk ) {
  return funk->child_head ? txn_descendant( funk->child_head ) : NULL;
}

/* Testing utilities */

ulong
xid_unique( void );

static inline fd_funk_txn_xid_t *
xid_set( fd_funk_txn_xid_t * xid,
         ulong               _xid ) {
  xid->ul[0] = _xid; xid->ul[1] = _xid+_xid; xid->ul[2] = _xid*_xid; xid->ul[3] = -_xid;
  return xid;
}

FD_FN_PURE static inline int
xid_eq( fd_funk_txn_xid_t const * xid,
         ulong                    _xid ) {
  fd_funk_txn_xid_t tmp[1];
  return fd_funk_txn_xid_eq( xid, xid_set( tmp, _xid ) );
}

static inline fd_funk_rec_key_t *
key_set( fd_funk_rec_key_t * key,
         ulong               _key ) {
  key->ul[0] = _key; key->ul[1] = _key+_key; key->ul[2] = _key*_key; key->ul[3] = -_key;
  key->ul[4] = _key; key->ul[5] = _key+_key; key->ul[6] = _key*_key; key->ul[7] = -_key;
  return key;
}

FD_FN_PURE int
key_eq( fd_funk_rec_key_t const * key,
        ulong                     _key );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_funk_test_funk_common_h */
