/* "Mini-funk" implementation for reference and testing purposes */

#include <stdlib.h>

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

FD_FN_PURE static rec_t * rec_query( funk_t * funk, txn_t * txn, ulong key );

static rec_t * rec_leave( funk_t * funk, rec_t * rec );
static void    rec_unmap( funk_t * funk, rec_t * rec );

FD_FN_PURE static int txn_is_frozen( txn_t * txn ) { return !!txn->child_head; }

FD_FN_PURE static int txn_is_only_child( txn_t * txn ) { return !txn->sibling_prev && !txn->sibling_next; }

FD_FN_PURE static txn_t *
txn_ancestor( txn_t * txn ) {
  for(;;) {
    if( !txn_is_only_child( txn ) ) break;
    if( !txn->parent ) return NULL;
    txn = txn->parent;
  }
  return txn;
}

FD_FN_PURE static txn_t *
txn_descendant( txn_t * txn ) {
  if( !txn_is_only_child( txn ) ) return NULL;
  for(;;) {
    if( !txn->child_head || !txn_is_only_child( txn->child_head ) ) break;
    txn = txn->child_head;
  }
  return txn;
}

static void
txn_unmap( funk_t * funk,
           txn_t *  txn ) {

  txn_t * prev = txn->map_prev;
  txn_t * next = txn->map_next;

  if( prev ) prev->map_next     = next;
  else       funk->txn_map_head = next;

  if( next ) next->map_prev     = prev;
  else       funk->txn_map_tail = prev;

  funk->txn_cnt--;
  free( txn );
}

static txn_t *
txn_leave( funk_t * funk,
           txn_t *  txn ) {
  txn_t ** _head = txn->parent ? &txn->parent->child_head : &funk->child_head;
  txn_t ** _tail = txn->parent ? &txn->parent->child_tail : &funk->child_tail;

  txn_t * prev = txn->sibling_prev;
  txn_t * next = txn->sibling_next;

  if( prev ) prev->sibling_next = next;
  else       *_head             = next;

  if( next ) next->sibling_prev = prev;
  else       *_tail             = prev;

  return txn;
}

static txn_t *
txn_prepare( funk_t * funk,
             txn_t *  parent,
             ulong    xid ) {
  //FD_LOG_NOTICE(( "prepare %lu (parent %lu)", xid, parent ? parent->xid : 0UL ));

  txn_t * txn = (txn_t *)malloc( sizeof(txn_t) );
  if( !txn ) FD_LOG_ERR(( "insufficient memory for unit test" ));

  txn->xid      = xid;
  txn->rec_head = NULL;
  txn->rec_tail = NULL;

  /* Map the txn */

  txn_t * prev = funk->txn_map_tail;

  txn->map_prev     = prev;
  txn->map_next     = NULL;

  if( prev ) prev->map_next     = txn;
  else       funk->txn_map_head = txn;
  funk->txn_map_tail = txn;

  funk->txn_cnt++;

  /* Join the family */

  txn_t ** _head = parent ? &parent->child_head : &funk->child_head;
  txn_t ** _tail = parent ? &parent->child_tail : &funk->child_tail;

  prev = *_tail;

  txn->parent       = parent;
  txn->child_head   = NULL;
  txn->child_tail   = NULL;
  txn->sibling_prev = prev;
  txn->sibling_next = NULL;

  if( prev ) prev->sibling_next = txn;
  else       *_head             = txn;
  *_tail = txn;

  return txn;
}

static txn_t * txn_cancel_children( funk_t * funk, txn_t * txn );

static void
txn_cancel( funk_t * funk,
            txn_t *  txn ) {
  //FD_LOG_NOTICE(( "cancel %lu", txn->xid ));

  rec_t * rec = txn->rec_head;
  while( rec ) {
    rec_t * next = rec->next;
    rec_unmap( funk, rec );
    rec = next;
  }

  txn_unmap( funk, txn_leave( funk, txn_cancel_children( funk, txn ) ) );
}

static txn_t *
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

static txn_t *
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

static ulong
txn_publish( funk_t * funk,
             txn_t *  txn,
             ulong    cnt ) {
  if( txn->parent ) cnt = txn_publish( funk, txn->parent, cnt );

  //FD_LOG_NOTICE(( "publish %lu", txn->xid ));

  rec_t * rec = txn->rec_head;
  while( rec ) {
    rec_t * next = rec->next;

    rec_t * root_rec = rec_query( funk, NULL, rec->key );

    if( rec->erase ) { /* erase published key */

      if( !root_rec ) FD_LOG_ERR(( "never get here unless memory corruption" )); /* should have key in the records */

      rec_unmap( funk, rec ); /* Unmap the record (don't bother leaving b/c we are unmapping everything */

      rec_unmap( funk, rec_leave( funk, root_rec ) ); /* Unmap root rec */

    } else if( !root_rec ) { /* key not published and not erasing, create published key */

      rec_t * prev = funk->rec_tail;

      rec->txn  = NULL;
      rec->prev = prev;
      rec->next = NULL;

      if( prev ) prev->next     = rec;
      else       funk->rec_head = rec;
      funk->rec_tail = rec;

    } else { /* key published and not erasing, update published key */

      rec_unmap( funk, rec ); /* Unmap the record (don't bother leaving b/c we are unmapping everything */

    }

    rec = next;
  }

  txn_cancel_siblings( funk, txn );

  for( txn_t * child=txn->child_head; child; child=child->sibling_next ) child->parent = NULL;
  funk->child_head = txn->child_head;
  funk->child_tail = txn->child_tail;

  funk->last_publish = txn->xid;

  txn_unmap( funk, txn );

  return cnt + 1UL;
}

static rec_t *
rec_query( funk_t * funk,
           txn_t *  txn,
           ulong    key ) {
  rec_t * rec = txn ? txn->rec_head : funk->rec_head;
  for( ; rec; rec=rec->next ) if( rec->key==key ) break;
  return rec;
}

FD_FN_PURE static rec_t *
rec_query_global( funk_t * funk,
                  txn_t *  txn,
                  ulong    key ) {
  while( txn ) {
    rec_t * rec = rec_query( funk, txn, key );
    if( rec ) return rec;
    txn = txn->parent;
  }
  return rec_query( funk, txn, key );
}

static rec_t *
rec_insert( funk_t * funk,
            txn_t *  txn,
            ulong    key ) {
  //FD_LOG_NOTICE(( "insert (%lu,%lu)", txn ? txn->xid : 0UL, key ));

  rec_t * rec = rec_query( funk, txn, key );
  if( rec ) {
    if( rec->erase ) { /* Undo any previous erase */
      rec->erase = 0;
      return rec;
    }
    FD_LOG_ERR(( "never get here unless user error" ));
  }

  rec = (rec_t *)malloc( sizeof(rec_t) );
  if( !rec ) FD_LOG_ERR(( "insufficient memory for unit test" ));

  /* Push into the map */

  rec->key   = key;
  rec->erase = 0;

  rec_t * prev = funk->rec_map_tail;

  rec->map_prev = prev;
  rec->map_next = NULL;

  if( prev ) prev->map_next     = rec;
  else       funk->rec_map_head = rec;
  funk->rec_map_tail = rec;

  funk->rec_cnt++;

  /* Join the txn */

  rec->txn = txn;

  rec_t ** _head = txn ? &txn->rec_head : &funk->rec_head;
  rec_t ** _tail = txn ? &txn->rec_tail : &funk->rec_tail;

  prev = *_tail;

  rec->prev = prev;
  rec->next = NULL;

  if( prev ) prev->next = rec;
  else       *_head     = rec;
  *_tail = rec;

  return rec;
}

static rec_t *
rec_leave( funk_t * funk,
           rec_t *  rec ) {
  rec_t ** _head = rec->txn ? &rec->txn->rec_head : &funk->rec_head;
  rec_t ** _tail = rec->txn ? &rec->txn->rec_tail : &funk->rec_tail;

  rec_t * prev = rec->prev;
  rec_t * next = rec->next;

  if( prev ) prev->next = next;
  else       *_head     = next;

  if( next ) next->prev = prev;
  else       *_tail     = prev;

  return rec;
}

static void
rec_unmap( funk_t * funk,
           rec_t *  rec ) {

  rec_t * map_prev = rec->map_prev;
  rec_t * map_next = rec->map_next;

  if( map_prev ) map_prev->map_next = map_next;
  else           funk->rec_map_head = map_next;

  if( map_next ) map_next->map_prev = map_prev;
  else           funk->rec_map_tail = map_prev;

  funk->rec_cnt--;
  free( rec );
}

static void
rec_remove( funk_t * funk,
            rec_t *  rec,
            int      erase ) {

  //FD_LOG_NOTICE(( "remove (%lu,%lu) erase=%i", rec->txn ? rec->txn->xid : 0UL, rec->key, erase ));

  if( !rec->txn ) {
    if( !erase     ) FD_LOG_ERR(( "never get here unless user error" ));
    if( rec->erase ) FD_LOG_ERR(( "never here unless memory corruption" ));
  } else {
    if( erase ) {
      if( rec->erase ) return; /* Already marked for erase */
      txn_t * txn = rec->txn;
      do {
        rec_t * match = rec_query( funk, txn->parent, rec->key );
        if( match ) {
          if( match->erase ) break; /* Already marked for erase in a recent ancestor so we can remove immediately */
          //FD_LOG_NOTICE(( "erases (%lu,%lu)", match->txn ? match->txn->xid : 0UL, rec->key ));
          rec->erase = 1;
          return;
        }
        txn = txn->parent;
      } while( txn );
    }
  }

  rec_unmap( funk, rec_leave( funk, rec ) );
}

static funk_t *
funk_new( void ) {
  funk_t * funk = (funk_t *)malloc( sizeof(funk_t) );
  if( !funk ) FD_LOG_ERR(( "insufficient memory for unit test" ));

  funk->last_publish = 0UL;
  funk->child_head   = NULL;
  funk->child_tail   = NULL;
  funk->txn_map_head = NULL;
  funk->txn_map_tail = NULL;
  funk->txn_cnt      = 0UL;

  funk->rec_head     = NULL;
  funk->rec_tail     = NULL;
  funk->rec_map_head = NULL;
  funk->rec_map_tail = NULL;
  funk->rec_cnt      = 0UL;

  return funk;
}

static void
funk_delete( funk_t * funk ) {
  txn_cancel_children( funk, NULL );
  rec_t * rec = funk->rec_map_head;
  while( rec ) {
    rec_t * next = rec->map_next;
    free( rec );
    rec = next;
  }
  free( funk );
}

static int funk_is_frozen( funk_t * funk ) { return !!funk->child_head; }

FD_FN_PURE static txn_t *
funk_descendant( funk_t * funk ) {
  return funk->child_head ? txn_descendant( funk->child_head ) : NULL;
}

static fd_funk_txn_xid_t *
xid_set( fd_funk_txn_xid_t * xid,
         ulong               _xid ) {
  xid->ul[0] = _xid; xid->ul[1] = _xid+_xid; xid->ul[2] = _xid*_xid; xid->ul[3] = -_xid;
  return xid;
}

static int
xid_eq( fd_funk_txn_xid_t const * xid,
         ulong                    _xid ) {
  fd_funk_txn_xid_t tmp[1];
  return fd_funk_txn_xid_eq( xid, xid_set( tmp, _xid ) );
}

static ulong
unique_xid( void ) {
  static ulong xid = 0UL;
  return ++xid;
}

static fd_funk_rec_key_t *
key_set( fd_funk_rec_key_t * key,
         ulong               _key ) {
  key->ul[0] = _key; key->ul[1] = _key+_key; key->ul[2] = _key*_key; key->ul[3] = -_key;
  key->ul[4] = _key; key->ul[5] = _key+_key; key->ul[6] = _key*_key; key->ul[7] = -_key;
  return key;
}

static int
key_eq( fd_funk_rec_key_t const * key,
         ulong                    _key ) {
  fd_funk_rec_key_t tmp[1];
  return fd_funk_rec_key_eq( key, key_set( tmp, _key ) );
}

