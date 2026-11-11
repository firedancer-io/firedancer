#ifndef HEADER_fd_src_discof_dragon_fd_dragon_watch_h
#define HEADER_fd_src_discof_dragon_fd_dragon_watch_h

/* fd_dragon_watch.h is the index of the accounts that Subscribe streams
   watch by address.

   A watch set is the list of addresses one stream asked to hear about,
   which the stream edits with add, remove and clear.  The index maps an
   address to the watch sets that hold it, so that an account write
   costs one lookup however many addresses are watched.

   An address is stored once, with one bit per watch set.  Up to
   FD_DRAGON_WATCH_SET_MAX sets are open at a time, which the owner
   numbers itself.  The memory for key_max distinct addresses is
   reserved when the index is created: an add that would need more
   fails and evicts nothing.

   Every operation is O(1).  Clearing or closing a set does not walk
   the index: the bit the set used is retired, and
   fd_dragon_watch_sweep takes retired bits out of the stored addresses
   a bounded number at a time.  Queries never see a retired bit.  Until
   the sweep is through, a retired bit cannot be given to another set
   and an address that only retired bits hold keeps its storage, so an
   add can fail for a while after a clear or a close.  The caller tells
   that case from a full index with fd_dragon_watch_sweep_pending and
   tries again after sweeping.

   The index is single threaded and local to the tile that owns it. */

#include "../../util/fd_util_base.h"

#define FD_DRAGON_WATCH_ALIGN   (128UL)
#define FD_DRAGON_WATCH_SET_MAX (64UL)

/* FD_DRAGON_WATCH_KEY_MAX is the largest key_max an index takes. */

#define FD_DRAGON_WATCH_KEY_MAX ((1UL<<31)-1UL)

struct fd_dragon_watch;
typedef struct fd_dragon_watch fd_dragon_watch_t;

FD_PROTOTYPES_BEGIN

/* Construction ********************************************************/

FD_FN_CONST ulong
fd_dragon_watch_align( void );

/* fd_dragon_watch_footprint returns the size of the memory region an
   index of key_max distinct addresses needs, or 0 if key_max is not in
   [1,FD_DRAGON_WATCH_KEY_MAX]. */

FD_FN_CONST ulong
fd_dragon_watch_footprint( ulong key_max );

/* fd_dragon_watch_new formats mem as an empty index with no open set.
   seed keys the address hash and should be unpredictable to clients.
   Returns mem on success, NULL on failure (logs warning). */

void *
fd_dragon_watch_new( void * mem,
                     ulong  key_max,
                     ulong  seed );

fd_dragon_watch_t *
fd_dragon_watch_join( void * mem );

void *
fd_dragon_watch_leave( fd_dragon_watch_t * watch );

void *
fd_dragon_watch_delete( void * mem );

/* Sets ****************************************************************/

/* fd_dragon_watch_set_open opens the empty watch set numbered set,
   which is in [0,FD_DRAGON_WATCH_SET_MAX) and not open.

   fd_dragon_watch_set_clear empties an open set.
   fd_dragon_watch_set_close empties it and closes it.  Both take
   effect for queries at once. */

void
fd_dragon_watch_set_open( fd_dragon_watch_t * watch,
                          ulong               set );

void
fd_dragon_watch_set_clear( fd_dragon_watch_t * watch,
                           ulong               set );

void
fd_dragon_watch_set_close( fd_dragon_watch_t * watch,
                           ulong               set );

/* fd_dragon_watch_set_mask returns the open sets, bit i for set i.
   fd_dragon_watch_set_key_cnt returns the number of addresses in an
   open set. */

FD_FN_PURE ulong
fd_dragon_watch_set_mask( fd_dragon_watch_t const * watch );

FD_FN_PURE ulong
fd_dragon_watch_set_key_cnt( fd_dragon_watch_t const * watch,
                             ulong                     set );

/* Addresses ***********************************************************/

/* fd_dragon_watch_add adds the 32 byte address pubkey to an open set.
   Returns 1 if it was added, 0 if the set held it already and -1 if
   there is no room for it, in which case nothing changed.  There is no
   room when the index stores key_max distinct addresses or, for the
   first address of a set, when every bit is in use or retired.  If
   fd_dragon_watch_sweep_pending is set, sweeping can make room. */

int
fd_dragon_watch_add( fd_dragon_watch_t * watch,
                     ulong               set,
                     uchar const *       pubkey );

/* fd_dragon_watch_remove removes pubkey from an open set.  Returns 1
   if it was removed and 0 if the set did not hold it. */

int
fd_dragon_watch_remove( fd_dragon_watch_t * watch,
                        ulong               set,
                        uchar const *       pubkey );

/* fd_dragon_watch_query returns the open sets that hold pubkey, bit i
   for set i. */

FD_FN_PURE ulong
fd_dragon_watch_query( fd_dragon_watch_t const * watch,
                       uchar const *             pubkey );

/* fd_dragon_watch_ref returns a reference to an address an open set
   holds, or ULONG_MAX if the set does not hold pubkey.

   fd_dragon_watch_ref_key returns the address ref names if set still
   holds it, and NULL if the address left the set since, whatever was
   stored in its place.  The pointer is valid until the index is next
   modified. */

FD_FN_PURE ulong
fd_dragon_watch_ref( fd_dragon_watch_t const * watch,
                     ulong                     set,
                     uchar const *             pubkey );

FD_FN_PURE uchar const *
fd_dragon_watch_ref_key( fd_dragon_watch_t const * watch,
                         ulong                     set,
                         ulong                     ref );

/* An address is pending in a set from the add that put it there until
   the owner has answered that add.  fd_dragon_watch_ref_pending sets
   or clears the mark for the address ref names, and does nothing if
   set does not hold that address any more.  Removing an address or
   emptying its set clears the mark.

   fd_dragon_watch_query_pending is fd_dragon_watch_query that also
   returns in *pending the sets among the result where the address is
   pending. */

void
fd_dragon_watch_ref_pending( fd_dragon_watch_t * watch,
                             ulong               set,
                             ulong               ref,
                             int                 pending );

ulong
fd_dragon_watch_query_pending( fd_dragon_watch_t const * watch,
                               uchar const *             pubkey,
                               ulong *                   pending );

/* fd_dragon_watch_key_cnt returns the number of distinct addresses the
   index stores, which counts those only retired bits still hold.
   fd_dragon_watch_key_max returns the key_max it was created with. */

FD_FN_PURE ulong
fd_dragon_watch_key_cnt( fd_dragon_watch_t const * watch );

FD_FN_PURE ulong
fd_dragon_watch_key_max( fd_dragon_watch_t const * watch );

/* Sweep ***************************************************************/

/* fd_dragon_watch_sweep visits up to visit_max storage slots and takes
   the retired bits out of the addresses in them.  Returns 1 if retired
   bits remain and 0 if none do.  key_max visits after a clear or a
   close, the bit it retired is free and the addresses only it held
   are gone.

   fd_dragon_watch_sweep_pending returns what the next call to
   fd_dragon_watch_sweep would return without visiting anything. */

int
fd_dragon_watch_sweep( fd_dragon_watch_t * watch,
                       ulong               visit_max );

FD_FN_PURE int
fd_dragon_watch_sweep_pending( fd_dragon_watch_t const * watch );

/* fd_dragon_watch_verify checks the index against its own invariants.
   Returns 0 if they hold and -1 otherwise (logs warning).  O(key_max). */

int
fd_dragon_watch_verify( fd_dragon_watch_t const * watch );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_dragon_fd_dragon_watch_h */
