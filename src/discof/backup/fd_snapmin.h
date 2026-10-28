#ifndef HEADER_fd_src_discof_backup_fd_snapmin_h
#define HEADER_fd_src_discof_backup_fd_snapmin_h

/* fd_snapmin is the keep set of the snapshot minimizer: the addresses
   of the accounts the minimized snapshot carries.  Many tiles insert
   at once; one tile reads the set after all inserts are done. */

#include "../../disco/topo/fd_topo.h"
#include "../../flamenco/runtime/fd_bank.h"

/* The all zero key is the system program, so a free slot is marked by
   used==0, not by the key. */

struct fd_snapmin_ele {
  fd_pubkey_t key;
  ulong       used;
};
typedef struct fd_snapmin_ele fd_snapmin_ele_t;

#define MAP_NAME                  fd_snapmin_map
#define MAP_ELE_T                 fd_snapmin_ele_t
#define MAP_KEY_T                 fd_pubkey_t
#define MAP_KEY_EQ(k0,k1)         fd_pubkey_eq( (k0), (k1) )
#define MAP_KEY_HASH(key,seed)    fd_hash( (seed), (key), sizeof(fd_pubkey_t) )
#define MAP_ELE_IS_FREE(ctx,ele)  (!(ele)->used)
#define MAP_ELE_FREE(ctx,ele)     do { (ele)->used = 0UL; } while(0)
#define MAP_ELE_MOVE(ctx,dst,src) do { *(dst) = *(src); (src)->used = 0UL; } while(0)
#define MAP_VERSION_T             ushort
#define MAP_LOCK_MAX              (8192)
#define MAP_IMPL_STYLE            1
#include "../../util/tmpl/fd_map_slot_para.c"

/* The shared object: this header, then the map, then the elements. */

struct fd_snapmin_shmem {
  ulong magic;
  ulong ele_max;
};
typedef struct fd_snapmin_shmem fd_snapmin_shmem_t;

struct fd_snapmin {
  fd_snapmin_shmem_t * shmem;
  fd_snapmin_map_t     map[1];
};
typedef struct fd_snapmin fd_snapmin_t;

FD_PROTOTYPES_BEGIN

ulong
fd_snapmin_align( void );

/* ele_max is a power of two. */

ulong
fd_snapmin_footprint( ulong ele_max );

void *
fd_snapmin_new( void * shmem,
                ulong  ele_max,
                ulong  seed );

fd_snapmin_t *
fd_snapmin_join( void * ljoin,
                 void * shmem );

/* fd_snapmin_insert adds pubkey to the set.  Many tiles may insert at
   once.  Aborts when the set is full. */

void
fd_snapmin_insert( fd_snapmin_t * set,
                   uchar const *  pubkey );

/* fd_snapmin_next copies up to out_max keys to out, scanning from
   *cursor, and moves the cursor past them.  Start with *cursor==0.
   Returns the count, 0 at the end.  One reader; an insert still in
   flight is seen whole or not at all. */

ulong
fd_snapmin_next( fd_snapmin_t * set,
                 ulong *        cursor,
                 fd_pubkey_t *  out,
                 ulong          out_max );

/* fd_snapmin_keep_boot_accounts inserts the accounts the loader and
   replay read without a transaction naming them: the feature, sysvar,
   program, vote and Alpenglow accounts of the snapshot bank, and the
   stake accounts when the slots up to end_slot cross into a new epoch
   or rewards are still paying out.  Reads the bank and the root stake
   store only. */

void
fd_snapmin_keep_boot_accounts( fd_snapmin_t * set,
                               fd_bank_t *    bank,
                               fd_banks_t *   banks,
                               ulong          end_slot );

/* fd_snapmin_balance_key is the address of the balancing account,
   sha256 of "firedancer snapshot minimizer". */

extern fd_pubkey_t const fd_snapmin_balance_key;

/* Topology object "snapmin", sized by the pod key obj.<id>.ele_max. */

extern fd_topo_obj_callbacks_t fd_obj_cb_snapmin;

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_backup_fd_snapmin_h */
