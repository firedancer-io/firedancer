#include "fd_sysvar_cache.h"
#include "../fd_acc_mgr.h"
#include "../fd_system_ids.h"

#define FD_SYSVAR_CACHE_MAGIC    (0x195a0e78828cacd5UL)
#define FD_SYSVAR_CACHE_WKSP_TAG (25UL)

/* Reuse this table to avoid code duplication */
#define FD_SYSVAR_CACHE_ITER(X) \
  X( fd_sol_sysvar_clock,             clock               ) \
  X( fd_epoch_schedule,               epoch_schedule      ) \
  X( fd_sysvar_epoch_rewards,         epoch_rewards       ) \
  X( fd_sysvar_fees,                  fees                ) \
  X( fd_rent,                         rent                ) \
  X( fd_slot_hashes,                  slot_hashes         ) \
  X( fd_recent_block_hashes,          recent_block_hashes ) \
  X( fd_stake_history,                stake_history       ) \
  X( fd_sol_sysvar_last_restart_slot, last_restart_slot   )

/* The memory of fd_sysvar_cache_t fits as much sysvar information into
   the struct as possible.  Unfortunately some parts of the sysvar
   spill out onto the heap due to how the type generator works.

   The has_{...} bits specify whether a sysvar logically exists.
   The val_{...} structs contain the top-level struct of each sysvar.
   If has_{...}==0 then any heap pointers in val_{...} are NULL,
   allowing for safe idempotent calls to fd_sol_sysvar_{...}_destroy() */

struct __attribute__((aligned(16UL))) fd_sysvar_cache_private {
  ulong        magic;  /* ==FD_SYSVAR_CACHE_MAGIC */
  fd_alloc_t * alloc;

  /* Declare the val_{...} values */
# define X( type, name ) \
  type##_t val_##name[1];
  FD_SYSVAR_CACHE_ITER(X)
# undef X

  /* Declare the has_{...} bits */
# define X( _type, name ) \
  ulong has_##name : 1;
  FD_SYSVAR_CACHE_ITER(X)
# undef X
};

ulong
fd_sysvar_cache_align( void ) {
  return alignof(fd_sysvar_cache_t);
}

ulong
fd_sysvar_cache_footprint( void ) {
  return sizeof(fd_sysvar_cache_t);
}

fd_sysvar_cache_t *
fd_sysvar_cache_new( void *      mem,
                     fd_wksp_t * wksp,
                     ulong       cgroup_hint ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "NULL wksp" ));
    return NULL;
  }

  fd_sysvar_cache_t * cache = (fd_sysvar_cache_t *)mem;
  fd_memset( cache, 0, sizeof(fd_sysvar_cache_t) );

  ulong  wksp_tag  = FD_SYSVAR_CACHE_WKSP_TAG;
  void * alloc_mem = fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), cgroup_hint );

  fd_alloc_t * alloc = fd_alloc_join( fd_alloc_new( alloc_mem, wksp_tag ), cgroup_hint );
  if( FD_UNLIKELY( !alloc ) ) return NULL;

  cache->alloc = alloc;

  FD_COMPILER_MFENCE();
  cache->magic = FD_SYSVAR_CACHE_MAGIC;
  FD_COMPILER_MFENCE();
  return cache;
}

void *
fd_sysvar_cache_delete( fd_sysvar_cache_t * cache ) {

  if( FD_UNLIKELY( !cache ) ) {
    FD_LOG_WARNING(( "NULL cache" ));
    return NULL;
  }

  if( FD_UNLIKELY( cache->magic != FD_SYSVAR_CACHE_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  if( FD_UNLIKELY( !cache->alloc ) ) {
    FD_LOG_WARNING(( "NULL alloc" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  cache->magic = 0UL;
  FD_COMPILER_MFENCE();

  /* fd_alloc_delete is not guaranteed to delete all allocations */
  fd_alloc_t * alloc = cache->alloc;
  fd_bincode_destroy_ctx_t ctx = { .valloc = fd_alloc_virtual( alloc ) };

  /* Call destroy on all objects.
     This is safe even if these objects logically don't exist
     (destory is safe on zero-initialized values and is idempotent) */
# define X( type, name ) \
  type##_destroy( cache->val_##name, &ctx );
  FD_SYSVAR_CACHE_ITER(X)
# undef X

  fd_alloc_delete( fd_alloc_leave( cache->alloc ) );
  return (void *)cache;
}

/* Define accessor methods */

#define X( type, name )                                                \
  type##_t const *                                                     \
  fd_sysvar_cache_##name( fd_sysvar_cache_t const * cache ) {          \
    return cache->val_##name;                                          \
  }
FD_SYSVAR_CACHE_ITER(X)
#undef X

/* Declare functions to restore sysvars */

#define X( type, name )                                                \
  static void                                                          \
  restore_##name( fd_sysvar_cache_t * cache,                           \
                  uchar const *       data,                            \
                  ulong               data_sz );
FD_SYSVAR_CACHE_ITER(X)
#undef X

static void
restore_one( fd_sysvar_cache_t * cache,
             fd_pubkey_t const * address,
             uchar const *       data,
             ulong               data_sz ) {
  /* Generate a chain of ifs that reloads the requested sysvar */
  /* TODO it would be nice to use the perfect hash table here to turn
          this into a switch */
# define X( type, name )                                                    \
  if( 0==memcmp( address, &fd_sysvar_##name##_id, sizeof(fd_pubkey_t) ) ) { \
    restore_##name( cache, data, data_sz );                                 \
    return;                                                                 \
  }
  FD_SYSVAR_CACHE_ITER(X)
# undef X
}

void
fd_sysvar_cache_restore_one( fd_sysvar_cache_t * cache,
                             fd_pubkey_t const * address,
                             uchar const *       data,
                             ulong               data_sz ) {
  if( !fd_pubkey_is_sysvar_id( address ) ) return;
  restore_one( cache, address, data, data_sz );
}

static void
restore_one_managed( fd_sysvar_cache_t *  cache,
                     fd_exec_slot_ctx_t * slot_ctx,
                     fd_pubkey_t const *  pubkey ) {

  fd_acc_mgr_t *  acc_mgr  = slot_ctx->acc_mgr;
  fd_funk_txn_t * funk_txn = slot_ctx->funk_txn;

  FD_BORROWED_ACCOUNT_DECL( account );
  int view_err = fd_acc_mgr_view( acc_mgr, funk_txn, pubkey, account );
  if( view_err==FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) return;

  if( FD_UNLIKELY( view_err!=FD_ACC_MGR_SUCCESS ) ) {
    char pubkey_cstr[ FD_BASE58_ENCODED_32_SZ ];
    FD_LOG_ERR(( "fd_acc_mgr_view(%s) failed (%d-%s)",
                 fd_acct_addr_cstr( pubkey_cstr, pubkey->key ),
                 view_err, fd_acc_mgr_strerror( view_err ) ));
  }

  restore_one( cache, pubkey, account->const_data, account->const_meta->dlen );
}

void
fd_sysvar_cache_restore( fd_sysvar_cache_t *  cache,
                         fd_exec_slot_ctx_t * slot_ctx ) {

  static fd_pubkey_t const * pubkeys[] = {
#   define X( type, name ) &fd_sysvar_##name##_id,
    FD_SYSVAR_CACHE_ITER(X)
#   undef X
  };
  ulong const pubkey_cnt = sizeof(pubkeys)/sizeof(fd_pubkey_t const *);

  for( ulong j=0UL; j<pubkey_cnt; j++ ) {
    restore_one_managed( cache, slot_ctx, pubkeys[j] );
  }
}

/* Generate functions to restore sysvars */

#define X( type, name )                                                \
  static void                                                          \
  restore_##name( fd_sysvar_cache_t * cache,                           \
                  uchar const *       data,                            \
                  ulong               data_sz ) {                      \
                                                                       \
    /* Destroy previous value */                                       \
                                                                       \
    fd_bincode_destroy_ctx_t destroy =                                 \
      { .valloc = fd_alloc_virtual( cache->alloc ) };                  \
    type##_destroy( cache->val_##name, &destroy );                     \
                                                                       \
    /* Decode new value                                                \
       type##_decode() does not do heap allocations on failure */      \
                                                                       \
    fd_bincode_decode_ctx_t decode =                                   \
      { .data    = data,                                               \
        .dataend = data + data_sz,                                     \
        .valloc  = fd_alloc_virtual( cache->alloc ) };                 \
    int err = type##_decode( cache->val_##name, &decode );             \
    cache->has_##name = (err==FD_BINCODE_SUCCESS);                     \
  }
FD_SYSVAR_CACHE_ITER(X)
#undef X
