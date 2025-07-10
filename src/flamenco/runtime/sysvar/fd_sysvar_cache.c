#include "fd_sysvar_cache.h"
#include "fd_sysvar_cache_private.h"
#include "fd_sysvar.h"
#include "../context/fd_exec_slot_ctx.h"
#include "../fd_system_ids_pp.h"
#include "fd_sysvar_clock.h"

struct sysvar_tbl {
  fd_pubkey_t key;
  uchar       desc_idx;
};
typedef struct sysvar_tbl sysvar_tbl_t;

#define MAP_PERFECT_NAME        sysvar_map
#define MAP_PERFECT_LG_TBL_SZ   4
#define MAP_PERFECT_T           sysvar_tbl_t
#define MAP_PERFECT_HASH_C      212885
#define MAP_PERFECT_KEY         key.uc
#define MAP_PERFECT_KEY_T       fd_pubkey_t const *
#define MAP_PERFECT_ZERO_KEY    (0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0)
#define MAP_PERFECT_COMPLEX_KEY 1
#define MAP_PERFECT_KEYS_EQUAL(k1,k2) (!memcmp( (k1), (k2), 32UL ))
#define PERFECT_HASH( u ) (((MAP_PERFECT_HASH_C*(u))>>28)&0xFU)
#define MAP_PERFECT_HASH_PP( a00,a01,a02,a03,a04,a05,a06,a07,a08,a09,a10,a11,a12,a13,a14,a15,    \
                             a16,a17,a18,a19,a20,a21,a22,a23,a24,a25,a26,a27,a28,a29,a30,a31) \
  PERFECT_HASH( (a08 | (a09<<8) | (a10<<16) | (a11<<24)) )
#define MAP_PERFECT_HASH_R( ptr ) PERFECT_HASH( fd_uint_load_4( (uchar const *)ptr + 8UL ) )
#define MAP_SYSVAR( id, desc ) ( id ), .desc_idx = ( offsetof( fd_sysvar_cache_descs_t, desc ) / sizeof(fd_sysvar_cache_desc_t) )
#define MAP_PERFECT_0  MAP_SYSVAR( SYSVAR_CLOCK_ID,          clock               )
#define MAP_PERFECT_1  MAP_SYSVAR( SYSVAR_SLOT_HIST_ID,      slot_history        )
#define MAP_PERFECT_2  MAP_SYSVAR( SYSVAR_SLOT_HASHES_ID,    slot_hashes         )
#define MAP_PERFECT_3  MAP_SYSVAR( SYSVAR_EPOCH_SCHED_ID,    epoch_schedule      )
#define MAP_PERFECT_4  MAP_SYSVAR( SYSVAR_RECENT_BLKHASH_ID, recent_block_hashes )
#define MAP_PERFECT_5  MAP_SYSVAR( SYSVAR_RENT_ID,           rent                )
#define MAP_PERFECT_6  MAP_SYSVAR( SYSVAR_EPOCH_REWARDS_ID,  epoch_rewards       )
#define MAP_PERFECT_7  MAP_SYSVAR( SYSVAR_STAKE_HIST_ID,     stake_history       )
#define MAP_PERFECT_8  MAP_SYSVAR( SYSVAR_LAST_RESTART_ID,   last_restart_slot   )
#include "../../../util/tmpl/fd_map_perfect.c"
#undef PERFECT_HASH

FD_FN_CONST ulong
fd_sysvar_cache_align( void ) {
  return FD_SYSVAR_CACHE_ALIGN;
}

FD_FN_CONST ulong
fd_sysvar_cache_footprint( void ) {
  return FD_SYSVAR_CACHE_FOOTPRINT;
}

void *
fd_sysvar_cache_new( void * mem ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_SYSVAR_CACHE_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  memset( mem, 0, sizeof(fd_sysvar_cache_footprint()) );
  fd_sysvar_cache_t * sysvar_cache = mem;

  FD_COMPILER_MFENCE();
  sysvar_cache->magic = FD_SYSVAR_CACHE_MAGIC;
  FD_COMPILER_MFENCE();

  return sysvar_cache;
}

fd_sysvar_cache_t *
fd_sysvar_cache_join( void * mem ) {
  /* FIXME refcount writer */
  return (fd_sysvar_cache_t *)fd_sysvar_cache_join_const( mem );
}

fd_sysvar_cache_t const *
fd_sysvar_cache_join_const( void const * mem ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_SYSVAR_CACHE_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  fd_sysvar_cache_t const * sysvar_cache = mem;
  if( FD_UNLIKELY( sysvar_cache->magic != FD_SYSVAR_CACHE_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return sysvar_cache;
}

void *
fd_sysvar_cache_leave( fd_sysvar_cache_t * sysvar_cache ) {
  return sysvar_cache;
}

void const *
fd_sysvar_cache_leave_const( fd_sysvar_cache_t const * sysvar_cache ) {
  return sysvar_cache;
}

void *
fd_sysvar_cache_delete( void * mem ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  fd_sysvar_cache_t * sysvar_cache = mem;
  if( FD_UNLIKELY( sysvar_cache->magic != FD_SYSVAR_CACHE_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  memset( sysvar_cache, 0, sizeof(fd_sysvar_cache_t) );

  return mem;
}

void *
fd_sysvar_cache_clone( void *                    mem2,
                       fd_sysvar_cache_t const * orig ) {

  if( FD_UNLIKELY( !mem2 ) ) {
    FD_LOG_WARNING(( "NULL mem2" ));
    return NULL;
  }
  if( FD_UNLIKELY( !orig ) ) {
    FD_LOG_WARNING(( "NULL orig" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem2, FD_SYSVAR_CACHE_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( orig->magic!=FD_SYSVAR_CACHE_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  memcpy( mem2, orig, fd_sysvar_cache_footprint() );
  return mem2;
}

void
fd_sysvar_cache_recover( fd_exec_slot_ctx_t * slot_ctx ) {

}

uchar const *
fd_sysvar_cache_data_query(
    fd_sysvar_cache_t const * sysvar_cache,
    void const *              address, /* 32 bytes */
    ulong *                   psz
) {
  fd_pubkey_t pubkey; memcpy( pubkey.uc, address, 32UL );
  sysvar_tbl_t const * entry = sysvar_map_query( &pubkey, NULL );
  if( FD_UNLIKELY( !entry ) ) return NULL; /* address is not a sysvar */
  fd_sysvar_cache_desc_t const * desc = &sysvar_cache->desc_tbl[ entry->desc_idx ];
  if( !fd_sysvar_cache_flags_valid( desc->flags ) ) return NULL; /* sysvar data invalid */
  *psz = desc->data_sz;
  return (uchar const *)fd_sysvar_cache_data_laddr( sysvar_cache, desc );
}

uchar *
fd_sysvar_cache_data_modify_prepare(
    fd_exec_slot_ctx_t * slot_ctx,
    void const *         address, /* 32 bytes */
    ulong *              opt_sz,
    ulong *              opt_sz_max
) {
  fd_sysvar_cache_t * cache = fd_bank_sysvar_cache_modify( slot_ctx->bank );
  fd_pubkey_t pubkey; memcpy( pubkey.uc, address, 32UL );
  sysvar_tbl_t const * entry = sysvar_map_query( &pubkey, NULL );
  if( FD_UNLIKELY( !entry ) ) {
    char address_cstr[ FD_BASE58_ENCODED_32_SZ ];
    fd_base58_encode_32( address, NULL, address_cstr );
    FD_LOG_ERR(( "fd_sysvar_cache_data_modify_prepare: %s is not a supported sysvar",
                 address_cstr ));
  }
  fd_sysvar_cache_desc_t * desc = &cache->desc_tbl[ entry->desc_idx ];
  /* FIXME clear the valid bit */
  *opt_sz     = desc->data_sz;
  *opt_sz_max = desc->data_sz_max;
}

void
fd_sysvar_cache_data_modify_commit(
    fd_exec_slot_ctx_t * slot_ctx,
    void const *         address, /* 32 bytes */
    ulong                sz
) {
  /* FIXME write lock */
}

fd_sol_sysvar_clock_t *
fd_sysvar_clock_read( fd_sysvar_cache_t const * cache,
                      fd_sol_sysvar_clock_t *   clock ) {
  fd_sysvar_cache_desc_t const * desc = &cache->desc.clock;
  if( FD_UNLIKELY( !desc->obj_off ) ) return NULL;
  return memcpy( clock, (uchar *)cache+desc->obj_off, sizeof(fd_sol_sysvar_clock_t) );
}

void
fd_sysvar_clock_write(
    fd_exec_slot_ctx_t *          slot_ctx,
    fd_sol_sysvar_clock_t const * clock
) {
  fd_sysvar_cache_t *      cache = slot_ctx->sysvar_cache;
  fd_sysvar_cache_desc_t * desc  = &cache->desc.clock;
  fd_sysvar_cache_desc_write_lock( desc );

  uchar * buf     = (uchar *)fd_sysvar_cache_data_laddr( cache, desc );
  ulong   buf_max = FD_SYSVAR_CLOCK_BINCODE_SZ;

  fd_bincode_encode_ctx_t encode_ctx = {
    .data    = buf,
    .dataend = buf+buf_max,
  };
  fd_sol_sysvar_clock_encode( clock, &encode_ctx );

  fd_sysvar_cache_desc_write_unlock( desc );
}

fd_slot_hash_t *
fd_sysvar_slot_hashes_join(
    fd_sysvar_cache_t * sysvar_cache
);

fd_slot_hash_t const *
fd_sysvar_slot_hashes_join_const(
    fd_sysvar_cache_t const * sysvar_cache
);
