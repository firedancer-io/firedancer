#include "../../disco/topo/fd_topo.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../flamenco/runtime/fd_txn_account.h"
#include "../../flamenco/accdb/fd_accdb_admin.h"
#include "../../flamenco/accdb/fd_accdb_user.h"
#include "../../flamenco/runtime/fd_hashes.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "generated/fd_genesi_tile_seccomp.h"
struct fd_genesi_tile {
  int fd;

  fd_accdb_admin_t accdb_admin[1];
  fd_accdb_user_t  accdb[1];

  ushort shred_version;
  uchar  genesis_hash[ 32UL ];

  fd_lthash_value_t lthash[1];

  int bootstrap;
  int shutdown;

  ulong genesis_sz;
  uchar genesis[ 10UL*1024UL*1024UL ] __attribute__((aligned(alignof(fd_genesis_solana_global_t)))); /* 10 MiB buffer for decoded genesis */
  uchar buffer[ 10UL*1024UL*1024UL ]; /* 10 MiB buffer for reading genesis file */

  fd_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;
};

typedef struct fd_genesi_tile fd_genesi_tile_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return alignof( fd_genesi_tile_t );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_genesi_tile_t ), sizeof( fd_genesi_tile_t ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline int
should_shutdown( fd_genesi_tile_t * ctx ) {
  return ctx->shutdown;
}

static void
initialize_accdb( fd_genesi_tile_t * ctx ) {
  /* Change 'last published' XID to 0 */
  fd_funk_txn_xid_t root_xid; fd_funk_txn_xid_set_root( &root_xid );
  fd_funk_txn_xid_t target_xid = { .ul = { 0UL, 0UL } };
  fd_accdb_attach_child( ctx->accdb_admin, &root_xid, &target_xid );
  fd_accdb_advance_root( ctx->accdb_admin, &target_xid );

  fd_genesis_solana_global_t * genesis = fd_type_pun( ctx->genesis );

  fd_pubkey_account_pair_global_t const * accounts = fd_genesis_solana_accounts_join( genesis );

  for( ulong i=0UL; i<genesis->accounts_len; i++ ) {
    fd_pubkey_account_pair_global_t const * account = &accounts[ i ];

    fd_funk_rec_prepare_t prepare;

    fd_txn_account_t rec[1];
    int err = fd_txn_account_init_from_funk_mutable( rec,
                                                     &account->key,
                                                     ctx->accdb->funk,
                                                     &target_xid,
                                                     1, /* do_create */
                                                     account->account.data_len,
                                                     &prepare );
    FD_TEST( !err );

    fd_txn_account_set_data( rec, fd_solana_account_data_join( &account->account ), account->account.data_len );
    fd_txn_account_set_lamports( rec, account->account.lamports );
    fd_txn_account_set_executable( rec, account->account.executable );
    fd_txn_account_set_owner( rec, &account->account.owner );
    fd_txn_account_mutable_fini( rec, ctx->accdb->funk, &prepare );

    fd_lthash_value_t new_hash[1];
    fd_hashes_account_lthash( rec->pubkey, fd_txn_account_get_meta( rec ), fd_txn_account_get_data( rec ), new_hash );
    fd_lthash_add( ctx->lthash, new_hash );
  }
}

static void
after_credit( fd_genesi_tile_t *  ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  (void)opt_poll_in;

  if( FD_UNLIKELY( ctx->shutdown ) ) return;

  *charge_busy = 1;

  initialize_accdb( ctx );

  uchar * dst = fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
  fd_memcpy( dst, &ctx->lthash->bytes, sizeof(fd_lthash_value_t) );
  fd_memcpy( dst+sizeof(fd_lthash_value_t), &ctx->genesis_hash, sizeof(fd_hash_t) );
  fd_memcpy( dst+sizeof(fd_lthash_value_t)+sizeof(fd_hash_t), ctx->genesis, ctx->genesis_sz );

  fd_stem_publish( stem, 0UL, ctx->shred_version, ctx->out_chunk, 0UL, 0UL, 0UL, 0UL );
  ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, ctx->genesis_sz+sizeof(fd_hash_t)+sizeof(fd_lthash_value_t), ctx->out_chunk0, ctx->out_wmark );

  ctx->shutdown = 1;
}

static void
process_local_genesis( fd_genesi_tile_t * ctx,
                       char const *       genesis_path,
                       ushort             expected_shred_version ) {
  struct stat st;
  int err = fstat( ctx->fd, &st );
  if( FD_UNLIKELY( -1==err ) ) FD_LOG_ERR(( "stat() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  ulong size = (ulong)st.st_size;

  if( FD_UNLIKELY( size>sizeof(ctx->buffer) ) ) FD_LOG_ERR(( "genesis file `%s` too large (%lu bytes, max %lu)", genesis_path, size, (ulong)sizeof(ctx->buffer) ));

  ulong bytes_read = 0UL;
  while( bytes_read<size ) {
    long result = read( ctx->fd, ctx->buffer+bytes_read, size-bytes_read );
    if( FD_UNLIKELY( -1==result ) ) FD_LOG_ERR(( "read() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( !result ) )  FD_LOG_ERR(( "read() returned 0 before reading full file" ));
    bytes_read += (ulong)result;
  }

  FD_TEST( bytes_read==size );

  if( FD_UNLIKELY( -1==close( ctx->fd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  fd_bincode_decode_ctx_t decode_ctx = {
    .data    = ctx->buffer,
    .dataend = ctx->buffer+size,
  };

  ctx->genesis_sz = 0UL;
  err = fd_genesis_solana_decode_footprint( &decode_ctx, &ctx->genesis_sz );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) FD_LOG_ERR(( "malformed genesis file at `%s`", genesis_path ));
  if( FD_UNLIKELY( ctx->genesis_sz>sizeof(ctx->genesis) ) ) FD_LOG_ERR(( "genesis file at `%s` decode footprint too large (%lu bytes, max %lu)", genesis_path, ctx->genesis_sz, sizeof(ctx->genesis) ));

  fd_genesis_solana_global_t * genesis = fd_genesis_solana_decode_global( ctx->genesis, &decode_ctx );
  FD_TEST( genesis );

  union {
    uchar  c[ 32 ];
    ushort s[ 16 ];
  } hash;
  fd_sha256_hash( ctx->buffer, size, hash.c );

  fd_memcpy( ctx->genesis_hash, hash.c, 32UL );

  ushort xor = 0;
  for( ulong i=0UL; i<16UL; i++ ) xor ^= hash.s[ i ];

  xor = fd_ushort_bswap( xor );
  xor = fd_ushort_if( xor<USHORT_MAX, (ushort)(xor + 1), USHORT_MAX );

  ctx->shred_version = xor;
  FD_TEST( ctx->shred_version );

  if( FD_UNLIKELY( ctx->bootstrap && expected_shred_version && expected_shred_version!=ctx->shred_version ) ) {
    FD_LOG_ERR(( "This node is bootstrapping the cluster as it has no gossip entrypoints provided, but "
                 "a [consensus.expected_shred_version] of %hu is provided which does not match the shred "
                 "version of %hu computed from the genesis.bin file at `%s`",
                 expected_shred_version, ctx->shred_version, genesis_path ));
  }
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_genesi_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_genesi_tile_t ), sizeof( fd_genesi_tile_t ) );

  ctx->fd = open( tile->genesi.genesis_path, O_RDONLY|O_CLOEXEC );
  if( FD_UNLIKELY( -1==ctx->fd ) ) {
    if( FD_LIKELY( errno==ENOENT  ) ) {
      if( FD_UNLIKELY( !tile->genesi.entrypoints_cnt ) ) {
        FD_LOG_ERR(( "This node is bootstrapping the cluster as it has no gossip entrypoints provided, but "
                     "the genesis.bin file at `%s` does not exist.  Please provide a valid genesis.bin "
                     "file by running genesis, or join an existing cluster.",
                     tile->genesi.genesis_path ));
      } else {
        if( FD_UNLIKELY( !tile->genesi.allow_download ) ) {
          FD_LOG_ERR(( "There is no genesis.bin file at `%s` and automatic downloading is disabled as "
                       "genesis_download is false in your configuration file.  Please either provide a valid "
                       "genesis.bin file locally, or allow donwloading from a gossip entrypoint.",
                       tile->genesi.genesis_path ));
        } else {
          FD_LOG_WARNING(( "UNIMPLEMENTED: automatic downloading of genesis.bin from gossip entrypoints is not yet implemented. "
                           "expected_genesis_hash and shred_version will not be verified." ));
        }
      }
    } else {
      FD_LOG_ERR(( "could not open genesis.bin file at `%s` (%i-%s)", tile->genesi.genesis_path, errno, fd_io_strerror( errno ) ));
    }
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_genesi_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_genesi_tile_t ), sizeof( fd_genesi_tile_t ) );

  FD_TEST( fd_accdb_admin_join( ctx->accdb_admin, fd_topo_obj_laddr( topo, tile->genesi.funk_obj_id ) ) );
  FD_TEST( fd_accdb_user_join ( ctx->accdb,       fd_topo_obj_laddr( topo, tile->genesi.funk_obj_id ) ) );

  fd_lthash_zero( ctx->lthash );

  ctx->shutdown = !!tile->genesi.entrypoints_cnt;
  ctx->bootstrap = !!tile->genesi.entrypoints_cnt;
  if( FD_LIKELY( -1!=ctx->fd ) ) process_local_genesis( ctx, tile->genesi.genesis_path, tile->genesi.expected_shred_version );

  ctx->out_mem    = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ 0 ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->out_mem, topo->links[ tile->out_link_id[ 0 ] ].dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->out_mem, topo->links[ tile->out_link_id[ 0 ] ].dcache, topo->links[ tile->out_link_id[ 0 ] ].mtu );
  ctx->out_chunk  = ctx->out_chunk0;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {

  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_genesi_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_genesi_tile_t ), sizeof( fd_genesi_tile_t ) );

  populate_sock_filter_policy_fd_genesi_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)ctx->fd );
  return sock_filter_policy_fd_genesi_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_genesi_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_genesi_tile_t ), sizeof( fd_genesi_tile_t ) );

  if( FD_UNLIKELY( out_fds_cnt<3UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  if( FD_LIKELY( ctx->fd!=-1 ) ) out_fds[ out_cnt++ ] = ctx->fd;
  return out_cnt;
}

#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_genesi_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_genesi_tile_t)

#define STEM_CALLBACK_AFTER_CREDIT    after_credit
#define STEM_CALLBACK_SHOULD_SHUTDOWN should_shutdown

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_genesi = {
  .name                     = "genesi",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
