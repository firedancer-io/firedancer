#include <linux/limits.h>
#define _GNU_SOURCE
#include "fd_genesi_tile.h"
#include "fd_genesis_client.h"
#include "../../disco/topo/fd_topo.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../flamenco/runtime/fd_genesis_parse.h"
#include "../../flamenco/accdb/fd_accdb_admin.h"
#include "../../flamenco/accdb/fd_accdb_impl_v1.h"
#include "../../flamenco/runtime/fd_hashes.h"
#include "../../util/archive/fd_tar.h"

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/fs.h>
#if FD_HAS_BZIP2
#include <bzlib.h>
#endif

#include "generated/fd_genesi_tile_seccomp.h"


#define GENESIS_MAX_SZ (10UL*1024UL*1024UL) /* 10 MiB */

static void *
bz2_malloc( void * opaque,
            int    items,
            int    size ) {
  fd_alloc_t * alloc = (fd_alloc_t *)opaque;

  void * result = fd_alloc_malloc( alloc, alignof(max_align_t), (ulong)(items*size) );
  if( FD_UNLIKELY( !result ) ) return NULL;
  return result;
}

static void
bz2_free( void * opaque,
          void * addr ) {
  fd_alloc_t * alloc = (fd_alloc_t *)opaque;

  if( FD_UNLIKELY( !addr ) ) return;
  fd_alloc_free( alloc, addr );
}

struct fd_genesi_tile {
  fd_accdb_admin_t accdb_admin[1];
  fd_accdb_user_t  accdb[1];

  uchar genesis_hash[ 32UL ];

  fd_genesis_client_t * client;

  fd_lthash_value_t lthash[1];

  int local_genesis;
  int bootstrap;
  int shutdown;

  int has_expected_genesis_hash;
  uchar expected_genesis_hash[ 32UL ];
  ushort expected_shred_version;

  uchar genesis[ GENESIS_MAX_SZ ] __attribute__((aligned(alignof(fd_genesis_t)))); /* 10 MiB buffer for decoded genesis */
  uchar buffer[ GENESIS_MAX_SZ ]; /* 10 MiB buffer for reading genesis file */

  char genesis_path[ PATH_MAX ];

  int in_fd;
  int out_fd;
  int out_dir_fd;

  fd_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;

  fd_alloc_t * bz2_alloc;
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
  l = FD_LAYOUT_APPEND( l, alignof( fd_genesi_tile_t ), sizeof( fd_genesi_tile_t )    );
  l = FD_LAYOUT_APPEND( l, fd_genesis_client_align(),   fd_genesis_client_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_alloc_align(),            fd_alloc_footprint()          );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_CONST static inline ulong
loose_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  /* Leftover space for bzip2 allocations */
  return 1UL<<26; /* 64 MiB */
}

static inline int
should_shutdown( fd_genesi_tile_t * ctx ) {
  return ctx->shutdown;
}

static void
initialize_accdb( fd_genesi_tile_t * ctx ) {
  /* Insert accounts at root */
  fd_funk_txn_xid_t root_xid; fd_funk_txn_xid_set_root( &root_xid );

  fd_genesis_t * genesis = fd_type_pun( ctx->genesis );

  fd_funk_t * funk = fd_accdb_user_v1_funk( ctx->accdb );
  for( ulong i=0UL; i<genesis->accounts_len; i++ ) {
    fd_genesis_account_t * account = fd_type_pun( (uchar *)genesis + genesis->accounts_off[ i ] );

    /* FIXME: use accdb API */
    fd_funk_rec_prepare_t prepare[1];
    fd_funk_rec_key_t key[1]; memcpy( key->uc, account->pubkey, sizeof(fd_pubkey_t) );
    fd_funk_rec_t * rec = fd_funk_rec_prepare( funk, &root_xid, key, prepare, NULL );
    FD_TEST( rec );
    fd_account_meta_t * meta = fd_funk_val_truncate( rec, funk->alloc, funk->wksp, 16UL, sizeof(fd_account_meta_t)+account->meta.dlen, NULL );
    FD_TEST( meta );
    void * data = (void *)( meta+1 );
    fd_memcpy( meta->owner, account->meta.owner, sizeof(fd_pubkey_t) );
    meta->lamports = account->meta.lamports;
    meta->slot = 0UL;
    meta->executable = !!account->meta.executable;
    meta->dlen = (uint)account->meta.dlen;
    fd_memcpy( data, account->data, account->meta.dlen );
    fd_funk_rec_publish( funk, prepare );

    fd_lthash_value_t new_hash[1];
    fd_hashes_account_lthash( fd_type_pun( account->pubkey ), meta, data, new_hash );
    fd_lthash_add( ctx->lthash, new_hash );
  }
}

static inline void
verify_cluster_type( fd_genesis_t const * genesis,
                     uchar const *        genesis_hash,
                     char const *         genesis_path ) {

  uchar mainnet_hash[ 32 ];
  FD_TEST( fd_base58_decode_32( "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d", mainnet_hash ) );

  uchar testnet_hash[ 32 ];
  FD_TEST( fd_base58_decode_32( "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY", testnet_hash ) );

  uchar devnet_hash[ 32 ];
  FD_TEST( fd_base58_decode_32( "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG", devnet_hash ) );

  switch( genesis->cluster_type ) {
    case FD_GENESIS_TYPE_MAINNET: {
      if( FD_UNLIKELY( memcmp( genesis_hash, mainnet_hash, 32UL ) ) ) {
        FD_LOG_ERR(( "genesis file `%s` has cluster type MAINNET but unexpected genesis hash `%s`",
                     genesis_path, FD_BASE58_ENC_32_ALLOCA( genesis_hash ) ));
      }
      break;
    }
    case FD_GENESIS_TYPE_TESTNET: {
      if( FD_UNLIKELY( memcmp( genesis_hash, testnet_hash, 32UL ) ) ) {
        FD_LOG_ERR(( "genesis file `%s` has cluster type TESTNET but unexpected genesis hash `%s`",
                     genesis_path, FD_BASE58_ENC_32_ALLOCA( genesis_hash ) ));
      }
      break;
    }
    case FD_GENESIS_TYPE_DEVNET: {
      if( FD_UNLIKELY( memcmp( genesis_hash, devnet_hash, 32UL ) ) ) {
        FD_LOG_ERR(( "genesis file `%s` has cluster type DEVNET but unexpected genesis hash `%s`",
                     genesis_path, FD_BASE58_ENC_32_ALLOCA( genesis_hash ) ));
      }
      break;
    }
    default:
      break;
  }
}

static void
after_credit( fd_genesi_tile_t *  ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  (void)opt_poll_in;

  if( FD_UNLIKELY( ctx->shutdown ) ) return;

  if( FD_LIKELY( ctx->local_genesis ) ) {
    FD_TEST( -1!=ctx->in_fd );

    fd_genesis_t * genesis = fd_type_pun( ctx->genesis );

    uchar * dst = fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
    if( FD_UNLIKELY( ctx->bootstrap ) ) {
      fd_memcpy( dst, &ctx->lthash->bytes, sizeof(fd_lthash_value_t) );
      fd_memcpy( dst+sizeof(fd_lthash_value_t), &ctx->genesis_hash, sizeof(fd_hash_t) );
      fd_memcpy( dst+sizeof(fd_lthash_value_t)+sizeof(fd_hash_t), ctx->genesis, genesis->total_sz );

      fd_stem_publish( stem, 0UL, GENESI_SIG_BOOTSTRAP_COMPLETED, ctx->out_chunk, 0UL, 0UL, 0UL, 0UL );
      ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, genesis->total_sz+sizeof(fd_hash_t)+sizeof(fd_lthash_value_t), ctx->out_chunk0, ctx->out_wmark );
    } else {
      fd_memcpy( dst, ctx->genesis_hash, sizeof(fd_hash_t) );
      fd_stem_publish( stem, 0UL, GENESI_SIG_GENESIS_HASH, ctx->out_chunk, sizeof(fd_hash_t), 0UL, 0UL, 0UL );
      ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, sizeof(fd_hash_t), ctx->out_chunk0, ctx->out_wmark );
    }

    *charge_busy = 1;
    FD_LOG_NOTICE(( "loaded local genesis.bin from file `%s`", ctx->genesis_path ));

    ctx->shutdown = 1;
  } else {
    uchar * buffer;
    ulong buffer_sz;
    fd_ip4_port_t peer;
    int result = fd_genesis_client_poll( ctx->client, &peer, &buffer, &buffer_sz, charge_busy );
    if( FD_UNLIKELY( -1==result ) ) FD_LOG_ERR(( "failed to retrieve genesis.bin from any configured gossip entrypoints" ));
    if( FD_LIKELY( 1==result ) ) return;

    uchar * decompressed = ctx->buffer;
    ulong   actual_decompressed_sz = 0UL;
#   if FD_HAS_BZIP2
    bz_stream bzstrm = {0};
    bzstrm.bzalloc = bz2_malloc;
    bzstrm.bzfree  = bz2_free;
    bzstrm.opaque  = ctx->bz2_alloc;
    int bzerr = BZ2_bzDecompressInit( &bzstrm, 0, 0 );
    if( FD_UNLIKELY( BZ_OK!=bzerr ) ) FD_LOG_ERR(( "BZ2_bzDecompressInit() failed (%d)", bzerr ));

    ulong decompressed_sz = GENESIS_MAX_SZ;

    bzstrm.next_in   = (char *)buffer;
    bzstrm.avail_in  = (uint)buffer_sz;
    bzstrm.next_out  = (char *)decompressed;
    bzstrm.avail_out = (uint)decompressed_sz;
    bzerr = BZ2_bzDecompress( &bzstrm );
    if( FD_UNLIKELY( BZ_STREAM_END!=bzerr ) ) FD_LOG_ERR(( "BZ2_bzDecompress() failed (%d)", bzerr ));

    actual_decompressed_sz = decompressed_sz - (ulong)bzstrm.avail_out;
#   else
    FD_LOG_ERR(( "This build does not include bzip2, which is required to boot from genesis.\n"
                 "To install bzip2, re-run ./deps.sh +dev, make distclean, and make -j" ));
#   endif

    FD_TEST( actual_decompressed_sz>=512UL );

    fd_tar_meta_t const * meta = (fd_tar_meta_t const *)decompressed;
    FD_TEST( !strcmp( meta->name, "genesis.bin" ) );
    FD_TEST( actual_decompressed_sz>=512UL+fd_tar_meta_get_size( meta ) );

    uchar hash[ 32UL ];
    fd_sha256_hash( decompressed+512UL, fd_tar_meta_get_size( meta ), hash );

    /* Can't verify expected_shred_version here because it needs to be
       mixed in with hard_forks from the snapshot.  Replay tile will
       combine them and do this verification. */

    if( FD_LIKELY( ctx->has_expected_genesis_hash && memcmp( hash, ctx->expected_genesis_hash, 32UL ) ) ) {
      FD_LOG_ERR(( "An expected genesis hash of `%s` has been set in your configuration file at [consensus.expected_genesis_hash] "
                   "but the genesis hash derived from the peer at `http://" FD_IP4_ADDR_FMT ":%hu` has unexpected hash `%s`",
                   FD_BASE58_ENC_32_ALLOCA( ctx->expected_genesis_hash ), FD_IP4_ADDR_FMT_ARGS( peer.addr ), fd_ushort_bswap( peer.port ), FD_BASE58_ENC_32_ALLOCA( hash ) ));
    }

    FD_TEST( !ctx->bootstrap );
    ulong size = 512UL+fd_tar_meta_get_size( meta );

    fd_genesis_t * genesis = fd_genesis_parse( ctx->buffer, size, ctx->genesis );

    verify_cluster_type( genesis, hash, ctx->genesis_path );

    uchar * dst = fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
    fd_memcpy( dst, hash, sizeof(fd_hash_t) );
    FD_LOG_WARNING(( "Genesis hash from peer: %s", FD_BASE58_ENC_32_ALLOCA( dst ) ));
    fd_stem_publish( stem, 0UL, GENESI_SIG_GENESIS_HASH, ctx->out_chunk, 32UL, 0UL, 0UL, 0UL );
    ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, sizeof(fd_hash_t), ctx->out_chunk0, ctx->out_wmark );

    ulong bytes_written = 0UL;
    while( bytes_written<fd_tar_meta_get_size( meta ) ) {
      long result = write( ctx->out_fd, decompressed+512UL+bytes_written, fd_tar_meta_get_size( meta )-bytes_written );
      if( FD_UNLIKELY( -1==result ) ) FD_LOG_ERR(( "write() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      bytes_written += (ulong)result;
    }

    char basename[ PATH_MAX ];
    const char * last_slash = strrchr( ctx->genesis_path, '/' );
    if( FD_LIKELY( last_slash ) ) FD_TEST( fd_cstr_printf_check( basename, PATH_MAX, NULL, "%s", last_slash+1UL ) );
    else                          FD_TEST( fd_cstr_printf_check( basename, PATH_MAX, NULL, "%s", ctx->genesis_path ) );

    char basename_partial[ PATH_MAX ];
    FD_TEST( fd_cstr_printf_check( basename_partial, PATH_MAX, NULL, "%s.partial", basename ) );

    int err = renameat2( ctx->out_dir_fd, basename_partial, ctx->out_dir_fd, basename, RENAME_NOREPLACE );
    if( FD_UNLIKELY( -1==err ) ) FD_LOG_ERR(( "renameat2() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    FD_LOG_NOTICE(( "retrieved genesis `%s` from peer at http://" FD_IP4_ADDR_FMT ":%hu/genesis.tar.bz2",
                    ctx->genesis_path, FD_IP4_ADDR_FMT_ARGS( peer.addr ), peer.port ));

    ctx->shutdown = 1;
  }
}

static void
process_local_genesis( fd_genesi_tile_t * ctx,
                       char const *       genesis_path ) {
  struct stat st;
  int err = fstat( ctx->in_fd, &st );
  if( FD_UNLIKELY( -1==err ) ) FD_LOG_ERR(( "stat() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  ulong size = (ulong)st.st_size;

  if( FD_UNLIKELY( size>sizeof(ctx->buffer) ) ) FD_LOG_ERR(( "genesis file `%s` too large (%lu bytes, max %lu)", genesis_path, size, (ulong)sizeof(ctx->buffer) ));

  ulong bytes_read = 0UL;
  while( bytes_read<size ) {
    long result = read( ctx->in_fd, ctx->buffer+bytes_read, size-bytes_read );
    if( FD_UNLIKELY( -1==result ) ) FD_LOG_ERR(( "read() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( !result ) )  FD_LOG_ERR(( "read() returned 0 before reading full file" ));
    bytes_read += (ulong)result;
  }

  FD_TEST( bytes_read==size );

  if( FD_UNLIKELY( -1==close( ctx->in_fd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  fd_genesis_t * genesis = fd_genesis_parse( ctx->buffer, size, ctx->genesis );

  union {
    uchar  c[ 32 ];
    ushort s[ 16 ];
  } hash;
  fd_sha256_hash( ctx->buffer, size, hash.c );

  verify_cluster_type( genesis, hash.c, genesis_path );

  fd_memcpy( ctx->genesis_hash, hash.c, 32UL );

  if( FD_UNLIKELY( ctx->bootstrap && ctx->expected_shred_version ) ) {
    ushort xor = 0;
    for( ulong i=0UL; i<16UL; i++ ) xor ^= hash.s[ i ];

    xor = fd_ushort_bswap( xor );
    xor = fd_ushort_if( xor<USHORT_MAX, (ushort)(xor + 1), USHORT_MAX );

    FD_TEST( xor );

    if( FD_UNLIKELY( xor!=ctx->expected_shred_version ) ) {
      FD_LOG_ERR(( "This node is bootstrapping the cluster as it has no gossip entrypoints provided, but "
                   "a [consensus.expected_shred_version] of %hu is provided which does not match the shred "
                   "version of %hu computed from the genesis.bin file at `%s`",
                   ctx->expected_shred_version, xor, genesis_path ));
    }
  }

  if( FD_LIKELY( ctx->has_expected_genesis_hash && memcmp( ctx->genesis_hash, ctx->expected_genesis_hash, 32UL ) ) ) {
    FD_LOG_ERR(( "An expected genesis hash of `%s` has been set in your configuration file at [consensus.expected_genesis_hash] "
                 "but the genesis hash derived from the genesis file at `%s` has unexpected hash (expected `%s`)", FD_BASE58_ENC_32_ALLOCA( ctx->expected_genesis_hash ), genesis_path, FD_BASE58_ENC_32_ALLOCA( ctx->genesis_hash ) ));
  }
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_genesi_tile_t * ctx        = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_genesi_tile_t ), sizeof( fd_genesi_tile_t )    );
  fd_genesis_client_t * _client = FD_SCRATCH_ALLOC_APPEND( l, fd_genesis_client_align(),   fd_genesis_client_footprint() );

  ctx->local_genesis = 1;
  ctx->in_fd = open( tile->genesi.genesis_path, O_RDONLY|O_CLOEXEC );
  if( FD_UNLIKELY( -1==ctx->in_fd ) ) {
    if( FD_LIKELY( errno==ENOENT  ) ) {
      FD_LOG_INFO(( "no local genesis.bin file found at `%s`", tile->genesi.genesis_path ));

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
          char basename[ PATH_MAX ];
          strncpy( basename, tile->genesi.genesis_path, PATH_MAX );
          char * last_slash = strrchr( basename, '/' );
          if( FD_LIKELY( last_slash ) ) *last_slash = '\0';

          ctx->out_dir_fd = open( basename, O_RDONLY|O_CLOEXEC|O_DIRECTORY );
          if( FD_UNLIKELY( -1==ctx->out_dir_fd ) ) FD_LOG_ERR(( "open() failed for genesis dir `%s` (%i-%s)", basename, errno, fd_io_strerror( errno ) ));

          /* Switch to non-root uid/gid for file creation.  Permissions checks
            are still done as root. */
          gid_t gid = getgid();
          uid_t uid = getuid();
          if( FD_LIKELY( !gid && -1==syscall( __NR_setresgid, -1, tile->genesi.target_gid, -1 ) ) ) FD_LOG_ERR(( "setresgid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
          if( FD_LIKELY( !uid && -1==syscall( __NR_setresuid, -1, tile->genesi.target_uid, -1 ) ) ) FD_LOG_ERR(( "setresuid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

          char partialname[ PATH_MAX ];
          FD_TEST( fd_cstr_printf_check( partialname, PATH_MAX, NULL, "%s.partial", tile->genesi.genesis_path ) );
          ctx->out_fd = openat( ctx->out_dir_fd, "genesis.bin.partial", O_CREAT|O_WRONLY|O_CLOEXEC|O_TRUNC, S_IRUSR|S_IWUSR );
          if( FD_UNLIKELY( -1==ctx->out_fd ) ) FD_LOG_ERR(( "openat() failed for genesis file `%s` (%i-%s)", partialname, errno, fd_io_strerror( errno ) ));

          if( FD_UNLIKELY( -1==syscall( __NR_setresuid, -1, uid, -1 ) ) ) FD_LOG_ERR(( "setresuid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
          if( FD_UNLIKELY( -1==syscall( __NR_setresgid, -1, gid, -1 ) ) ) FD_LOG_ERR(( "setresgid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

          ctx->local_genesis = 0;
          ctx->client = fd_genesis_client_join( fd_genesis_client_new( _client ) );
          FD_TEST( ctx->client );
          fd_genesis_client_init( ctx->client, tile->genesi.entrypoints, tile->genesi.entrypoints_cnt );
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
  fd_genesi_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_genesi_tile_t ), sizeof( fd_genesi_tile_t )    );
                           FD_SCRATCH_ALLOC_APPEND( l, fd_genesis_client_align(),   fd_genesis_client_footprint() );
  void * _alloc          = FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(),            fd_alloc_footprint()          );

  FD_TEST( fd_accdb_admin_join  ( ctx->accdb_admin, fd_topo_obj_laddr( topo, tile->genesi.funk_obj_id ) ) );
  FD_TEST( fd_accdb_user_v1_init( ctx->accdb,       fd_topo_obj_laddr( topo, tile->genesi.funk_obj_id ) ) );

  fd_lthash_zero( ctx->lthash );

  ctx->shutdown = 0;
  ctx->bootstrap = !tile->genesi.entrypoints_cnt;
  ctx->expected_shred_version = tile->genesi.expected_shred_version;
  ctx->has_expected_genesis_hash = tile->genesi.has_expected_genesis_hash;
  fd_memcpy( ctx->expected_genesis_hash, tile->genesi.expected_genesis_hash, 32UL );
  if( FD_LIKELY( -1!=ctx->in_fd ) ) {
    process_local_genesis( ctx, tile->genesi.genesis_path );
    if( FD_UNLIKELY( ctx->bootstrap ) ) initialize_accdb( ctx );
  }

  FD_TEST( fd_cstr_printf_check( ctx->genesis_path, PATH_MAX, NULL, "%s", tile->genesi.genesis_path ) );

  ctx->out_mem    = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ 0 ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->out_mem, topo->links[ tile->out_link_id[ 0 ] ].dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->out_mem, topo->links[ tile->out_link_id[ 0 ] ].dcache, topo->links[ tile->out_link_id[ 0 ] ].mtu );
  ctx->out_chunk  = ctx->out_chunk0;

  ctx->bz2_alloc = fd_alloc_join( fd_alloc_new( _alloc, 1UL ), 1UL );
  FD_TEST( ctx->bz2_alloc );

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static ulong
rlimit_file_cnt( fd_topo_t const *      topo FD_PARAM_UNUSED,
                 fd_topo_tile_t const * tile ) {
  return 1UL +                         /* stderr */
         1UL +                         /* logfile */
         1UL +                         /* genesis file */
         1UL +                         /* genesis dir */
         tile->genesi.entrypoints_cnt; /* for the client */
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {

  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_genesi_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_genesi_tile_t ), sizeof( fd_genesi_tile_t ) );

  uint in_fd, out_fd, out_dir_fd;
  if( FD_LIKELY( -1!=ctx->in_fd ) ) {
    in_fd      = (uint)ctx->in_fd;
    out_fd     = (uint)-1;
    out_dir_fd = (uint)-1;
  } else {
    in_fd      = (uint)-1;
    out_fd     = (uint)ctx->out_fd;
    out_dir_fd = (uint)ctx->out_dir_fd;
  }

  populate_sock_filter_policy_fd_genesi_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), in_fd, out_fd, out_dir_fd );
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

  if( FD_UNLIKELY( out_fds_cnt<tile->genesi.entrypoints_cnt+5UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */

  if( FD_UNLIKELY( -1==ctx->in_fd ) ) {
    FD_TEST( -1!=ctx->out_dir_fd );
    FD_TEST( -1!=ctx->out_fd );
    out_fds[ out_cnt++ ] = ctx->out_dir_fd;
    out_fds[ out_cnt++ ] = ctx->out_fd;

    for( ulong i=0UL; i<tile->genesi.entrypoints_cnt; i++ ) {
      int fd = fd_genesis_client_get_pollfds( ctx->client )[ i ].fd;
      if( FD_LIKELY( -1!=fd ) ) out_fds[ out_cnt++ ] = fd;
    }
  } else {
    FD_TEST( -1!=ctx->in_fd );
    out_fds[ out_cnt++ ] = ctx->in_fd;
  }

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
  .rlimit_file_cnt_fn       = rlimit_file_cnt,
  .allow_connect            = 1,
  .allow_renameat           = 1,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .loose_footprint          = loose_footprint,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
