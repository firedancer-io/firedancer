/* test_snapzp_tile.c tests snapzp tile disk-account packing. */

#define _GNU_SOURCE

#define fd_tile_snapzp fd_tile_snapzp_test
#include "fd_snapzp_tile.c"
#undef fd_tile_snapzp

#include "../../util/fd_util.h"
#include "../../util/tmpl/fd_unit_test.c"

#define POOL_CNT 4UL

static uchar raw[ RAW_BUF_SZ ] __attribute__((aligned(4096)));
static fd_wksp_t * wksp;

static void
fill_key( fd_pubkey_t * key,
          uchar         seed ) {
  for( ulong i=0UL; i<sizeof(fd_pubkey_t); i++ ) key->uc[ i ] = (uchar)( seed + i );
}

static void
init_ctx( fd_snapzp_t *       ctx,
          fd_accdb_accmeta_t * pool,
          fd_wksp_t *         wksp ) {
  memset( ctx, 0, sizeof(fd_snapzp_t) );
  memset( raw, 0xa5, sizeof(snap_acc_hdr_t)+64UL );
  ctx->fd                   = 1;
  ctx->snapmk_zp_mem        = wksp;
  ctx->snapmk_zp_chunk0     = 0UL;
  ctx->snapmk_zp_wmark      = ULONG_MAX;
  ctx->snaprd_mem           = wksp;
  ctx->raw                  = raw;
  ctx->raw_buf.src          = raw;
  ctx->raw_buf.size         = 0UL;
  ctx->acc_cache->acc_pool  = pool;
  ctx->acc_cache->max_accounts = POOL_CNT;
}

static void
prepare_account( fd_backup_disk_msg_t * frag,
                 fd_accdb_accmeta_t * pool,
                 uint                acc_idx,
                 fd_pubkey_t const * pubkey,
                 fd_pubkey_t const * owner,
                 uint                size,
                 ulong               lamports,
                 uint                data_sz ) {
  frag->pubkey  = *pubkey;
  frag->owner   = *owner;
  frag->size    = size;
  frag->acc_idx = acc_idx;
  frag->snap_sz = (uint)( sizeof(snap_acc_hdr_t) + fd_ulong_align_up( (ulong)FD_ACCDB_SIZE_DATA( size ), 8UL ) );
  frag->data_sz = data_sz;

  memcpy( pool[ acc_idx ].key.pubkey, pubkey->uc, sizeof(fd_pubkey_t) );
  pool[ acc_idx ].executable_size = size;
  pool[ acc_idx ].lamports        = lamports;
}

/* zero writes a zero-data account header. */
FD_UNIT_TEST( zero ) {
  fd_wksp_reset( wksp, 1U );

  fd_snapzp_t ctx[1];
  fd_accdb_accmeta_t pool[ POOL_CNT ];
  memset( pool,  0, sizeof(pool)  );

  fd_pubkey_t pubkey, owner;
  fill_key( &pubkey, 0x11 );
  fill_key( &owner,  0x91 );

  init_ctx( ctx, pool, wksp );
  fd_backup_disk_msg_t * frag = fd_wksp_alloc_laddr( wksp, FD_CHUNK_ALIGN, sizeof(fd_backup_disk_msg_t), 1UL ); FD_TEST( frag );
  uint  size = FD_ACCDB_SIZE_PACK( 0U, 0 );
  prepare_account( frag, pool, 1U, &pubkey, &owner, size, 1234UL, 0U );
  ulong chunk = fd_laddr_to_chunk( wksp, frag );

  ulong ctl = fd_frag_meta_ctl( FD_BACKUP_ORIG_ACC_DISK, 1, 1, 0 );
  process_account_disk( ctx, 2UL, 0UL, chunk, sizeof(fd_backup_disk_msg_t), ctl, 0UL, 0UL );

  FD_TEST( ctx->raw_buf.size==sizeof(snap_acc_hdr_t) );
  FD_TEST( ctx->metrics.accounts_compressed==1UL );

  snap_acc_hdr_t const * hdr = (snap_acc_hdr_t const *)raw;
  FD_TEST( !memcmp( hdr->pubkey.uc, pubkey.uc, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( hdr->owner .uc, owner .uc, sizeof(fd_pubkey_t) ) );
  FD_TEST( hdr->lamports==1234UL );
  FD_TEST( hdr->data_len==0UL );
  FD_TEST( !hdr->executable );
}

/* split joins disk data fragments and pads account data. */
FD_UNIT_TEST( split ) {
  fd_wksp_reset( wksp, 1U );

  fd_snapzp_t ctx[1];
  fd_accdb_accmeta_t pool[ POOL_CNT ];
  memset( pool,  0, sizeof(pool)  );

  fd_pubkey_t pubkey, owner;
  fill_key( &pubkey, 0x22 );
  fill_key( &owner,  0xa2 );

  init_ctx( ctx, pool, wksp );
  fd_backup_disk_msg_t * frag = fd_wksp_alloc_laddr( wksp, FD_CHUNK_ALIGN, sizeof(fd_backup_disk_msg_t), 1UL ); FD_TEST( frag );
  uint  size = FD_ACCDB_SIZE_PACK( 13U, 1 );
  prepare_account( frag, pool, 2U, &pubkey, &owner, size, 5678UL, 5U );
  ulong chunk = fd_laddr_to_chunk( wksp, frag );

  uchar * frag0 = fd_wksp_alloc_laddr( wksp, 8UL, 16UL, 1UL ); FD_TEST( frag0 );
  uchar * frag1 = frag0 + 5UL;
  for( ulong i=0UL; i<5UL; i++ ) frag0[ i ] = (uchar)( 0x30U+i );
  for( ulong i=0UL; i<8UL; i++ ) frag1[ i ] = (uchar)( 0x35U+i );

  ulong ctl0 = fd_frag_meta_ctl( FD_BACKUP_ORIG_ACC_DISK, 1, 0, 0 );
  process_account_disk( ctx, 3UL, fd_wksp_gaddr_fast( wksp, frag0 ), chunk, sizeof(fd_backup_disk_msg_t), ctl0, 0UL, 5UL );

  FD_TEST( ctx->raw_buf.size==sizeof(snap_acc_hdr_t)+5UL );
  FD_TEST( ctx->disk.active );
  FD_TEST( ctx->disk.data_rem==8UL );
  FD_TEST( !ctx->metrics.accounts_compressed );

  ulong ctl1 = fd_frag_meta_ctl( FD_BACKUP_ORIG_ACC_DISK, 0, 1, 0 );
  process_account_disk( ctx, 4UL, fd_wksp_gaddr_fast( wksp, frag1 ), 0UL, 0UL, ctl1, 0UL, 8UL );

  FD_TEST( ctx->raw_buf.size==sizeof(snap_acc_hdr_t)+16UL );
  FD_TEST( !ctx->disk.active );
  FD_TEST( ctx->metrics.accounts_compressed==1UL );

  snap_acc_hdr_t const * hdr = (snap_acc_hdr_t const *)raw;
  FD_TEST( !memcmp( hdr->pubkey.uc, pubkey.uc, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( hdr->owner .uc, owner .uc, sizeof(fd_pubkey_t) ) );
  FD_TEST( hdr->lamports==5678UL );
  FD_TEST( hdr->data_len==13UL );
  FD_TEST( hdr->executable );

  uchar const * data = raw + sizeof(snap_acc_hdr_t);
  for( ulong i=0UL; i<13UL; i++ ) FD_TEST( data[ i ]==(uchar)( 0x30U+i ) );
  for( ulong i=13UL; i<16UL; i++ ) FD_TEST( data[ i ]==0U );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  wksp = fd_wksp_new_anonymous( FD_SHMEM_NORMAL_PAGE_SZ, 64UL, fd_shmem_cpu_idx( 0UL ), "snapzp_disk", 0UL );
  FD_TEST( wksp );

  fd_unit_tests( argc, argv );

  fd_wksp_delete_anonymous( wksp );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
