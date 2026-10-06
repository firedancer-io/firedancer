#define _GNU_SOURCE

#include "../../util/archive/fd_tar.h"

#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include "fd_snapin_tile.c"

#define TEST_APPENDVEC_CNT   (9UL)
#define TEST_ACCOUNT_CNT     (FD_SSPARSE_ACC_BATCH_MAX+TEST_APPENDVEC_CNT-1UL)
#define TEST_WORKER_MAX      (9UL)
#define TEST_MAX_ACCOUNTS    (65536UL)
#define TEST_PARTITION_SZ    (32UL<<20)
#define TEST_CACHE_FOOTPRINT (32UL<<20)

typedef struct {
  uchar pubkey[ 32UL ];
  uchar owner [ 32UL ];
  ulong lamports;
  int   executable;
  ulong data_len;
  uchar data[ 64UL ];
} test_account_t;

typedef struct {
  ulong                    worker_cnt;
  void *                   shmem_mem;
  fd_accdb_shmem_t *       shmem;
  void *                   snapin_shmem_mem;
  fd_snapin_shmem_t *      snapin_shmem;
  void *                   stake_mem;
  fd_snapin_tile_t *       worker;
  void *                   join_mem [ TEST_WORKER_MAX ];
  fd_accdb_fork_id_t       root;
} test_env_t;

static ulong
tar_entry( uchar *       tar,
           ulong         tar_max,
           ulong         off,
           char const *  name,
           uchar const * data,
           ulong         data_sz ) {
  ulong padded = fd_ulong_align_up( data_sz, 512UL );
  FD_TEST( off+512UL+padded<=tar_max );
  FD_TEST( fd_tar_meta_init_file_default( (fd_tar_meta_t *)(tar+off),
                                          name, data_sz,
                                          1700000000L*1000000000L ) );
  off += 512UL;
  if( data_sz ) fd_memcpy( tar+off, data, data_sz );
  fd_memset( tar+off+data_sz, 0, padded-data_sz );
  return off+padded;
}

static ulong
appendvec_account( uchar *                dst,
                   test_account_t const * account ) {
  ulong sz = fd_ulong_align_up( 136UL+account->data_len, 8UL );
  fd_memset( dst, 0, sz );
  FD_STORE( ulong, dst,      account->lamports );
  FD_STORE( ulong, dst+8UL,  account->data_len );
  fd_memcpy( dst+16UL, account->pubkey, 32UL );
  FD_STORE( ulong, dst+48UL, account->lamports );
  fd_memcpy( dst+64UL, account->owner, 32UL );
  dst[ 96UL ] = (uchar)account->executable;
  fd_memcpy( dst+136UL, account->data, account->data_len );
  return sz;
}

static ulong
build_snapshot( uchar *          tar,
                ulong            tar_max,
                test_account_t const * accounts ) {
  uchar batch_body[ FD_SSPARSE_ACC_BATCH_MAX*136UL ];
  ulong batch_sz = 0UL;
  for( ulong i=0UL; i<FD_SSPARSE_ACC_BATCH_MAX; i++ ) {
    batch_sz += appendvec_account( batch_body+batch_sz, &accounts[ i ] );
  }

  uchar metadata = 0xA5U;

  ulong off = 0UL;
  off = tar_entry( tar, tar_max, off, "version",                (uchar const *)"1.2.0", 5UL );
  off = tar_entry( tar, tar_max, off, "snapshots/500/500",      &metadata,              1UL );
  off = tar_entry( tar, tar_max, off, "accounts/100.0",         batch_body,             batch_sz );
  for( ulong av=1UL; av<TEST_APPENDVEC_CNT; av++ ) {
    uchar body[ 256UL ];
    ulong body_sz = appendvec_account( body, &accounts[ FD_SSPARSE_ACC_BATCH_MAX+av-1UL ] );
    char name[ 64UL ];
    FD_TEST( fd_cstr_printf_check( name, sizeof(name), NULL, "accounts/%lu.%lu", 100UL+av, av ) );
    off = tar_entry( tar, tar_max, off, name, body, body_sz );
  }
  off = tar_entry( tar, tar_max, off, "snapshots/status_cache", &metadata,              1UL );
  FD_TEST( off+1024UL<=tar_max );
  fd_memset( tar+off, 0, 1024UL );
  return off+1024UL;
}

static void
test_env_init( test_env_t * env,
               ulong        worker_cnt ) {
  FD_TEST( worker_cnt==1UL || worker_cnt==9UL );
  fd_memset( env, 0, sizeof(*env) );
  env->worker_cnt = worker_cnt;

  int fd = memfd_create( "snapin_accdb", 0 );
  FD_TEST( fd>=0 );
  FD_TEST( dup2( fd, FD_ACCDB_FD_RW )==FD_ACCDB_FD_RW );
  if( fd!=FD_ACCDB_FD_RW ) FD_TEST( !close( fd ) );

  int stake_fd = memfd_create( "snapin_accdb_stake", 0 );
  FD_TEST( stake_fd>=0 );
  FD_TEST( dup2( stake_fd, FD_STAKE_DELEGATIONS_FD )==FD_STAKE_DELEGATIONS_FD );
  if( stake_fd!=FD_STAKE_DELEGATIONS_FD ) FD_TEST( !close( stake_fd ) );

  ulong shmem_fp = fd_accdb_shmem_footprint( TEST_MAX_ACCOUNTS, 16UL, 128UL, 32UL,
                                             TEST_CACHE_FOOTPRINT, 2UL,
                                             worker_cnt, 0UL );
  env->shmem_mem = aligned_alloc( fd_accdb_shmem_align(), shmem_fp );
  FD_TEST( env->shmem_mem );
  env->shmem = fd_accdb_shmem_join(
      fd_accdb_shmem_new( env->shmem_mem, TEST_MAX_ACCOUNTS, 16UL, 128UL, 32UL,
                          TEST_PARTITION_SZ, TEST_CACHE_FOOTPRINT, 2UL,
                          0, 42UL, worker_cnt, 0UL ) );
  FD_TEST( env->shmem );

  env->snapin_shmem_mem = aligned_alloc( alignof(fd_snapin_shmem_t), sizeof(fd_snapin_shmem_t) );
  FD_TEST( env->snapin_shmem_mem );
  env->snapin_shmem = (fd_snapin_shmem_t *)env->snapin_shmem_mem;
  fd_memset( env->snapin_shmem, 0, sizeof(fd_snapin_shmem_t) );
  env->snapin_shmem->stake_fork = USHORT_MAX;

  /* Replaced versions tombstone snooped stake delegations. */
  ulong stake_fp = fd_ulong_align_up( fd_stake_delegations_footprint( 16UL, 4UL ), fd_stake_delegations_align() );
  env->stake_mem = aligned_alloc( fd_stake_delegations_align(), stake_fp );
  FD_TEST( env->stake_mem );
  FD_TEST( fd_stake_delegations_new( env->stake_mem, FD_STAKE_DELEGATIONS_FD, 1UL, 16UL, 16UL, 4UL ) );
  fd_stake_delegations_t * stake_delegations = fd_stake_delegations_join( env->stake_mem, FD_STAKE_DELEGATIONS_FD );
  FD_TEST( stake_delegations );

  ulong worker_fp = fd_ulong_align_up( worker_cnt*sizeof(fd_snapin_tile_t), alignof(fd_snapin_tile_t) );
  env->worker = aligned_alloc( alignof(fd_snapin_tile_t), worker_fp );
  FD_TEST( env->worker );
  fd_memset( env->worker, 0, worker_fp );

  for( ulong i=0UL; i<worker_cnt; i++ ) {
    ulong join_fp = fd_accdb_footprint( 16UL, 0 );
    env->join_mem[ i ] = aligned_alloc( fd_accdb_align(), join_fp );
    FD_TEST( env->join_mem[ i ] );

    fd_snapin_tile_t * ctx = &env->worker[ i ];
    ctx->accdb = fd_accdb_join( fd_accdb_new( env->join_mem[ i ], env->shmem,
                                               FD_ACCDB_FD_RW, 0UL, NULL, NULL, 0UL, 0 ) );
    FD_TEST( ctx->accdb );
    ctx->full              = 1;
    ctx->tile_idx          = i;
    ctx->incr_fork         = (ulong)USHORT_MAX;
    ctx->shmem             = env->snapin_shmem;
    ctx->stake_delegations = stake_delegations;

    /* Same reopen as privileged_init.  Direct IO on a memfd needs
       kernel support; fall back to the buffered fd where it is missing
       so the padding logic is still exercised. */
    char path[ 64 ];
    FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "/proc/self/fd/%d", FD_ACCDB_FD_RW ) );
    ctx->writer.accdb_direct_fd = open( path, O_WRONLY|O_DIRECT|O_CLOEXEC );
    if( FD_UNLIKELY( ctx->writer.accdb_direct_fd<0 ) ) {
      FD_LOG_NOTICE(( "O_DIRECT unsupported here (%i-%s), testing with buffered writes", errno, fd_io_strerror( errno ) ));
      ctx->writer.accdb_direct_fd = FD_ACCDB_FD_RW;
    }
  }

  env->root = fd_accdb_attach_child( env->worker[ 0 ].accdb, (fd_accdb_fork_id_t){ .val = USHORT_MAX } );
  fd_accdb_snapshot_load_begin( env->worker[ 0 ].accdb );
}

static void
dispatch_snapshot( test_env_t *  env,
                   uchar const * tar,
                   ulong         tar_sz ) {
  fd_ssparse_t parser[ 1 ];
  fd_ssparse_init( parser );
  fd_ssparse_batch_enable( parser, 1 );

  fd_snapin_tile_t * owner = NULL;
  ulong off                = 0UL;
  ulong appendvec_cnt      = 0UL;
  ulong batch_cnt          = 0UL;
  ulong batch_account_cnt  = 0UL;
  ulong header_cnt         = 0UL;
  ulong header_fragment_cnt = 0UL;
  ulong data_cnt           = 0UL;
  ulong zero_progress      = 0UL;
  int   fragment_account   = 0;
  int   awaiting_header    = 0;
  int   done               = 0;

  while( off<tar_sz ) {
    ulong feed_sz = fragment_account ? fd_ulong_min( 11UL, tar_sz-off ) : tar_sz-off;
    fd_ssparse_advance_result_t result[ 1 ];
    int res = fd_ssparse_advance( parser, tar+off, feed_sz, result );
    FD_TEST( res!=FD_SSPARSE_ADVANCE_ERROR );
    FD_TEST( result->bytes_consumed<=feed_sz );

    switch( res ) {
      case FD_SSPARSE_ADVANCE_APPENDVEC:
        FD_TEST( appendvec_cnt<TEST_APPENDVEC_CNT );
        owner = &env->worker[ appendvec_cnt%env->worker_cnt ];
        fd_ssparse_appendvec_parse( parser );
        appendvec_cnt++;
        fragment_account = appendvec_cnt==2UL;
        awaiting_header  = fragment_account;
        break;
      case FD_SSPARSE_ADVANCE_ACCOUNT_BATCH:
        FD_TEST( owner );
        FD_TEST( !process_account_batch( owner, result ) );
        batch_cnt++;
        batch_account_cnt += result->account_batch.batch_cnt;
        break;
      case FD_SSPARSE_ADVANCE_ACCOUNT_HEADER:
        FD_TEST( owner );
        FD_TEST( !process_account_header( owner, result ) );
        awaiting_header = 0;
        header_cnt++;
        break;
      case FD_SSPARSE_ADVANCE_ACCOUNT_DATA:
        FD_TEST( owner );
        FD_TEST( !process_account_data( owner, result ) );
        data_cnt++;
        break;
      case FD_SSPARSE_ADVANCE_DONE:
        done = 1;
        break;
      default:
        break;
    }
    if( awaiting_header && res==FD_SSPARSE_ADVANCE_AGAIN && result->bytes_consumed ) header_fragment_cnt++;

    off += result->bytes_consumed;
    if( result->bytes_consumed ) zero_progress = 0UL;
    else                         FD_TEST( ++zero_progress<1024UL );
    if( done ) break;
  }

  FD_TEST( done );
  FD_TEST( off==tar_sz );
  FD_TEST( appendvec_cnt==TEST_APPENDVEC_CNT );
  FD_TEST( batch_cnt==1UL );
  FD_TEST( batch_account_cnt==FD_SSPARSE_ACC_BATCH_MAX );
  FD_TEST( header_cnt==TEST_APPENDVEC_CNT-1UL );
  FD_TEST( header_fragment_cnt>1UL );
  FD_TEST( data_cnt>1UL );
}

static void
read_account( test_env_t *          env,
              test_account_t const * expected ) {
  uchar const * pubkeys[ 1 ] = { expected->pubkey };
  int           writable[ 1 ] = { 0 };
  fd_acc_t      account[ 1 ];
  fd_memset( account, 0, sizeof(account) );

  fd_accdb_acquire( env->worker[ 0 ].accdb, env->root, 1UL, pubkeys, writable, account );
  FD_TEST( fd_memeq( account->pubkey, expected->pubkey, 32UL ) );
  FD_TEST( fd_memeq( account->owner,  expected->owner,  32UL ) );
  FD_TEST( account->lamports==expected->lamports );
  FD_TEST( account->executable==expected->executable );
  FD_TEST( account->data_len==expected->data_len );
  if( expected->data_len ) FD_TEST( fd_memeq( account->data, expected->data, expected->data_len ) );
  fd_accdb_release( env->worker[ 0 ].accdb, 1UL, account );
}

static void
test_env_free( test_env_t * env ) {
  for( ulong i=0UL; i<env->worker_cnt; i++ ) {
    if( env->worker[ i ].writer.accdb_direct_fd!=FD_ACCDB_FD_RW ) FD_TEST( !close( env->worker[ i ].writer.accdb_direct_fd ) );
    free( env->join_mem[ i ] );
  }
  free( env->worker );
  free( env->stake_mem );
  free( env->snapin_shmem_mem );
  free( env->shmem_mem );
  FD_TEST( !close( FD_ACCDB_FD_RW ) );
  FD_TEST( !close( FD_STAKE_DELEGATIONS_FD ) );
}

static void
test_env_fini( test_env_t *          env,
               test_account_t const * accounts ) {
  /* Every account is still buffered: exactly one flush per worker,
     each padded to FD_SNAPIN_DIRECT_ALIGN. */
  ulong buffered_bytes = 0UL;
  ulong expected_bytes = 0UL;
  ulong bytes_written  = 0UL;
  for( ulong i=0UL; i<env->worker_cnt; i++ ) {
    fd_snapin_tile_t * ctx = &env->worker[ i ];
    buffered_bytes += ctx->writer.buf_used;
    if( ctx->writer.buf_used ) expected_bytes += fd_ulong_align_up( ctx->writer.buf_used+sizeof(fd_accdb_disk_meta_t), FD_SNAPIN_DIRECT_ALIGN );
    FD_TEST( !writer_flush( ctx ) );
    bytes_written += ctx->metrics.disk_bytes_written;
    fd_accdb_flush_metrics( ctx->accdb );
  }

  FD_TEST( buffered_bytes==TEST_ACCOUNT_CNT*sizeof(fd_accdb_disk_meta_t)+accounts[ FD_SSPARSE_ACC_BATCH_MAX ].data_len );
  FD_TEST( bytes_written==expected_bytes );

  fd_accdb_snapshot_load_end( env->worker[ 0 ].accdb );
  for( ulong i=0UL; i<TEST_ACCOUNT_CNT; i++ ) read_account( env, &accounts[ i ] );

  test_env_free( env );
}

static void
fill_accounts( test_account_t * accounts ) {
  fd_memset( accounts, 0, TEST_ACCOUNT_CNT*sizeof(test_account_t) );
  for( ulong i=0UL; i<TEST_ACCOUNT_CNT; i++ ) {
    accounts[ i ].pubkey[ 0 ] = (uchar)(i+1UL);
    accounts[ i ].pubkey[ 31 ] = 0xC3U;
    accounts[ i ].owner[ 0 ] = (uchar)(0x80UL+i);
    accounts[ i ].owner[ 31 ] = 0x5AU;
    accounts[ i ].lamports   = 1000UL+i;
    accounts[ i ].executable = (int)(i&1UL);
  }
  accounts[ FD_SSPARSE_ACC_BATCH_MAX ].data_len = 37UL;
  accounts[ FD_SSPARSE_ACC_BATCH_MAX ].executable = 1;
  for( ulong i=0UL; i<accounts[ FD_SSPARSE_ACC_BATCH_MAX ].data_len; i++ ) {
    accounts[ FD_SSPARSE_ACC_BATCH_MAX ].data[ i ] = (uchar)(0x40UL+i);
  }
}

static void
test_snapin_accdb( ulong worker_cnt ) {
  test_account_t accounts[ TEST_ACCOUNT_CNT ];
  fill_accounts( accounts );

  uchar tar[ 16384UL ];
  ulong tar_sz = build_snapshot( tar, sizeof(tar), accounts );

  test_env_t env[ 1 ];
  test_env_init( env, worker_cnt );
  dispatch_snapshot( env, tar, tar_sz );
  test_env_fini( env, accounts );
}

/* Under instant boot the lead loads into hidden nodes while the
   validator runs from the boot stream, and the bank state the boot
   stream provides is not taken from the snapshot. */

static ulong
stake_delegation_cnt( fd_stake_delegations_t const * stake_delegations ) {
  ulong cnt = 0UL;
  fd_stake_delegations_iter_t iter_[ 1 ];
  for( fd_stake_delegations_iter_t * iter = fd_stake_delegations_iter_init( iter_, stake_delegations );
       !fd_stake_delegations_iter_done( iter );
       fd_stake_delegations_iter_next( iter ) ) {
    cnt++;
  }
  return cnt;
}

/* A funded, delegated stake account, the kind writer_flush snoops. */

static void
stage_stake_account( fd_snapin_tile_t * ctx,
                     uchar const *      pubkey ) {
  uchar data[ FD_STAKE_STATE_SZ ] = {0};
  FD_STORE( uint, data, FD_STAKE_STATE_STAKE );
  FD_TEST( fd_stake_state_view( data, sizeof(data) ) );
  FD_TEST( !writer_append_account( ctx, pubkey, fd_solana_stake_program_id.uc, data,
                                   100UL, 1000UL, sizeof(data), 0 ) );
}

static void
test_instant_boot_skips_bank_state( void ) {
  test_account_t accounts[ TEST_ACCOUNT_CNT ];
  fill_accounts( accounts );

  uchar tar[ 16384UL ];
  ulong tar_sz = build_snapshot( tar, sizeof(tar), accounts );
  uchar stake_pubkey[ 32UL ] = { 0xD1U };

  /* With the flag off the same fixture records the delegation, so the
     skip below cannot pass by the snoop being broken. */
  test_env_t ctrl[ 1 ];
  test_env_init( ctrl, 9UL );
  dispatch_snapshot( ctrl, tar, tar_sz );
  stage_stake_account( &ctrl->worker[ 0 ], stake_pubkey );
  for( ulong i=0UL; i<ctrl->worker_cnt; i++ ) FD_TEST( !writer_flush( &ctrl->worker[ i ] ) );
  FD_TEST( stake_delegation_cnt( ctrl->worker[ 0 ].stake_delegations )==1UL );
  fd_accdb_snapshot_load_end( ctrl->worker[ 0 ].accdb );
  test_env_free( ctrl );

  test_env_t env[ 1 ];
  test_env_init( env, 9UL );
  for( ulong i=0UL; i<env->worker_cnt; i++ ) env->worker[ i ].instant_boot = 1;

  /* What the lead's setup leaves behind: the load is hidden from
     every join but its own.  The rest of the setup needs the accdb
     tile to service fd_accdb_reset, which this harness does not
     run. */
  fd_accdb_snapshot_hide( env->worker[ 0 ].accdb, 1 );
  fd_accdb_show_hidden  ( env->worker[ 0 ].accdb, 1 );

  dispatch_snapshot( env, tar, tar_sz );
  stage_stake_account( &env->worker[ 0 ], stake_pubkey );

  /* Staged but not flushed: nothing is in the accounts database yet,
     so a failure here would still be retryable. */
  FD_TEST( !attempt_wrote_accounts( &env->worker[ 0 ] ) );
  for( ulong i=0UL; i<env->worker_cnt; i++ ) FD_TEST( !writer_flush( &env->worker[ i ] ) );
  FD_TEST( attempt_wrote_accounts( &env->worker[ 0 ] ) );

  /* The boot stream carries no stake accounts, so the snoop ran on
     every batch and the root holds the fixture's stake account. */
  FD_TEST( stake_delegation_cnt( env->worker[ 0 ].stake_delegations )==1UL );

  /* A plain join cannot see the loaded accounts until the lead
     unhides them. */
  fd_accdb_t * plain = env->worker[ 1 ].accdb;
  FD_TEST( !fd_accdb_exists  ( plain, env->root, accounts[ 0 ].pubkey ) );
  FD_TEST( !fd_accdb_lamports( plain, env->root, accounts[ 0 ].pubkey ) );
  FD_TEST( !fd_accdb_lamports( plain, env->root, stake_pubkey ) );

  /* The lead still reads back what it wrote, which is how it verifies
     sysvars and capitalization. */
  FD_TEST( fd_accdb_lamports( env->worker[ 0 ].accdb, env->root, accounts[ 0 ].pubkey )==accounts[ 0 ].lamports );

  fd_accdb_snapshot_hide( env->worker[ 0 ].accdb, 0 );
  for( ulong i=0UL; i<TEST_ACCOUNT_CNT; i++ ) {
    FD_TEST( fd_accdb_lamports( plain, env->root, accounts[ i ].pubkey )==accounts[ i ].lamports );
  }
  FD_TEST( fd_accdb_lamports( plain, env->root, stake_pubkey )==1000UL );

  fd_accdb_snapshot_load_end( env->worker[ 0 ].accdb );
  test_env_free( env );
}

/* The stream parser tile writes the boot stream into the boot fork
   through the normal path, so the running validator reads what it
   writes while the snapshot load stays hidden. */

#define TEST_STREAM_SLOT (900UL)

static void
test_stream_writes_boot_fork( void ) {
  test_env_t env[ 1 ];
  test_env_init( env, 9UL );

  /* What the lead's setup leaves behind: the fork an incremental
     writes, the fork the stream writes, and everything the loader
     writes hidden from the running validator. */
  fd_accdb_fork_id_t incr = fd_accdb_attach_child( env->worker[ 0 ].accdb, env->root );
  fd_accdb_fork_id_t boot = fd_accdb_attach_child( env->worker[ 0 ].accdb, incr );
  fd_accdb_snapshot_hide( env->worker[ 0 ].accdb, 1 );
  env->snapin_shmem->incr_fork_id = (ulong)incr.val;
  env->snapin_shmem->boot_fork_id = (ulong)boot.val;
  env->snapin_shmem->stream_slot  = TEST_STREAM_SLOT;
  env->snapin_shmem->setup_done   = 1UL;

  uchar   fseq_mem[ FD_FSEQ_FOOTPRINT ] __attribute__((aligned(FD_FSEQ_ALIGN)));
  ulong * slot_fseq = fd_fseq_join( fd_fseq_new( fseq_mem, ULONG_MAX ) );
  FD_TEST( slot_fseq );
  fd_fseq_update( slot_fseq, 0UL );

  fd_snapin_tile_t * ctx = &env->worker[ 0 ];
  ctx->stream    = 1;
  ctx->boot_fork = boot;
  ctx->slot_fseq = slot_fseq;

  /* The stream lists its manifest and status cache before its
     accounts, so the slot it starts from is known by the time an
     appendvec ends. */
  ctx->lead.flags.manifest_processed = 1;

  /* The stream carries each account as it was at the stream's manifest
     slot, so the first value of a key is the one to keep. */
  uchar pubkey[ 32UL ] = { 0xE1U };
  uchar dead  [ 32UL ] = { 0xE2U };
  uchar owner [ 32UL ] = { 0x33U };
  uchar data  [  4UL ] = { 1U, 2U, 3U, 4U };
  uchar other [  4UL ] = { 9U, 9U, 9U, 9U };
  FD_TEST( !writer_append_account( ctx, pubkey, owner, data, TEST_STREAM_SLOT+1UL, 500UL, sizeof(data), 1 ) );
  FD_TEST( !writer_flush( ctx ) );

  /* Two more copies of a key an earlier flush already wrote, and an
     account that did not exist at the stream's slot. */
  FD_TEST( !writer_append_account( ctx, pubkey, owner, other, TEST_STREAM_SLOT+2UL, 700UL, sizeof(other), 0 ) );
  FD_TEST( !writer_append_account( ctx, pubkey, owner, other, TEST_STREAM_SLOT+2UL, 800UL, sizeof(other), 0 ) );
  FD_TEST( !writer_append_account( ctx, dead,   owner, data,  TEST_STREAM_SLOT+2UL,   0UL, 0UL,           0 ) );

  /* An overflow file leaves the slot incomplete, so the marker stays
     where it was. */
  fd_ssparse_advance_result_t result[ 1 ];
  fd_memset( result, 0, sizeof(result) );
  result->appendvec.slot = TEST_STREAM_SLOT+2UL;
  result->appendvec.id   = 1UL;
  FD_TEST( !stream_appendvec_done( ctx, NULL, result ) );
  FD_TEST( !fd_fseq_query( slot_fseq ) );

  result->appendvec.id = 0UL;
  FD_TEST( !stream_appendvec_done( ctx, NULL, result ) );
  FD_TEST( fd_fseq_query( slot_fseq )==TEST_STREAM_SLOT+2UL );

  /* A slot out of order does not take the marker back. */
  result->appendvec.slot = TEST_STREAM_SLOT+1UL;
  FD_TEST( !stream_appendvec_done( ctx, NULL, result ) );
  FD_TEST( fd_fseq_query( slot_fseq )==TEST_STREAM_SLOT+2UL );

  /* A stream that lists its accounts before its manifest and status
     cache: the slot it starts from is still unknown, so the appendvec
     that lets replay boot would be published as a finished slot and
     DONE would never follow.  That ends the process. */
  pid_t pid = fork();
  FD_TEST( pid>=0 );
  if( !pid ) {
    fd_log_level_logfile_set( 6 );
    fd_log_level_stderr_set( 6 );
    ctx->lead.flags.manifest_processed = 0;
    FD_VOLATILE( ctx->shmem->stream_slot ) = 0UL;
    stream_appendvec_done( ctx, NULL, result );
    _exit( 0 );
  }
  int status = 0;
  FD_TEST( waitpid( pid, &status, 0 )==pid );
  FD_TEST( WIFEXITED( status ) );
  FD_TEST( WEXITSTATUS( status )==1 );

  /* One version of the key on the boot fork, holding the first value,
     and nothing on the fork the snapshot loads into. */
  int   pd_write;
  ulong probe_len;
  ulong probe_lamports;
  FD_TEST( ctx->metrics.accounts_loaded==2UL );
  FD_TEST( ctx->metrics.accounts_ignored==2UL );
  FD_TEST( fd_accdb_probe_pd_this_fork( ctx->accdb, boot, pubkey, &pd_write, &probe_len, &probe_lamports ) );
  FD_TEST( probe_lamports==500UL );
  FD_TEST( probe_len==sizeof(data) );
  FD_TEST( !fd_accdb_probe_pd_this_fork( ctx->accdb, incr, pubkey, &pd_write, &probe_len, &probe_lamports ) );
  FD_TEST( !fd_accdb_lamports( ctx->accdb, incr, pubkey ) );

  uchar const * pubkeys [ 1 ] = { pubkey };
  int           writable[ 1 ] = { 0 };
  fd_acc_t      acc     [ 1 ];
  fd_memset( acc, 0, sizeof(acc) );
  fd_accdb_acquire( ctx->accdb, boot, 1UL, pubkeys, writable, acc );
  FD_TEST( acc->lamports==500UL );
  FD_TEST( acc->executable==1 );
  FD_TEST( acc->data_len==sizeof(data) );
  FD_TEST( fd_memeq( acc->owner, owner, 32UL ) );
  FD_TEST( fd_memeq( acc->data,  data,  sizeof(data) ) );
  fd_accdb_release( ctx->accdb, 1UL, acc );

  /* A key that appears twice inside one flush with no earlier version:
     the first copy is written and the second is dropped. */
  uchar twice  [ 32UL ] = { 0xE3U };
  ulong loaded          = ctx->metrics.accounts_loaded;
  ulong ignored         = ctx->metrics.accounts_ignored;
  FD_TEST( !writer_append_account( ctx, twice, owner, data,  TEST_STREAM_SLOT+3UL, 300UL, sizeof(data),  0 ) );
  FD_TEST( !writer_append_account( ctx, twice, owner, other, TEST_STREAM_SLOT+3UL, 400UL, sizeof(other), 0 ) );
  FD_TEST( !writer_flush( ctx ) );
  FD_TEST( ctx->metrics.accounts_loaded ==loaded +1UL );
  FD_TEST( ctx->metrics.accounts_ignored==ignored+1UL );
  FD_TEST( fd_accdb_lamports( ctx->accdb, boot, twice )==300UL );

  /* The closed account is a version on the boot fork that reads as an
     account that does not exist. */
  fd_accdb_fork_id_t child = fd_accdb_attach_child( ctx->accdb, boot );
  FD_TEST( fd_accdb_probe_pd_this_fork( ctx->accdb, boot, dead, &pd_write, &probe_len, &probe_lamports ) );
  FD_TEST( !probe_lamports );
  FD_TEST( !fd_accdb_lamports( ctx->accdb, child, dead ) );
  FD_TEST( !fd_accdb_exists  ( ctx->accdb, child, dead ) );
  FD_TEST( fd_accdb_lamports ( ctx->accdb, child, pubkey )==500UL );

  /* The stream writes no hidden nodes, so a plain join reads them
     while the snapshot load is still hidden. */
  FD_TEST( fd_accdb_lamports( env->worker[ 1 ].accdb, boot, pubkey )==500UL );

  fd_accdb_snapshot_hide( env->worker[ 0 ].accdb, 0 );
  fd_accdb_snapshot_load_end( env->worker[ 0 ].accdb );
  test_env_free( env );
}

/* Capitalization across a full and an incremental snapshot whose
   per-version lamport totals pass 2^64 (an incremental stores each vote
   account once per slot) while capitalization stays small. */

#define TEST_CAP_FULL_SLOT (100UL)
#define TEST_CAP_BIG       (2000000000000000000UL) /* 2e18, a whale vote account */
#define TEST_CAP_SMALL     (   1000000000000000UL) /* 1e15 */
#define TEST_CAP_VERSIONS  (10UL)                  /* 2e19 of versions, past 2^64 */

static void
cap_stage( fd_snapin_tile_t * ctx,
           ulong              id,
           ulong              slot,
           ulong              lamports ) {
  uchar pubkey[ 32UL ] = {0};
  uchar owner [ 32UL ] = { 0x42U };
  uchar data  [ 1UL  ] = {0};
  FD_STORE( ulong, pubkey, id );
  pubkey[ 31 ] = 0xC3U;
  FD_TEST( !writer_append_account( ctx, pubkey, owner, data, slot, lamports, 0UL, 0 ) );
}

static void
cap_flush( test_env_t * env ) {
  for( ulong i=0UL; i<env->worker_cnt; i++ ) FD_TEST( !writer_flush( &env->worker[ i ] ) );
}

/* Loads a whale (id 1) and three small accounts as the full snapshot,
   checks it, then begins an incremental the way INIT_INCR does.
   Returns the full snapshot's capitalization. */

static ulong
cap_full_then_begin_incr( test_env_t * env ) {
  fd_snapin_tile_t * lead = &env->worker[ 0 ];
  fd_snapin_tile_t * w1   = &env->worker[ 1 ];
  cap_stage( lead, 1UL, TEST_CAP_FULL_SLOT, TEST_CAP_BIG   );
  cap_stage( lead, 2UL, TEST_CAP_FULL_SLOT, TEST_CAP_SMALL );
  cap_stage( w1,   3UL, TEST_CAP_FULL_SLOT, TEST_CAP_SMALL );
  cap_stage( w1,   4UL, TEST_CAP_FULL_SLOT, TEST_CAP_SMALL );
  cap_flush( env );

  ulong full_cap = TEST_CAP_BIG + 3UL*TEST_CAP_SMALL;
  lead->lead.manifest_capitalization = full_cap;
  FD_TEST( !validate_capitalization( lead ) );
  lead->lead.recovery.capitalization = full_cap;

  fd_accdb_fork_id_t incr = fd_accdb_attach_child( lead->accdb, env->root );
  fd_memset( &env->snapin_shmem->values, 0, sizeof(env->snapin_shmem->values) );
  for( ulong i=0UL; i<env->worker_cnt; i++ ) {
    env->worker[ i ].full      = 0;
    env->worker[ i ].incr_fork = (ulong)incr.val;
  }
  return full_cap;
}

/* The testnet case: the whale once per slot, newest first on another
   worker so the accdb both replaces and ignores versions, and one small
   balance up by 7.  Input and duplicate lamports each pass 2^64 while
   capitalization moves by 7.  Saturating sums computed 0 here. */

static void
test_capitalization_versions_past_2_64( void ) {
  test_env_t env[1];
  test_env_init( env, 9UL );
  fd_snapin_tile_t * lead = &env->worker[ 0 ];
  ulong full_cap = cap_full_then_begin_incr( env );

  for( ulong v=0UL; v<TEST_CAP_VERSIONS; v++ ) {
    cap_stage( &env->worker[ 1UL-(v&1UL) ], 1UL, TEST_CAP_FULL_SLOT+TEST_CAP_VERSIONS-v, TEST_CAP_BIG );
  }
  cap_stage( lead, 2UL, TEST_CAP_FULL_SLOT+5UL, TEST_CAP_SMALL+7UL );
  cap_flush( env );
  FD_TEST( TEST_CAP_BIG>ULONG_MAX/TEST_CAP_VERSIONS );

  lead->lead.manifest_capitalization = full_cap+7UL; FD_TEST( !validate_capitalization( lead ) );
  lead->lead.manifest_capitalization = full_cap+6UL; FD_TEST(  validate_capitalization( lead ) );
  lead->lead.manifest_capitalization = full_cap+8UL; FD_TEST(  validate_capitalization( lead ) );

  fd_accdb_snapshot_load_end( lead->accdb );
  test_env_free( env );
}

/* A crafted incremental: one balance up by 7, and a new account that
   holds H lamports and is then closed, with H picked so the saturated
   sum lands on the full snapshot's capitalization.  Saturating sums
   accepted a manifest that claims nothing changed. */

static void
test_capitalization_crafted_mismatch( void ) {
  test_env_t env[1];
  test_env_init( env, 9UL );
  fd_snapin_tile_t * lead = &env->worker[ 0 ];
  ulong full_cap = cap_full_then_begin_incr( env );

  cap_stage( lead,            2UL, TEST_CAP_FULL_SLOT+5UL, TEST_CAP_SMALL+7UL );
  cap_stage( lead,            5UL, TEST_CAP_FULL_SLOT+1UL, ULONG_MAX-full_cap-TEST_CAP_SMALL );
  cap_stage( &env->worker[1], 5UL, TEST_CAP_FULL_SLOT+2UL, 0UL );
  cap_flush( env );

  lead->lead.manifest_capitalization = full_cap;     FD_TEST(  validate_capitalization( lead ) );
  lead->lead.manifest_capitalization = full_cap+7UL; FD_TEST( !validate_capitalization( lead ) );

  fd_accdb_snapshot_load_end( lead->accdb );
  test_env_free( env );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_snapin_accdb( 1UL );
  test_snapin_accdb( 9UL );
  test_capitalization_versions_past_2_64();
  test_capitalization_crafted_mismatch();
  test_instant_boot_skips_bank_state();
  test_stream_writes_boot_fork();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
