#include "fd_snapshot_loader.h"
#include "fd_snapshot_http.h"
#include "fd_snapshot_restore_private.h"
#include "../runtime/fd_acc_mgr.h"
#include "../runtime/context/fd_exec_slot_ctx.h"
#include "../../ballet/zstd/fd_zstd.h"
#include "../../flamenco/types/fd_types.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <regex.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/random.h>

/* Snapshot restore ***************************************************/

#define OSTREAM_BUFSZ (32768UL)

struct fd_snapshot_dumper {
  fd_alloc_t * alloc;
  fd_funk_t    funk[1];

  fd_exec_slot_ctx_t *  slot_ctx;

  int snapshot_fd;

  fd_snapshot_loader_t *  loader;
  fd_snapshot_restore_t * restore;

  int                      csv_fd;
  fd_io_buffered_ostream_t csv_out;
  uchar                    csv_buf[ OSTREAM_BUFSZ ];

  int want_accounts;
  int has_fail;
};

typedef struct fd_snapshot_dumper fd_snapshot_dumper_t;

static fd_snapshot_dumper_t *
fd_snapshot_dumper_new( void * mem ) {
  fd_snapshot_dumper_t * dumper = mem;
  *dumper = (fd_snapshot_dumper_t) {
    .snapshot_fd = -1,
    .csv_fd      = -1
  };
  return dumper;
}

static void *
fd_snapshot_dumper_delete( fd_snapshot_dumper_t * dumper ) {

  if( dumper->loader ) {
    fd_snapshot_loader_delete( dumper->loader );
    dumper->loader = NULL;
  }

  if( dumper->restore ) {
    fd_snapshot_restore_delete( dumper->restore );
    dumper->restore = NULL;
  }

  if( dumper->slot_ctx ) {
    fd_exec_slot_ctx_delete( fd_exec_slot_ctx_leave( dumper->slot_ctx ) );
    dumper->slot_ctx = NULL;
  }

  if( dumper->funk->shmem ) {
    void * shfunk = NULL;
    fd_funk_leave( dumper->funk, &shfunk );
    fd_wksp_free_laddr( fd_funk_delete( shfunk ) );
  }

  if( dumper->alloc ) {
    fd_wksp_free_laddr( fd_alloc_delete( fd_alloc_leave( dumper->alloc ) ) );
    dumper->alloc = NULL;
  }

  if( dumper->csv_fd>=0 ) {
    fd_io_buffered_ostream_fini( &dumper->csv_out );
    if( FD_UNLIKELY( 0!=close( dumper->csv_fd ) ) )
      FD_LOG_WARNING(( "close(%d) failed (%d-%s)", dumper->csv_fd, errno, fd_io_strerror( errno ) ));
    dumper->csv_fd = -1;
  }

  fd_memset( dumper, 0, sizeof(fd_snapshot_dumper_t) );
  return dumper;
}

/* fd_snapshot_dumper_record processes a newly encountered account
   record. */

union fd_snapshot_csv_rec {
  char line[ 180 ];
  struct __attribute__((packed)) {
    char acct_addr[ FD_BASE58_ENCODED_32_LEN ];
    char comma1;
    char owner_addr[ FD_BASE58_ENCODED_32_LEN ];
    char comma2;
    char hash[ FD_BASE58_ENCODED_32_LEN ];
    char comma3;
    char slot[ 14 ];  /* enough for 10000 years at 400ms slot time */
    char comma4;
    char size[ 8 ];  /* can represent [0,10<<20) */
    char comma5;
    char lamports[ 20 ];  /* can represent [0,1<<64) */
    char newline;
  };
};

typedef union fd_snapshot_csv_rec fd_snapshot_csv_rec_t;

static void
fd_snapshot_dumper_record( fd_snapshot_dumper_t * d,
                           fd_funk_rec_t const *  rec,
                           fd_wksp_t *            wksp ) {

  uchar const *             rec_val = fd_funk_val_const( rec, wksp );
  fd_account_meta_t const * meta    = (fd_account_meta_t const *)rec_val;
  //uchar const *             data    = rec_val + meta->hlen;

  if( d->csv_fd>=0 ) {
    fd_snapshot_csv_rec_t csv_rec;
    fd_memset( &csv_rec, ' ', sizeof(csv_rec) );

    ulong b58sz;
    fd_base58_encode_32( rec->pair.key->uc, &b58sz, csv_rec.acct_addr );
    csv_rec.line[ offsetof(fd_snapshot_csv_rec_t,acct_addr)+b58sz ] = ' ';
    csv_rec.comma1 = ',';

    fd_base58_encode_32( meta->info.owner, &b58sz, csv_rec.owner_addr );
    csv_rec.line[ offsetof(fd_snapshot_csv_rec_t,owner_addr)+b58sz ] = ' ';
    csv_rec.comma2 = ',';

    fd_base58_encode_32( meta->hash, &b58sz, csv_rec.hash );
    csv_rec.line[ offsetof(fd_snapshot_csv_rec_t,hash)+b58sz ] = ' ';
    csv_rec.comma3 = ',';

    fd_cstr_append_ulong_as_text( csv_rec.slot, ' ', '\0', meta->dlen, 15 );
    csv_rec.comma4 = ',';

    fd_cstr_append_ulong_as_text( csv_rec.size, ' ', '\0', meta->dlen, 8 );
    csv_rec.comma5 = ',';

    fd_cstr_append_ulong_as_text( csv_rec.lamports, ' ', '\0', meta->info.lamports, 20 );
    csv_rec.newline = '\n';

    fd_io_buffered_ostream_write( &d->csv_out, csv_rec.line, sizeof(csv_rec.line) );
  }
}

/* fd_snapshot_dumper_release visits any newly appeared accounts and
   removes their records from the database. */

static int
fd_snapshot_dumper_release( fd_snapshot_dumper_t * d ) {

  fd_funk_txn_t *   funk_txn = d->restore->funk_txn;
  fd_funk_txn_xid_t txn_xid  = funk_txn->xid;
  fd_funk_t *       funk     = d->funk;
  fd_wksp_t *       wksp     = fd_funk_wksp( funk );

  /* Dump all the records */
  for( fd_funk_rec_t const * rec = fd_funk_txn_first_rec( funk, funk_txn );
       rec;
       rec = fd_funk_txn_next_rec( funk, rec ) ) {
    if( FD_UNLIKELY( !fd_funk_key_is_acc( rec->pair.key ) ) ) continue;
    fd_snapshot_dumper_record( d, rec, wksp );
  }

  /* In order to save heap space, evict all the accounts we just
     visited.  We can do this because we know we'll never read them
     again. */

  if( FD_UNLIKELY( fd_funk_txn_cancel( funk, funk_txn, 1 )!=1UL ) )
    FD_LOG_ERR(( "Failed to cancel funk txn" ));  /* unreachable */

  funk_txn = fd_funk_txn_prepare( funk, NULL, &txn_xid, 1 );
  if( FD_UNLIKELY( !funk_txn ) )
    FD_LOG_ERR(( "Failed to prepare funk txn" ));  /* unreachable */

  d->restore->funk_txn = funk_txn;
  return 0;
}

/* fd_snapshot_dumper_advance polls the tar reader for data and handles
   any newly appeared accounts. */

static int
fd_snapshot_dumper_advance( fd_snapshot_dumper_t * dumper ) {

  int advance_err = fd_snapshot_loader_advance( dumper->loader );
  if( FD_UNLIKELY( advance_err ) ) {
    if( advance_err==MANIFEST_DONE ) return 0;
    if( advance_err>0 ) FD_LOG_WARNING(( "fd_snapshot_loader_advance() failed (%d)", advance_err ));
    return advance_err;
  }

  int collect_err = fd_snapshot_dumper_release( dumper );
  if( FD_UNLIKELY( collect_err ) ) return collect_err;

  return 0;
}

/* fd_snapshot_dump_args_t contains the command-line arguments for the
   dump command. */

struct fd_snapshot_dump_args {
  char const * _page_sz;
  ulong        page_cnt;
  ulong        near_cpu;
  ulong        zstd_window_sz;
  char *       snapshot;
  char const * csv_path;
  int          csv_hdr;
  ushort       http_redirs;
};

typedef struct fd_snapshot_dump_args fd_snapshot_dump_args_t;

static int
do_dump( fd_snapshot_dumper_t *    d,
         fd_snapshot_dump_args_t * args,
         fd_wksp_t *               wksp,
         fd_spad_t *               spad ) {

  /* Resolve snapshot source */

  fd_snapshot_src_t src[1];
  src->snapshot_dir = NULL;
  if( FD_UNLIKELY( !fd_snapshot_src_parse_type_unknown( src, args->snapshot ) ) )
    return EXIT_FAILURE;

  /* Create a heap */

  ulong const fd_alloc_tag = 41UL;
  d->alloc = fd_alloc_join( fd_alloc_new( fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), fd_alloc_tag ), fd_alloc_tag ), 0UL );
  if( FD_UNLIKELY( !d->alloc ) ) { FD_LOG_WARNING(( "fd_alloc_join() failed" )); return EXIT_FAILURE; }

  fd_wksp_usage_t wksp_usage[1] = {0};
  fd_wksp_usage( wksp, NULL, 0UL, wksp_usage );

  if( args->csv_path ) {
    d->csv_fd = open( args->csv_path, O_WRONLY|O_CREAT|O_TRUNC, 0644 );
    if( FD_UNLIKELY( d->csv_fd<0 ) ) { FD_LOG_WARNING(( "open(%s) failed (%d-%s)", args->csv_path, errno, fd_io_strerror( errno ) )); return EXIT_FAILURE; }
    fd_io_buffered_ostream_init( &d->csv_out, d->csv_fd, d->csv_buf, OSTREAM_BUFSZ );
  }

  /* Create loader */

  d->loader = fd_snapshot_loader_new( fd_spad_alloc( spad, fd_snapshot_loader_align(), fd_snapshot_loader_footprint( args->zstd_window_sz ) ), args->zstd_window_sz );
  if( FD_UNLIKELY( !d->loader ) ) { FD_LOG_WARNING(( "Failed to create fd_snapshot_loader_t" )); return EXIT_FAILURE; }

  /* Create a high-quality hash seed for fd_funk */

  ulong funk_seed;
  if( FD_UNLIKELY( sizeof(ulong)!=getrandom( &funk_seed, sizeof(ulong), 0 ) ) )
    { FD_LOG_WARNING(( "getrandom() failed (%d-%s)", errno, fd_io_strerror( errno ) )); return EXIT_FAILURE; }

  /* Create a funk database */

  ulong const txn_max =   16UL;  /* we really only need 1 */
  uint const rec_max = 1024UL;  /* we evict records as we go */

  ulong funk_tag = 42UL;
  int funk_ok = !!fd_funk_join( d->funk, fd_funk_new( fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint(txn_max, rec_max), funk_tag ), funk_tag, funk_seed, txn_max, rec_max ) );
  if( FD_UNLIKELY( !funk_ok ) ) { FD_LOG_WARNING(( "Failed to create fd_funk_t" )); return EXIT_FAILURE; }

  /* Create a new processing context */

  d->slot_ctx = fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( fd_spad_alloc( spad, FD_EXEC_SLOT_CTX_ALIGN, FD_EXEC_SLOT_CTX_FOOTPRINT ) ) );
  if( FD_UNLIKELY( !d->slot_ctx ) ) { FD_LOG_WARNING(( "Failed to create fd_exec_slot_ctx_t" )); return EXIT_FAILURE; }

  /* funk_txn is destroyed automatically when deleting fd_funk_t. */

  fd_funk_txn_xid_t funk_txn_xid = { .ul = { 1UL } };
  fd_funk_txn_t * funk_txn = fd_funk_txn_prepare( d->funk, NULL, &funk_txn_xid, 1 );
  d->slot_ctx->funk_txn = funk_txn;

  void * restore_mem = fd_spad_alloc( spad, fd_snapshot_restore_align(), fd_snapshot_restore_footprint() );
  if( FD_UNLIKELY( !restore_mem ) ) FD_LOG_ERR(( "Failed to allocate restore buffer" ));  /* unreachable */

  d->restore = fd_snapshot_restore_new( restore_mem, d->funk, funk_txn, spad, d, NULL, NULL );
  if( FD_UNLIKELY( !d->restore ) ) { FD_LOG_WARNING(( "Failed to create fd_snapshot_restore_t" )); return EXIT_FAILURE; }

  /* Set up the snapshot loader */

  if( FD_UNLIKELY( !fd_snapshot_loader_init( d->loader, d->restore, src, 0UL, 0 ) ) ) {
    FD_LOG_WARNING(( "fd_snapshot_loader_init failed" ));
    return EXIT_FAILURE;
  }

  d->want_accounts = (!!args->csv_path);

  if( FD_UNLIKELY( !d->want_accounts ) ) {
    FD_LOG_NOTICE(( "Nothing to do, exiting." ));
    return EXIT_SUCCESS;
  }

  if( (d->csv_fd>=0) & (args->csv_hdr) ) {
    fd_snapshot_csv_rec_t csv_rec;
    memset( &csv_rec, ' ', sizeof(fd_snapshot_csv_rec_t) );
    memcpy( csv_rec.acct_addr,  "address",  strlen( "address"  ) );
    memcpy( csv_rec.owner_addr, "owner",    strlen( "owner"    ) );
    memcpy( csv_rec.hash,       "hash",     strlen( "hash"     ) );
    memcpy( csv_rec.slot,       "slot",     strlen( "slot"     ) );
    memcpy( csv_rec.size,       "size",     strlen( "size"     ) );
    memcpy( csv_rec.lamports,   "lamports", strlen( "lamports" ) );
    csv_rec.comma1  = ',';
    csv_rec.comma2  = ',';
    csv_rec.comma3  = ',';
    csv_rec.comma4  = ',';
    csv_rec.comma5  = ',';
    csv_rec.newline = '\n';

    if( FD_UNLIKELY( write( d->csv_fd, csv_rec.line, sizeof(fd_snapshot_csv_rec_t) )
                     != sizeof(fd_snapshot_csv_rec_t) ) ) {
      FD_LOG_WARNING(( "Failed to write CSV header (%d-%s)", errno, fd_io_strerror( errno ) ));
      d->has_fail = 1;
      return EXIT_FAILURE;
    }
  }

  for(;;) {
    int err = fd_snapshot_dumper_advance( d );
    if( err==0 )     { /* ok */ }
    else if( err<0 ) { /* EOF */ break; }
    else             { return EXIT_FAILURE; }

    if( FD_UNLIKELY( !d->want_accounts ) )
      break;
  }

  return d->has_fail ? EXIT_FAILURE : EXIT_SUCCESS;
}

int
cmd_dump( int     argc,
          char ** argv ) {

  fd_snapshot_dump_args_t args[1] = {{0}};
  args->_page_sz       =         fd_env_strip_cmdline_cstr  ( &argc, &argv, "--page-sz",        NULL,      "gigantic" );
  args->page_cnt       =         fd_env_strip_cmdline_ulong ( &argc, &argv, "--page-cnt",       NULL,             5UL );
  args->near_cpu       =         fd_env_strip_cmdline_ulong ( &argc, &argv, "--near-cpu",       NULL, fd_log_cpu_id() );
  args->zstd_window_sz =         fd_env_strip_cmdline_ulong ( &argc, &argv, "--zstd-window-sz", NULL,      33554432UL );
  args->snapshot       = (char *)fd_env_strip_cmdline_cstr  ( &argc, &argv, "--snapshot",       NULL,            NULL );
  args->csv_path       =         fd_env_strip_cmdline_cstr  ( &argc, &argv, "--csv",            NULL,            NULL );
  args->csv_hdr        =         fd_env_strip_cmdline_int   ( &argc, &argv, "--csv-hdr",        NULL,               1 );
  args->http_redirs    = (ushort)fd_env_strip_cmdline_ushort( &argc, &argv, "--http-redirs",    NULL,               5 );

  if( FD_UNLIKELY( argc!=1 ) )
    FD_LOG_ERR(( "Unexpected command-line arguments" ));
  if( FD_UNLIKELY( !args->snapshot ) )
    FD_LOG_ERR(( "Missing --snapshot argument" ));

  FD_LOG_NOTICE(( "Creating workspace (--page-cnt %lu, --page-sz %s)", args->page_cnt, args->_page_sz ));

  /* With workspace */

  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( args->_page_sz ), args->page_cnt, args->near_cpu, "wksp", 0UL );
  if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "fd_wksp_new_anonymous() failed" ));

  /* With spad */

  ulong       mem_max = args->zstd_window_sz + (1UL<<32); /* manifest plus 4 GiB headroom */
  uchar *     mem     = fd_wksp_alloc_laddr(  wksp, FD_SPAD_ALIGN, FD_SPAD_FOOTPRINT( mem_max ), 1UL );
  fd_spad_t * spad    = fd_spad_join( fd_spad_new( mem, mem_max ) );
  if( FD_UNLIKELY( !spad ) ) {
    FD_LOG_ERR(( "Failed to allocate spad" ));
  }
  fd_spad_push( spad );

  /* With dump context */

  fd_snapshot_dumper_t  _dumper[1];
  fd_snapshot_dumper_t * dumper = fd_snapshot_dumper_new( _dumper );

  int rc = do_dump( dumper, args, wksp, spad );
  FD_LOG_INFO(( "Done. Cleaning up." ));

  fd_snapshot_dumper_delete( dumper );

  fd_spad_pop( spad );
  void * spad_mem = fd_spad_delete( fd_spad_leave( spad ) );
  fd_wksp_free_laddr( spad_mem );

  fd_wksp_delete_anonymous( wksp );
  return rc;
}

FD_IMPORT_CSTR( _help, "src/flamenco/snapshot/fd_snapshot_help.txt" );

__attribute__((noreturn)) static int
usage( int code ) {
  fwrite( _help, 1, _help_sz, stderr );
  fflush( stderr );
  exit( code );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  if( argc==1 ) return usage(1);
  if( 0==strcmp( argv[1], "help" ) ) return usage(0);
  for( int i=1; i<argc; i++ )
    if( 0==strcmp( argv[i], "--help" ) )
      return usage(0);

  argc--; argv++;
  char const * cmd = argv[0];

  if( 0==strcmp( cmd, "dump" ) ) {
    return cmd_dump( argc, argv );
  } else {
    fprintf( stderr, "Unknown command: %s\n", cmd );
    return usage(1);
  }

  fd_halt();
  return 0;
}
