#include "../fd_flamenco.h"
#include "fd_solcap_proto.h"
#include "fd_solcap_reader.h"
#include "fd_solcap.pb.h"

#include <errno.h>
#include <stdio.h>


/* Define routines for sorting the bank hash account delta accounts.
   The solcap format does not mandate accounts to be sorted. */

static inline int
fd_solcap_account_tbl_lt( fd_solcap_account_tbl_t const * a,
                          fd_solcap_account_tbl_t const * b ) {
  return memcmp( a->key, b->key, 32UL ) < 0;
}
#define SORT_NAME        sort_account_tbl
#define SORT_KEY_T       fd_solcap_account_tbl_t
#define SORT_BEFORE(a,b) fd_solcap_account_tbl_lt( &(a), &(b) )
#include "../../util/tmpl/fd_sort.c"

/* TODO this differ is currently a separate file, but it would make
        sense to move/copy it to test_runtime.  Doing so would enable
        a fast feedback cycle wherein a developer supplies the expected
        (Labs) capture to test_runtime, then automatically runs the
        differ after each execution. */

struct fd_solcap_differ {
  fd_solcap_chunk_iter_t iter    [2];
  fd_solcap_BankPreimage preimage[2];
  int                    verbose;
};

typedef struct fd_solcap_differ fd_solcap_differ_t;

static fd_solcap_differ_t *
fd_solcap_differ_new( fd_solcap_differ_t * diff,
                      FILE *               streams[2] ) {

  /* Attach to capture files */

  for( ulong i=0UL; i<2UL; i++ ) {
    FILE * stream = streams[i];

    /* Read file header */
    fd_solcap_fhdr_t hdr[1];
    if( FD_UNLIKELY( 1UL!=fread( hdr, sizeof(fd_solcap_fhdr_t), 1UL, stream ) ) ) {
      /* TODO also log path of file that failed to read */
      FD_LOG_WARNING(( "Failed to read file header (%d-%s)", errno, strerror( errno ) ));
      return NULL;
    }

    /* Seek to first chunk */
    long skip = ( (long)hdr->chunk0_foff - (long)sizeof(fd_solcap_fhdr_t) );
    if( FD_UNLIKELY( 0!=fseek( stream, skip, SEEK_CUR ) ) ) {
      FD_LOG_WARNING(( "Failed to seek to first chunk (%d-%s)", errno, strerror( errno ) ));
      return NULL;
    }

    if( FD_UNLIKELY( !fd_solcap_chunk_iter_new( &diff->iter[i], stream ) ) )
      FD_LOG_CRIT(( "fd_solcap_chunk_iter_new() failed" ));
  }

  return diff;
}

/* fd_solcap_differ_advance seeks an iterator to the next bank hash.
   idx identifies the iterator.  Returns 1 on success, 0 if end-of-file
   reached, and negated errno-like on failure. */

static int
fd_solcap_differ_advance( fd_solcap_differ_t * diff,
                          ulong                idx ) { /* [0,2) */

  fd_solcap_chunk_iter_t * iter     = &diff->iter    [ idx ];
  fd_solcap_BankPreimage * preimage = &diff->preimage[ idx ];

  long off = fd_solcap_chunk_iter_find( iter, FD_SOLCAP_V1_BANK_MAGIC );
  if( FD_UNLIKELY( off<0L ) )
    return fd_solcap_chunk_iter_err( iter );

  int err = fd_solcap_read_bank_preimage( iter->stream, iter->chunk_off, preimage, &iter->chunk );
  if( FD_UNLIKELY( err!=0 ) ) return -err;
  return 1;
}

/* fd_solcap_differ_sync synchronizes the given two iterators such that
   both point to the lowest common slot number.  Returns 1 on success
   and 0 if no common slot was found.  Negative values are negated
   errno-like. */

static int
fd_solcap_differ_sync( fd_solcap_differ_t * diff ) {

  /* Seek to first bank preimage object */

  for( ulong i=0UL; i<2UL; i++ ) {
    int res = fd_solcap_differ_advance( diff, i );
    if( FD_UNLIKELY( res!=1 ) ) return res;
  }

  for(;;) {
    ulong slot0 = diff->preimage[ 0 ].slot;
    ulong slot1 = diff->preimage[ 1 ].slot;

    if( slot0==slot1 ) return 1;

    ulong idx = slot0<slot1;
    int res = fd_solcap_differ_advance( diff, idx );
    if( FD_UNLIKELY( res<=0 ) ) return res;
  }

  return 0;
}

/* fd_solcap_diff_account prints further details about a mismatch
   between two accounts.  Preserves stream cursors. */

static void
fd_solcap_diff_account( fd_solcap_differ_t *                  diff,
                        fd_solcap_account_tbl_t const * const entry       [ static 2 ],
                        ulong const                           acc_tbl_goff[ static 2 ] ) {

  /* Remember current file offsets  (should probably just use readat) */
  long orig_off[ 2 ];
  for( ulong i=0UL; i<2UL; i++ ) {
    orig_off[ i ] = ftell( diff->iter[ i ].stream );
    if( FD_UNLIKELY( orig_off[ i ]<0L ) )
      FD_LOG_ERR(( "ftell failed (%d-%s)", errno, strerror( errno ) ));
  }

  /* Read account meta */
  fd_solcap_AccountMeta meta[2];
  for( ulong i=0UL; i<2UL; i++ ) {
    FILE * stream = diff->iter[ i ].stream;
    int err = fd_solcap_find_account( stream, meta+i, entry[i], acc_tbl_goff[i] );
    FD_TEST( err==0 );
    /* TODO pretty print data */
  }

  if( meta[0].lamports != meta[1].lamports )
    printf( "    -lamports:   %lu\n"
            "    +lamports:   %lu\n",
            meta[0].lamports,
            meta[1].lamports );
  if( meta[0].data_sz != meta[1].data_sz )
    printf( "    -data_sz:    %lu\n"
            "    +data_sz:    %lu\n",
            meta[0].data_sz,
            meta[1].data_sz );
  if( 0!=memcmp( meta[0].owner, meta[1].owner, 32UL ) )
    printf( "    -owner:      %32J\n"
            "    +owner:      %32J\n",
            meta[0].owner,
            meta[1].owner );
  if( meta[0].slot != meta[1].slot )
    printf( "    -slot:       %lu\n"
            "    +slot:       %lu\n",
            meta[0].slot,
            meta[1].slot );
  if( meta[0].rent_epoch != meta[1].rent_epoch )
    printf( "    -rent_epoch: %lu\n"
            "    +rent_epoch: %lu\n",
            meta[0].rent_epoch,
            meta[1].rent_epoch );

  /* Restore file offsets */
  for( ulong i=0UL; i<2UL; i++ ) {
    if( FD_UNLIKELY( 0!=fseek( diff->iter[ i ].stream, orig_off[ i ], SEEK_SET ) ) )
      FD_LOG_ERR(( "fseek failed (%d-%s)", errno, strerror( errno ) ));
  }
}

/* fd_solcap_diff_account_tbl detects and prints differences in the
   accounts that were hashed into the account delta hash. */

static void
fd_solcap_diff_account_tbl( fd_solcap_differ_t * diff ) {

  /* Read and sort tables */

  fd_solcap_account_tbl_t * tbl    [2];
  fd_solcap_account_tbl_t * tbl_end[2];
  ulong                     chunk_goff[2];
  for( ulong i=0UL; i<2UL; i++ ) {
    if( diff->preimage[i].account_table_coff == 0L ) {
      FD_LOG_WARNING(( "Missing accounts table in capture" ));
      return;
    }
    chunk_goff[i] = (ulong)( (long)diff->iter[i].chunk_off + diff->preimage[i].account_table_coff );

    /* Read table meta and seek to table */
    FILE * stream = diff->iter[i].stream;
    fd_solcap_AccountTableMeta meta[1];
    int err = fd_solcap_find_account_table( stream, meta, chunk_goff[i] );
    FD_TEST( err==0 );

    if( FD_UNLIKELY( meta->account_table_cnt > INT_MAX ) ) {
      FD_LOG_WARNING(( "Too many accounts in capture" ));
      return;
    }

    /* Allocate table */
    ulong tbl_cnt   = meta->account_table_cnt;
    ulong tbl_align = alignof(fd_solcap_account_tbl_t);
    ulong tbl_sz    = tbl_cnt * sizeof(fd_solcap_account_tbl_t);
    FD_TEST( fd_scratch_alloc_is_safe( tbl_align, tbl_sz ) );
    tbl    [i] = fd_scratch_alloc( tbl_align, tbl_sz );
    tbl_end[i] = tbl[i] + tbl_cnt;

    /* Read table */
    FD_TEST( tbl_cnt==fread( tbl[i], sizeof(fd_solcap_account_tbl_t), tbl_cnt, stream ) );

    /* Sort table */
    sort_account_tbl_inplace( tbl[i], tbl_cnt );
  }

  /* Walk tables in parallel */

  for(;;) {
    fd_solcap_account_tbl_t * a = tbl[0];
    fd_solcap_account_tbl_t * b = tbl[1];

    if( a==tbl_end[0] ) break;
    if( b==tbl_end[1] ) break;

    int key_cmp = memcmp( a->key, b->key, 32UL );
    if( key_cmp==0 ) {
      int hash_cmp = memcmp( a->hash, b->hash, 32UL );
      if( hash_cmp!=0 ) {
        printf( "   account: %32J\n"
                "    -hash:       %32J\n"
                "    +hash:       %32J\n",
                a->key,
                a->hash,
                b->hash );

        if( diff->verbose >= 3 )
          fd_solcap_diff_account( diff, (fd_solcap_account_tbl_t const * const *)tbl, chunk_goff );
      }

      tbl[0]++;
      tbl[1]++;
      continue;
    }

    if( key_cmp<0 ) {
      printf( "  -account: %32J\n", a->key );
      tbl[0]++;
      continue;
    }

    if( key_cmp>0 ) {
      printf( "  +account: %32J\n", b->key );
      tbl[1]++;
      continue;
    }
  }
  while( tbl[0]!=tbl_end[0] ) {
    printf( "  -account: %32J\n", tbl[0]->key );
    tbl[0]++;
  }
  while( tbl[1]!=tbl_end[1] ) {
    printf( "  +account: %32J\n", tbl[1]->key );
    tbl[1]++;
  }

}

/* fd_solcap_diff_bank detects bank hash mismatches and prints a
   human-readable description of the root cause to stdout.  Returns 0
   if bank hashes match, 1 if a mismatch was detected. */

static int
fd_solcap_diff_bank( fd_solcap_differ_t * diff ) {

  fd_solcap_BankPreimage const * pre = diff->preimage;

  FD_TEST( pre[0].slot == pre[1].slot );
  if( 0==memcmp( &pre[0], &pre[1], sizeof(fd_solcap_BankPreimage) ) )
    return 0;

  printf( "Slot % 10lu: Bank hash mismatch\n"
          "\n"
          "-bank_hash: %32J\n"
          "+bank_hash: %32J\n",
          pre[0].slot,
          pre[0].bank_hash,
          pre[1].bank_hash );

  /* Investigate reason for mismatch */

  int only_account_mismatch = 0;
  if( 0!=memcmp( pre[0].account_delta_hash, pre[1].account_delta_hash, 32UL ) ) {
    only_account_mismatch = 1;
    printf( "-account_delta_hash: %32J\n"
            "+account_delta_hash: %32J\n",
            pre[0].account_delta_hash,
            pre[1].account_delta_hash );
  }
  if( 0!=memcmp( pre[0].prev_bank_hash, pre[1].prev_bank_hash, 32UL ) ) {
    only_account_mismatch = 0;
    printf( "-prev_bank_hash:     %32J\n"
            "+prev_bank_hash:     %32J\n",
            pre[0].prev_bank_hash,
            pre[1].prev_bank_hash );
  }
  if( 0!=memcmp( pre[0].poh_hash, pre[1].poh_hash, 32UL ) ) {
    only_account_mismatch = 0;
    printf( "-poh_hash:           %32J\n"
            "+poh_hash:           %32J\n",
            pre[0].poh_hash,
            pre[1].poh_hash );
  }
  if( pre[0].signature_cnt != pre[1].signature_cnt ) {
    only_account_mismatch = 0;
    printf( "-signature_cnt:      %lu\n"
            "+signature_cnt:      %lu\n",
            pre[0].signature_cnt,
            pre[1].signature_cnt );
  }
  if( pre[0].account_cnt != pre[1].account_cnt ) {
    printf( "-account_cnt:        %lu\n"
            "+account_cnt:        %lu\n",
            pre[0].account_cnt,
            pre[1].account_cnt );
  }

  if( only_account_mismatch && diff->verbose >= 2 ) {
    fd_scratch_push();
    fd_solcap_diff_account_tbl( diff );
    fd_scratch_pop();
  }

  return 1;
}


static void
usage( void ) {
  fprintf( stderr,
    "Usage: fd_solcap_diff [options] {FILE1} {FILE2}\n"
    "\n"
    "Imports a runtime capture file from JSON.\n"
    "\n"
    "Options:\n"
    "  --page-sz      {gigantic|huge|normal}    Page size\n"
    "  --page-cnt     {count}                   Page count\n"
    "  --scratch-mb   1024                      Scratch mem MiB\n"
    "  -v             1                         Diff verbosity\n"
    //"  --slots        (null)                    Slot range\n"
    "\n" );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_flamenco_boot( &argc, &argv );

  /* Command line handling */

  for( int i=1; i<argc; i++ ) {
    if( 0==strcmp( argv[i], "--help" ) ) {
      usage();
      return 0;
    }
  }

  char const * _page_sz   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",    NULL, "gigantic" );
  ulong        page_cnt   = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",   NULL, 2UL        );
  ulong        scratch_mb = fd_env_strip_cmdline_ulong( &argc, &argv, "--scratch-mb", NULL, 1024UL     );
  int          verbose    = fd_env_strip_cmdline_int  ( &argc, &argv, "-v",           NULL, 1          );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  char const * cap_path[2] = {0};
  int          caps_found  = 0;

  for( int i=1; i<argc; i++ ) {
    if( 0==strncmp( argv[i], "--", 2 ) ) continue;
    if( caps_found>=2 ) { usage(); return 1; }
    cap_path[ caps_found++ ] = argv[i];
  }
  if( caps_found!=2 ) {
    fprintf( stderr, "ERROR: expected 2 arguments, got %d\n", argc-1 );
    usage();
    return 1;
  }

  /* Acquire workspace */

  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_log_cpu_id(), "wksp", 0UL );
  if( FD_UNLIKELY( !wksp ) ) FD_LOG_ERR(( "fd_wksp_new_anonymous() failed" ));

  /* Create scratch allocator */

  ulong  smax = scratch_mb << 20;
  void * smem = fd_wksp_alloc_laddr( wksp, fd_scratch_smem_align(), smax, 1UL );
  if( FD_UNLIKELY( !smem ) ) FD_LOG_ERR(( "Failed to alloc scratch mem" ));

# define SCRATCH_DEPTH (4UL)
  ulong fmem[ SCRATCH_DEPTH ] __attribute((aligned(FD_SCRATCH_FMEM_ALIGN)));

  fd_scratch_attach( smem, fmem, smax, SCRATCH_DEPTH );

  /* Open capture files for reading */

  FILE * cap_file[2] = {0};
  cap_file[0] = fopen( cap_path[0], "rb" );
  cap_file[1] = fopen( cap_path[1], "rb" );

  if( FD_UNLIKELY( (!cap_file[0]) | (!cap_file[1]) ) )
    FD_LOG_ERR(( "fopen failed (%d-%s)", errno, strerror( errno ) ));

  /* Create differ */

  fd_solcap_differ_t diff[1];
  if( FD_UNLIKELY( !fd_solcap_differ_new( diff, cap_file ) ) )
    return 1;
  diff->verbose = verbose;
  int res = fd_solcap_differ_sync( diff );
  if( res <0 ) FD_LOG_ERR(( "fd_solcap_differ_sync failed (%d-%s)",
                            -res, strerror( -res ) ));
  if( res==0 ) FD_LOG_ERR(( "Captures don't share any slots" ));

  /* Diff each block */

  for(;;) {
    /* TODO probably should return an error code on mismatch */
    if( FD_UNLIKELY( fd_solcap_diff_bank( diff ) ) ) break;
    printf( "Slot % 10lu: OK\n", diff->preimage[0].slot );
    /* Advance to next slot.
       TODO probably should log if a slot gets skipped on one capture,
            but not the other. */
    int res = fd_solcap_differ_sync( diff );
    if( FD_UNLIKELY( res<0 ) )
      FD_LOG_ERR(( "fd_solcap_differ_sync failed (%d-%s)",
                   -res, strerror( -res ) ));
    if( res==0 ) break;
  }

  /* Cleanup */

  fclose( cap_file[1] );
  fclose( cap_file[0] );
  FD_TEST( fd_scratch_frame_used()==0UL );
  fd_wksp_free_laddr( fd_scratch_detach( NULL ) );
  fd_flamenco_halt();
  fd_halt();
  return 0;
}
