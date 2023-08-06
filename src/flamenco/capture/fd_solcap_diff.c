#include "../fd_flamenco.h"
#include "fd_solcap_reader.h"
#include "fd_solcap.pb.h"

#include <errno.h>
#include <stdio.h>

/* TODO this differ is currently a separate file, but it would make
        sense to move/copy it to test_runtime.  Doing so would enable
        a fast feedback cycle wherein a developer supplies the expected
        (Labs) capture to test_runtime, then automatically runs the
        differ after each execution. */

struct fd_solcap_differ {
  fd_solcap_chunk_iter_t iter    [2];
  fd_solcap_BankPreimage preimage[2];
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
    int err = fd_solcap_differ_advance( diff, idx );
    if( FD_UNLIKELY( err<0 ) ) return err;
  }

  return 0;
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
  int res = fd_solcap_differ_sync( diff );
  if( res <0 ) FD_LOG_ERR(( "fd_solcap_differ_sync failed (%d-%s)",
                            -res, strerror( -res ) ));
  if( res==0 ) FD_LOG_ERR(( "Captures don't share any slots" ));

  /* Cleanup */

  fclose( cap_file[1] );
  fclose( cap_file[0] );
  FD_TEST( fd_scratch_frame_used()==0UL );
  fd_wksp_free_laddr( fd_scratch_detach( NULL ) );
  fd_flamenco_halt();
  fd_halt();
  return 0;
}
