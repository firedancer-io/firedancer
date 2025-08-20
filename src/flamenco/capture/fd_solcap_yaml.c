#include "fd_solcap_proto.h"
#include "fd_solcap_reader.h"
#include "fd_solcap.pb.h"
#include "../runtime/fd_executor_err.h"
#include "../../ballet/base64/fd_base64.h"
#include "../../ballet/nanopb/pb_decode.h"
#include <errno.h>
#include <stdio.h>

static int
usage( void ) {
  fprintf( stderr,
    "Usage: fd_solcap_yaml [options] {FILE}\n"
    "\n"
    "Print a runtime capture file as YAML.\n"
    "\n"
    "Options:\n"
    "  --page-sz      {gigantic|huge|normal}    Page size\n"
    "  --page-cnt     {count}                   Page count\n"
    "  --scratch-mb   1024                      Scratch mem MiB\n"
    "  -v             {level}                   YAML verbosity\n"
    "  --start-slot   {slot}                    Start slot\n"
    "  --end-slot     {slot}                    End slot\n"
    "\n" );
  return 0;
}

/* process_account reads and dumps a single account.  If verbose>4,
   includes a base64 dump of account content. */

static int
process_account( FILE * file,
                 long   goff,
                 int    verbose ) {

  /* Remember stream cursor */

  long pos = ftell( file );
  if( FD_UNLIKELY( pos<0L ) ) {
    FD_LOG_ERR(( "ftell failed (%d-%s)", errno, strerror( errno ) ));
    return 0;
  }

  /* Seek to chunk */

  if( FD_UNLIKELY( 0!=fseek( file, goff, SEEK_SET ) ) ) {
    FD_LOG_ERR(( "fseek failed (%d-%s)", errno, strerror( errno ) ));
    return 0;
  }

  /* Read chunk */

  fd_solcap_chunk_t chunk[1];
  ulong n = fread( chunk, sizeof(fd_solcap_chunk_t), 1UL, file );
  if( FD_UNLIKELY( n!=1UL ) ) {
    FD_LOG_ERR(( "fread chunk failed (%d-%s)", errno, strerror( errno ) ));
    return 0;
  }
  if( FD_UNLIKELY( chunk->magic != FD_SOLCAP_V1_ACCT_MAGIC ) ) {
    FD_LOG_ERR(( "expected account table chunk at %#lx, got magic=0x%016lx", (ulong)goff, chunk->magic ));
    return 0;
  }

  /* Read metadata */

  fd_solcap_AccountMeta meta[1];
  do {

    uchar meta_buf[ 512UL ];
    ulong meta_sz = chunk->meta_sz;
    if( FD_UNLIKELY( meta_sz > sizeof(meta_buf ) ) )
      FD_LOG_ERR(( "invalid account meta size (%lu)", meta_sz ));

    if( FD_UNLIKELY( 0!=fseek( file, (long)chunk->meta_coff - (long)sizeof(fd_solcap_chunk_t), SEEK_CUR ) ) )
      FD_LOG_ERR(( "fseek to account meta failed (%d-%s)", errno, strerror( errno ) ));

    if( FD_UNLIKELY( meta_sz != fread( meta_buf, 1UL, meta_sz, file ) ) )
      FD_LOG_ERR(( "fread account meta failed (%d-%s)", errno, strerror( errno ) ));

    pb_istream_t stream = pb_istream_from_buffer( meta_buf, meta_sz );
    if( FD_UNLIKELY( !pb_decode( &stream, fd_solcap_AccountMeta_fields, meta ) ) ) {
      FD_LOG_HEXDUMP_DEBUG(( "account meta", meta_buf, meta_sz ));
      FD_LOG_ERR(( "pb_decode account meta failed (%s)", PB_GET_ERROR(&stream) ));
    }

    long rewind = (long)chunk->meta_coff + (long)meta_sz;
    if( FD_UNLIKELY( 0!=fseek( file, -rewind, SEEK_CUR ) ) )
      FD_LOG_ERR(( "fseek failed (%d-%s)", errno, strerror( errno ) ));

  } while(0);

  printf(
    "      owner:      '%s'\n"
    "      lamports:   %lu\n"
    "      slot:       %lu\n"
    "      executable: %s\n"
    "      data_sz:    %lu\n",
    FD_BASE58_ENC_32_ALLOCA( meta->owner ),
    meta->lamports,
    meta->slot,
    meta->executable ? "true" : "false",
    meta->data_sz );

  /* Optionally print account data */

  if( verbose>4 ) {
    printf( "      data: '" );

    /* Seek to account data */
    if( FD_UNLIKELY( 0!=fseek( file, goff + meta->data_coff, SEEK_SET ) ) )
      FD_LOG_ERR(( "fseek to account data failed (%d-%s)", errno, strerror( errno ) ));

    /* Streaming Base64 encode.

       Process inputs in "parts" with length divided by 3, 4 such that
       no padding is in the middle of the encoding.  Technically Base64
       allows padding in the middle, but it's cleaner to only have
       padding at the end of the message. */
#   define PART_RAW_SZ (720UL)
    ulong data_sz = meta->data_sz;
    while( data_sz>0UL ) {
      ulong n = fd_ulong_min( data_sz, PART_RAW_SZ );

      /* Read chunk */
      uchar buf[ PART_RAW_SZ ];
      if( FD_UNLIKELY( 1UL!=fread( buf, n, 1UL, file ) ) )
        FD_LOG_ERR(( "fread account data failed (%d-%s)", errno, strerror( errno ) ));

      /* Encode chunk */
      char  chunk[ FD_BASE64_ENC_SZ( PART_RAW_SZ ) ];
      ulong chunk_sz = fd_base64_encode( chunk, buf, n );
      /* Print encoded chunk */
      FD_TEST( 1UL==fwrite( chunk, chunk_sz, 1UL, stdout ) );

      /* Wind up for next iteration */
      data_sz -= n;
    }
#   undef PART_RAW_SZ
#   undef PART_BLK_SZ

    /* Finish YAML entry */
    printf( "'\n" );
  }

  /* Restore cursor */

  if( FD_UNLIKELY( 0!=fseek( file, pos, SEEK_SET ) ) ) {
    FD_LOG_ERR(( "fseek failed (%d-%s)", errno, strerror( errno ) ));
    return 0;
  }

  return 1;
}

/* process_account_table reads and dumps an account table chunk.
   If verbose>3, also prints account content.  Returns 1 on success and
   0 on failure.  On success, restores stream cursor to position on
   function entry. */

static int
process_account_table( FILE * file,
                       ulong  slot,
                       int    verbose,
                       int    show_duplicate_accounts ) {

  /* Remember stream cursor */

  long pos = ftell( file );
  if( FD_UNLIKELY( pos<0L ) ) {
    FD_LOG_ERR(( "ftell failed (%d-%s)", errno, strerror( errno ) ));
    return 0;
  }

  /* Read chunk */

  fd_solcap_chunk_t chunk[1];
  ulong n = fread( chunk, sizeof(fd_solcap_chunk_t), 1UL, file );
  if( FD_UNLIKELY( n!=1UL ) ) {
    FD_LOG_ERR(( "fread chunk failed (%d-%s)", errno, strerror( errno ) ));
    return 0;
  }
  if( FD_UNLIKELY( chunk->magic != FD_SOLCAP_V1_ACTB_MAGIC ) ) {
    FD_LOG_ERR(( "expected account table chunk, got 0x%016lx", chunk->magic ));
    return 0;
  }

  /* Read metadata */

  fd_solcap_AccountTableMeta meta[1];
  do {

    uchar meta_buf[ 512UL ];
    ulong meta_sz = chunk->meta_sz;
    if( FD_UNLIKELY( meta_sz > sizeof(meta_buf ) ) ) {
      FD_LOG_ERR(( "invalid accounts table meta size (%lu)", meta_sz ));
      return 0;
    }

    if( FD_UNLIKELY( 0!=fseek( file, (long)chunk->meta_coff - (long)sizeof(fd_solcap_chunk_t), SEEK_CUR ) ) ) {
      FD_LOG_ERR(( "fseek to accounts table meta failed (%d-%s)", errno, strerror( errno ) ));
      return 0;
    }

    if( FD_UNLIKELY( meta_sz != fread( meta_buf, 1UL, meta_sz, file ) ) ) {
      FD_LOG_ERR(( "fread accounts table meta failed (%d-%s)", errno, strerror( errno ) ));
      return 0;
    }

    pb_istream_t stream = pb_istream_from_buffer( meta_buf, meta_sz );
    if( FD_UNLIKELY( !pb_decode( &stream, fd_solcap_AccountTableMeta_fields, meta ) ) ) {
      FD_LOG_HEXDUMP_DEBUG(( "accounts table meta", meta_buf, meta_sz ));
      FD_LOG_ERR(( "pb_decode accounts table meta failed (%s)", PB_GET_ERROR(&stream) ));
      return 0;
    }

    long rewind = (long)chunk->meta_coff + (long)meta_sz;
    if( FD_UNLIKELY( 0!=fseek( file, -rewind, SEEK_CUR ) ) ) {
      FD_LOG_ERR(( "fseek failed (%d-%s)", errno, strerror( errno ) ));
      return 0;
    }

  } while(0);

  /* TODO verify meta.slot */

  /* Seek to accounts table */

  if( FD_UNLIKELY( 0!=fseek( file, (long)meta->account_table_coff, SEEK_CUR ) ) ) {
    FD_LOG_ERR(( "fseek to accounts table failed (%d-%s)", errno, strerror( errno ) ));
    return 0;
  }

  typedef struct {
    fd_solcap_account_tbl_t entry;
    long acc_coff;
    int is_last_occurrence;
  } account_entry_info_t;

  account_entry_info_t * entries = malloc(meta->account_table_cnt * sizeof(account_entry_info_t));
  if( FD_UNLIKELY( !entries ) ) {
    FD_LOG_ERR(( "malloc failed for account entries" ));
    return 0;
  }

  for( ulong i=0UL; i < meta->account_table_cnt; i++ ) {
    if( FD_UNLIKELY( 1UL!=fread( &entries[i].entry, sizeof(fd_solcap_account_tbl_t), 1UL, file ) ) ) {
      FD_LOG_ERR(( "fread accounts table entry failed (%d-%s)", errno, strerror( errno ) ));
      free(entries);
      return 0;
    }
    entries[i].acc_coff = entries[i].entry.acc_coff;
    entries[i].is_last_occurrence = 1;
  }

  for( ulong i=0UL; i < meta->account_table_cnt; i++ ) {
    for( ulong j=i+1UL; j < meta->account_table_cnt; j++ ) {
      if( memcmp(entries[i].entry.key, entries[j].entry.key, sizeof(entries[i].entry.key)) == 0 ) {
        entries[i].is_last_occurrence = 0;
        break;
      }
    }
  }

  for( ulong i=0UL; i < meta->account_table_cnt; i++ ) {
    if( !entries[i].is_last_occurrence && !show_duplicate_accounts ) {
      continue;
    }

    /* Write to YAML */

    printf(
      "    - pubkey:   '%s'\n"
      "      hash:     '%s'\n"
      "      explorer: 'https://explorer.solana.com/block/%lu?accountFilter=%s&filter=all'\n",
      FD_BASE58_ENC_32_ALLOCA( entries[i].entry.key ),
      FD_BASE58_ENC_32_ALLOCA( entries[i].entry.hash ),
      slot,
      FD_BASE58_ENC_32_ALLOCA( entries[i].entry.key ) );

    /* Fetch account details */

    if( verbose > 3 ) {
      long acc_goff = (long)pos + entries[i].acc_coff;
      if( FD_UNLIKELY( !process_account( file, acc_goff, verbose ) ) ) {
        FD_LOG_ERR(( "process_account() failed" ));
        free(entries);
        return 0;
      }
    }

  } /* end for */

  free(entries);

  /* Restore cursor */

  if( FD_UNLIKELY( 0!=fseek( file, pos, SEEK_SET ) ) ) {
    FD_LOG_ERR(( "fseek failed (%d-%s)", errno, strerror( errno ) ));
    return 0;
  }

  return 0;
}

/* process_bank reads and dumps a bank chunk.  If verbose>1, also
   processes account table.  Returns errno (0 on success).  Stream
   cursor is undefined on return. */

static int
process_bank( fd_solcap_chunk_t const * chunk,
              FILE *                    file,
              int                       verbose,
              int                       show_duplicate_accounts,
              long                      chunk_gaddr,
              ulong                     start_slot,
              ulong                     end_slot,
              int                       has_txns ) {

# define FD_SOLCAP_BANK_PREIMAGE_FOOTPRINT (512UL)
  if( FD_UNLIKELY( chunk->meta_sz > FD_SOLCAP_BANK_PREIMAGE_FOOTPRINT ) ) {
    FD_LOG_ERR(( "invalid bank preimage meta size (%u)", chunk->meta_sz ));
    return ENOMEM;
  }

  /* Read bank preimage meta */

  uchar meta_buf[ 512UL ];
  if( FD_UNLIKELY( 0!=fseek( file, chunk_gaddr + (long)chunk->meta_coff, SEEK_SET ) ) ) {
    FD_LOG_ERR(( "fseek bank preimage meta failed (%d-%s)", errno, strerror( errno ) ));
    return errno;
  }
  if( FD_UNLIKELY( chunk->meta_sz != fread( meta_buf, 1UL, chunk->meta_sz, file ) ) ) {
    FD_LOG_ERR(( "fread bank preimage meta failed (%d-%s)", errno, strerror( errno ) ));
    return errno;
  }

  /* Deserialize bank preimage meta */

  pb_istream_t stream = pb_istream_from_buffer( meta_buf, chunk->meta_sz );

  fd_solcap_BankPreimage meta;
  if( FD_UNLIKELY( !pb_decode( &stream, fd_solcap_BankPreimage_fields, &meta ) ) ) {
    FD_LOG_HEXDUMP_DEBUG(( "bank preimage meta", meta_buf, chunk->meta_sz ));
    FD_LOG_ERR(( "pb_decode bank preimage meta failed (%s)", PB_GET_ERROR(&stream) ));
    return EPROTO;
  }

  if ( meta.slot < start_slot || meta.slot > end_slot ) {
    return 0;
  }

  /* Write YAML */
  if ( verbose < 3 || !has_txns )
    printf( "- slot: %lu\n", meta.slot );

  printf(
      "  - bank_hash:                 '%s'\n",
      FD_BASE58_ENC_32_ALLOCA( meta.bank_hash ) );

  if( verbose>=1 ) {
    printf(
      "  - prev_bank_hash:            '%s'\n"
      "  - account_delta_hash:        '%s'\n"
      "  - accounts_lt_hash_checksum: '%s'\n"
      "  - poh_hash:                  '%s'\n"
      "  - signature_cnt:             %lu\n",
      FD_BASE58_ENC_32_ALLOCA( meta.prev_bank_hash ),
      FD_BASE58_ENC_32_ALLOCA( meta.account_delta_hash ),
      FD_BASE58_ENC_32_ALLOCA( meta.accounts_lt_hash_checksum ),
      FD_BASE58_ENC_32_ALLOCA( meta.poh_hash ),
      meta.signature_cnt );
  }

  /* Accounts */

  if( verbose >= 2 ) {
    if( meta.account_table_coff==0L ) {
      if( meta.account_cnt > 0UL )
        FD_LOG_WARNING(( "Capture does not include account info for slot=%lu", meta.slot ));
      return 0;
    }

    if( FD_UNLIKELY( 0!=fseek( file, chunk_gaddr + (long)meta.account_table_coff, SEEK_SET ) ) ) {
      FD_LOG_ERR(( "fseek to account table failed (%d-%s)", errno, strerror( errno ) ));
      return errno;
    }

    printf( "  - accounts_delta:\n" );
    if( FD_UNLIKELY( 0!=process_account_table( file, meta.slot, verbose, show_duplicate_accounts ) ) )
      return errno;
  }

  return 0;
}

static ulong
process_txn( fd_solcap_chunk_t const * chunk,
             FILE *                    file,
             int                       verbose,
             long                      chunk_gaddr,
             ulong                     prev_slot,
             ulong                     start_slot,
             ulong                     end_slot ) {

if ( verbose < 3 )
  return 0;

# define FD_SOLCAP_TRANSACTION_FOOTPRINT (128UL)
  if( FD_UNLIKELY( chunk->meta_sz > FD_SOLCAP_TRANSACTION_FOOTPRINT ) ) {
    FD_LOG_ERR(( "invalid transaction meta size (%u)", chunk->meta_sz ));
  }

  /* Read transaction meta */

  uchar meta_buf[ 128UL ];
  if( FD_UNLIKELY( 0!=fseek( file, chunk_gaddr + (long)chunk->meta_coff, SEEK_SET ) ) ) {
    FD_LOG_ERR(( "fseek transaction meta failed (%d-%s)", errno, strerror( errno ) ));
  }
  if( FD_UNLIKELY( chunk->meta_sz != fread( meta_buf, 1UL, chunk->meta_sz, file ) ) ) {
    FD_LOG_ERR(( "fread transaction meta failed (%d-%s)", errno, strerror( errno ) ));
  }

  /* Deserialize transaction meta */

  pb_istream_t stream = pb_istream_from_buffer( meta_buf, chunk->meta_sz );

  fd_solcap_Transaction meta;
  if( FD_UNLIKELY( !pb_decode( &stream, fd_solcap_Transaction_fields, &meta ) ) ) {
    FD_LOG_HEXDUMP_DEBUG(( "transaction meta", meta_buf, chunk->meta_sz ));
    FD_LOG_ERR(( "pb_decode transaction meta failed (%s)", PB_GET_ERROR(&stream) ));
  }

  if ( meta.slot < start_slot || meta.slot > end_slot ) {
    return meta.slot;
  }

  /* Write YAML */
  if ( prev_slot == 0 || prev_slot != meta.slot ) {
    printf(
      "- slot: %lu\n"
      "  - txns:\n", meta.slot
    );
  }

  printf(
    "    - txn_sig:        '%s'\n"
    "      txn_err:         %d\n"
    "      cus_used:        %lu\n"
    "      instr_err_idx:   %d\n",
    FD_BASE58_ENC_64_ALLOCA( meta.txn_sig ),
    meta.fd_txn_err,
    meta.fd_cus_used,
    meta.instr_err_idx);

  /* Only print custom error if it has been set*/
  if ( meta.fd_txn_err == FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR) {
    printf( "      custom_err:      %u\n", meta.fd_custom_err );
  }

  if ( verbose < 4 )
    return meta.slot;

  if ( meta.solana_txn_err != ULONG_MAX || meta.solana_cus_used != ULONG_MAX ) {
    printf(
      "      solana_txn_err:  %lu\n"
      "      solana_cus_used: %lu\n",
      meta.solana_txn_err,
      meta.solana_cus_used );
  }

  printf(
    "      explorer:       'https://explorer.solana.com/tx/%s'\n"
    "      solscan:        'https://solscan.io/tx/%s'\n"
    "      solanafm:       'https://solana.fm/tx/%s'\n",
    FD_BASE58_ENC_64_ALLOCA( meta.txn_sig ),
    FD_BASE58_ENC_64_ALLOCA( meta.txn_sig ),
    FD_BASE58_ENC_64_ALLOCA( meta.txn_sig ) );

  return meta.slot;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* Command line handling */

  for( int i=1; i<argc; i++ )
    if( 0==strcmp( argv[i], "--help" ) ) return usage();

  int   verbose                 = fd_env_strip_cmdline_int     ( &argc, &argv, "-v",           NULL, 0         );
  int   show_duplicate_accounts = fd_env_strip_cmdline_contains( &argc, &argv, "--show-duplicate-accounts"     );
  ulong start_slot              = fd_env_strip_cmdline_ulong   ( &argc, &argv, "--start-slot", NULL, 0         );
  ulong end_slot                = fd_env_strip_cmdline_ulong   ( &argc, &argv, "--end-slot",   NULL, ULONG_MAX );

  if( argc!=2 ) {
    fprintf( stderr, "ERROR: expected 1 argument, got %d\n", argc-1 );
    usage();
    return 1;
  }

  /* Open file */

  char const * path = argv[ 1 ];
  FILE * file = fopen( path, "rb" );
  if( FD_UNLIKELY( !file ) )
    FD_LOG_ERR(( "fopen(%s) failed (%d-%s)", path, errno, strerror( errno ) ));

  /* Read file header */

  fd_solcap_fhdr_t fhdr[1];
  ulong n = fread( fhdr, sizeof(fd_solcap_fhdr_t), 1UL, file );
  if( FD_UNLIKELY( n!=1UL ) ) {
    FD_LOG_ERR(( "fread file header failed (%d-%s)", errno, strerror( errno ) ));
    return errno;
  }

  /* TODO Read file meta */

  /* Seek to first chunk */

  int err = fseek( file, (long)fhdr->chunk0_foff - (long)sizeof(fd_solcap_fhdr_t), SEEK_CUR );
  if( FD_UNLIKELY( err<0L ) ) {
    FD_LOG_ERR(( "fseek chunk0 failed (%d-%s)", errno, strerror( errno ) ));
    return errno;
  }

  /* Read chunks */

  fd_solcap_chunk_iter_t iter[1];
  fd_solcap_chunk_iter_new( iter, file );
  ulong previous_slot = 0;
  /* TODO replace this with fd_solcap_chunk_iter_find */
  for(;;) {
    long chunk_gaddr = fd_solcap_chunk_iter_next( iter );
    if( FD_UNLIKELY( chunk_gaddr<0L ) ) {
      int err = fd_solcap_chunk_iter_err( iter );
      if( err==0 ) break;
      FD_LOG_ERR(( "fd_solcap_chunk_iter_next() failed (%d-%s)", err, strerror( err ) ));
    }

    if( fd_solcap_chunk_iter_done( iter ) ) break;

    fd_solcap_chunk_t const * chunk = fd_solcap_chunk_iter_item( iter );
    if( FD_UNLIKELY( !chunk ) ) FD_LOG_ERR(( "fd_solcap_chunk_item() failed" ));

    /* TODO: figure out how to make solana.solcap yamls print slot */
    if( chunk->magic == FD_SOLCAP_V1_BANK_MAGIC )
      process_bank( chunk, file, verbose, show_duplicate_accounts, chunk_gaddr, start_slot, end_slot, previous_slot != 0 );
    else if ( chunk->magic == FD_SOLCAP_V1_TRXN_MAGIC )
      previous_slot = process_txn( chunk, file, verbose, chunk_gaddr, previous_slot, start_slot, end_slot );
  }

  /* Cleanup */

  FD_LOG_NOTICE(( "Done" ));
  fclose( file );
  fd_halt();
  return 0;
}
