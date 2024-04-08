#include "../fd_flamenco.h"
#include "fd_solcap_proto.h"
#include "fd_solcap_reader.h"
#include "fd_solcap.pb.h"
#include "../../ballet/base58/fd_base58.h"
#include "../runtime/fd_runtime.h"
#include "../types/fd_types_yaml.h"

#include <errno.h>
#include <stdio.h>
#include <sys/stat.h> /* mkdir(2) */
#include <fcntl.h>    /* open(2) */
#include <unistd.h>   /* close(2) */


/* TODO: Ugly -- These should not be hard coded! */

static const uchar
_vote_program_address[ 32 ] =
  "\x07\x61\x48\x1d\x35\x74\x74\xbb\x7c\x4d\x76\x24\xeb\xd3\xbd\xb3"
  "\xd8\x35\x5e\x73\xd1\x10\x43\xfc\x0d\xa3\x53\x80\x00\x00\x00\x00";

static const uchar
_stake_program_address[ 32 ] =
  "\x06\xa1\xd8\x17\x91\x37\x54\x2a\x98\x34\x37\xbd\xfe\x2a\x7a\xb2"
  "\x55\x7f\x53\x5c\x8a\x78\x72\x2b\x68\xa4\x9d\xc0\x00\x00\x00\x00";

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

  int          verbose;
  int          dump_dir_fd;
  char const * dump_dir;
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

    ulong idx = slot0>slot1;
    int res = fd_solcap_differ_advance( diff, idx );
    if( FD_UNLIKELY( res<=0 ) ) return res;
  }

  return 0;
}

static int
fd_solcap_can_pretty_print( uchar const owner [ static 32 ],
                            uchar const pubkey[ static 32 ] ) {

  /* TODO clean up */
  uchar _sysvar_clock[ 32 ];
  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111", _sysvar_clock );
  uchar _sysvar_rent[ 32 ];
  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111", _sysvar_rent );
  uchar _sysvar_epoch_rewards[ 32 ];
  fd_base58_decode_32( "SysvarEpochRewards1111111111111111111111111", _sysvar_epoch_rewards );
  uchar _sysvar_stake_history[ 32 ];
  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111", _sysvar_stake_history );

  if( 0==memcmp( owner, _vote_program_address, 32UL ) )
    return 1;
  if( 0==memcmp( owner, _stake_program_address, 32UL ) )
    return 1;

  if( 0==memcmp( pubkey, _sysvar_clock, 32UL ) )
    return 1;
  if( 0==memcmp( pubkey, _sysvar_rent, 32UL ) )
    return 1;
  if( 0==memcmp( pubkey, _sysvar_epoch_rewards, 32UL ) )
    return 1;
  if( 0==memcmp( pubkey, _sysvar_stake_history, 32UL ) )
    return 1;
  return 0;
}

static int
fd_solcap_account_pretty_print( uchar const   pubkey[ static 32 ],
                                uchar const   owner[ static 32 ],
                                uchar const * data,
                                ulong         data_sz,
  FILE *        file ) {

  FD_SCRATCH_SCOPE_BEGIN {

    fd_bincode_decode_ctx_t decode = {
      .data    = data,
      .dataend = data + data_sz,
      .valloc  = fd_scratch_virtual()
    };

    fd_flamenco_yaml_t * yaml =
      fd_flamenco_yaml_init( fd_flamenco_yaml_new(
          fd_scratch_alloc( fd_flamenco_yaml_align(), fd_flamenco_yaml_footprint() ) ),
        file );
    FD_TEST( yaml );

    /* TODO clean up */
    uchar _sysvar_clock[ 32 ];
    fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111", _sysvar_clock );
    uchar _sysvar_rent[ 32 ];
    fd_base58_decode_32( "SysvarRent111111111111111111111111111111111", _sysvar_rent );
    uchar _sysvar_epoch_rewards[ 32 ];
    fd_base58_decode_32( "SysvarEpochRewards1111111111111111111111111", _sysvar_epoch_rewards );
    uchar _sysvar_stake_history[ 32 ];
    fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111", _sysvar_stake_history );

    if( 0==memcmp( owner, _vote_program_address, 32UL ) ) {
      fd_vote_state_versioned_t vote_state[1];
      int err = fd_vote_state_versioned_decode( vote_state, &decode );
      if( FD_UNLIKELY( err!=0 ) ) return err;

      fd_vote_state_versioned_walk( yaml, vote_state, fd_flamenco_yaml_walk, NULL, 0U );
    } else if( 0==memcmp( owner, _stake_program_address, 32UL ) ) {
      fd_stake_state_v2_t stake_state[1];
      int err = fd_stake_state_v2_decode( stake_state, &decode );
      if( FD_UNLIKELY( err!=0 ) ) return err;

      fd_stake_state_v2_walk( yaml, stake_state, fd_flamenco_yaml_walk, NULL, 0U );
    } else if( 0==memcmp( pubkey, _sysvar_clock, 32UL ) ) {
      fd_sol_sysvar_clock_t clock[1];
      int err = fd_sol_sysvar_clock_decode( clock, &decode );
      if( FD_UNLIKELY( err!=0 ) ) return err;

      fd_sol_sysvar_clock_walk( yaml, clock, fd_flamenco_yaml_walk, NULL, 0U );
    } else if( 0==memcmp( pubkey, _sysvar_rent, 32UL ) ) {
      fd_rent_t rent[1];
      int err = fd_rent_decode( rent, &decode );
      if( FD_UNLIKELY( err!=0 ) ) return err;

      fd_rent_walk( yaml, rent, fd_flamenco_yaml_walk, NULL, 0U );
    } else if( 0==memcmp( pubkey, _sysvar_epoch_rewards, 32UL ) ) {
      fd_sysvar_epoch_rewards_t epoch_rewards[1];
      int err = fd_sysvar_epoch_rewards_decode( epoch_rewards, &decode );
      if( FD_UNLIKELY( err!=0 ) ) return err;

      fd_sysvar_epoch_rewards_walk( yaml, epoch_rewards, fd_flamenco_yaml_walk, NULL, 0U );
    } else if( 0==memcmp( pubkey, _sysvar_stake_history, 32UL ) ) {
      fd_stake_history_t stake_history[1];
      int err = fd_stake_history_decode( stake_history, &decode );
      if( FD_UNLIKELY( err!=0 ) ) return err;

      fd_stake_history_walk( yaml, stake_history, fd_flamenco_yaml_walk, NULL, 0U );
    }

    int err = ferror( file );
    if( FD_UNLIKELY( err!=0 ) ) return err;

    /* No need to destroy structures, using fd_scratch allocator */

    fd_flamenco_yaml_delete( yaml );
    return 0;
  } FD_SCRATCH_SCOPE_END;
}

/* fd_solcap_dump_account_data writes a binary file containing exactly
   the given account's content. */

static void
fd_solcap_dump_account_data( fd_solcap_differ_t *            diff,
                             fd_solcap_AccountMeta const *   meta,
                             fd_solcap_account_tbl_t const * entry,
                             void const *                    acc_data ) {
  /* Create dump file */
  char path[ FD_BASE58_ENCODED_32_LEN+1+FD_BASE58_ENCODED_32_LEN+4+1 ];
  int res = snprintf( path, sizeof(path), "%32J-%32J.bin", entry->key, entry->hash );
  FD_TEST( (res>0) & (res<(int)sizeof(path)) );
  int fd = openat( diff->dump_dir_fd, path, O_CREAT|O_WRONLY|O_TRUNC, 0666 );
  if( FD_UNLIKELY( fd<0 ) )
    FD_LOG_ERR(( "openat(%d,%s) failed (%d-%s)",
                diff->dump_dir_fd, path, errno, strerror( errno ) ));

  /* Write dump file */
  FILE * file = fdopen( fd, "wb" );
  FD_TEST( meta->data_sz == fwrite( acc_data, 1UL, meta->data_sz, file ) );
  fclose( file );  /* Closes fd */
}

static void
fd_solcap_diff_account_data( fd_solcap_differ_t *                  diff,
                             fd_solcap_AccountMeta   const         meta     [ static 2 ],
                             fd_solcap_account_tbl_t const * const entry    [ static 2 ],
                             ulong const                           data_goff[ static 2 ] ) {

  /* Streaming diff */
  int data_eq = meta[0].data_sz == meta[1].data_sz;
  if( data_eq ) {
    for( ulong i=0UL; i<2UL; i++ )
      FD_TEST( 0==fseek( diff->iter[ i ].stream, (long)data_goff[i], SEEK_SET ) );

    for( ulong off=0UL; off<meta[0].data_sz; ) {
#     define BUFSZ (512UL)

      /* Read chunks */
      uchar buf[2][ BUFSZ ];
      ulong sz = fd_ulong_min( BUFSZ, meta[0].data_sz-off );
      for( ulong i=0UL; i<2UL; i++ )
        FD_TEST( sz==fread( &buf[i], 1UL, sz, diff->iter[i].stream ) );

      /* Compare chunks */
      data_eq = 0==memcmp( buf[0], buf[1], sz );
      if( !data_eq ) break;

      off += sz;
#     undef BUFSZ
    }
  }
  if( data_eq ) return;

  /* Dump account data to file */
  if( diff->verbose >= 4 ) {

    /* TODO: Remove hardcoded account size check */
    FD_TEST( meta[0].data_sz <= 1048576 );
    FD_TEST( meta[1].data_sz <= 1048576 );

    FD_SCRATCH_SCOPE_BEGIN {
      void * acc_data[2];
      acc_data[0] = fd_scratch_alloc( 1UL, meta[0].data_sz );
      acc_data[1] = fd_scratch_alloc( 1UL, meta[1].data_sz );

      for( ulong i=0UL; i<2UL; i++ ) {
        /* Rewind capture stream */
        FD_TEST( 0==fseek( diff->iter[ i ].stream, (long)data_goff[i], SEEK_SET ) );

        /* Copy data */
        FD_TEST( meta[i].data_sz == fread( acc_data[i], 1UL, meta[i].data_sz, diff->iter[i].stream ) );
      }

      for( ulong i=0; i<2; i++ ) {
        fd_solcap_dump_account_data( diff, meta+i, entry[i], acc_data[i] );
      }

      /* Inform user */
      printf( "    -data:       %s/%32J-%32J.bin\n"
        "    +data:       %s/%32J-%32J.bin\n"
        "                 vimdiff <(xxd '%s/%32J-%32J.bin') <(xxd '%s/%32J-%32J.bin')\n",
        diff->dump_dir, entry[0]->key, entry[0]->hash,
        diff->dump_dir, entry[1]->key, entry[1]->hash,
        diff->dump_dir, entry[0]->key, entry[0]->hash,
        diff->dump_dir, entry[1]->key, entry[1]->hash );

      if( fd_solcap_can_pretty_print( meta[0].owner, entry[0]->key )
        & fd_solcap_can_pretty_print( meta[1].owner, entry[1]->key ) ) {

        for( ulong i=0UL; i<2UL; i++ ) {
          /* Create YAML file */
          char path[ FD_BASE58_ENCODED_32_LEN+1+FD_BASE58_ENCODED_32_LEN+4+1 ];
          int res = snprintf( path, sizeof(path), "%32J-%32J.yml", entry[i]->key, entry[i]->hash );
          FD_TEST( (res>0) & (res<(int)sizeof(path)) );
          int fd = openat( diff->dump_dir_fd, path, O_CREAT|O_WRONLY|O_TRUNC, 0666 );
          if( FD_UNLIKELY( fd<0 ) )
            FD_LOG_ERR(( "openat(%d,%s) failed (%d-%s)",
                diff->dump_dir_fd, path, errno, strerror( errno ) ));

          /* Write YAML file */
          FILE * file = fdopen( fd, "wb" );
          fd_solcap_account_pretty_print( entry[i]->key, meta[i].owner, acc_data[i], meta[i].data_sz, file );
          fclose( file );  /* closes fd */
        }


        /* Inform user */
        printf( "                 vimdiff '%s/%32J-%32J.yml' '%s/%32J-%32J.yml'\n",
          diff->dump_dir, entry[0]->key, entry[0]->hash,
          diff->dump_dir, entry[1]->key, entry[1]->hash );

      }
    } FD_SCRATCH_SCOPE_END;
  }
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
  ulong                 data_goff[2];
  for( ulong i=0UL; i<2UL; i++ ) {
    FILE * stream = diff->iter[ i ].stream;
    int err = fd_solcap_find_account( stream, meta+i, &data_goff[i], entry[i], acc_tbl_goff[i] );
    FD_TEST( err==0 );
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
  else
    printf( "     owner:      %32J\n", meta[0].owner );
    /* Even if the owner matches, still print it for convenience */
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
  if( meta[0].executable != meta[1].executable )
    printf( "    -executable: %d\n"
            "    +executable: %d\n",
            meta[0].executable,
            meta[1].executable );
  if( ( (meta[0].data_sz == 0UL) | fd_solcap_includes_account_data( &meta[0] ) )
    & ( (meta[1].data_sz == 0UL) | fd_solcap_includes_account_data( &meta[1] ) ) )
        fd_solcap_diff_account_data( diff, meta, entry, data_goff );

  /* Restore file offsets */
  for( ulong i=0UL; i<2UL; i++ ) {
    if( FD_UNLIKELY( 0!=fseek( diff->iter[ i ].stream, orig_off[ i ], SEEK_SET ) ) )
      FD_LOG_ERR(( "fseek failed (%d-%s)", errno, strerror( errno ) ));
  }
}

/* fd_solcap_diff_missing_account is like fd_solcap_diff_account but in
   the case that either side of the account is missing entirely. */

static void
fd_solcap_diff_missing_account( fd_solcap_differ_t *                  diff,
                                fd_solcap_account_tbl_t const * const entry,
                                ulong                           const acc_tbl_goff,
                                FILE *                                stream,
                                int                                   prefix ) {

  /* Remember current file offset */
  long orig_off = ftell( stream );
  if( FD_UNLIKELY( orig_off<0L ) )
    FD_LOG_ERR(( "ftell failed (%d-%s)", errno, strerror( errno ) ));

  /* Read account meta */
  fd_solcap_AccountMeta meta[1];
  ulong                 data_goff[1];
  int err = fd_solcap_find_account( stream, meta, data_goff, entry, acc_tbl_goff );
  FD_TEST( err==0 );

  printf( "    %clamports:   %lu\n",
          prefix, meta->lamports );
  printf( "    %cdata_sz:    %lu\n",
          prefix, meta->data_sz );
  printf( "    %cowner:      %32J\n",
          prefix, meta->owner );
  printf( "    %cslot:       %lu\n",
          prefix, meta->slot );
  printf( "    %crent_epoch: %lu\n",
          prefix, meta->rent_epoch );
  printf( "    %cexecutable: %d\n",
          prefix, meta->executable );

  /* Dump account data to file */
  if( diff->verbose >= 4 ) {

    /* TODO: Remove hardcoded account size check */
    FD_TEST( meta->data_sz <= 1048576 );

    FD_SCRATCH_SCOPE_BEGIN {
      void * acc_data = fd_scratch_alloc( 1UL, meta->data_sz );

      /* Rewind capture stream */
      FD_TEST( 0==fseek(stream, (long)*data_goff, SEEK_SET ) );

      /* Copy data */
      FD_TEST( meta->data_sz == fread( acc_data, 1UL, meta->data_sz, stream ) );

      fd_solcap_dump_account_data( diff, meta, entry, acc_data );

      /* Inform user */
      printf( "    %cdata:       %s/%32J-%32J.bin\n"
        "                 xxd '%s/%32J-%32J.bin'\n",
        prefix,
        diff->dump_dir, entry->key, entry->hash,
        diff->dump_dir, entry->key, entry->hash );

      if( fd_solcap_can_pretty_print( meta->owner, entry->key ) ) {
        /* Create YAML file */
        char path[ FD_BASE58_ENCODED_32_LEN+1+FD_BASE58_ENCODED_32_LEN+4+1 ];
        int res = snprintf( path, sizeof(path), "%32J-%32J.yml", entry->key, entry->hash );
        FD_TEST( (res>0) & (res<(int)sizeof(path)) );
        int fd = openat( diff->dump_dir_fd, path, O_CREAT|O_WRONLY|O_TRUNC, 0666 );
        if( FD_UNLIKELY( fd<0 ) )
          FD_LOG_ERR(( "openat(%d,%s) failed (%d-%s)",
              diff->dump_dir_fd, path, errno, strerror( errno ) ));

        /* Write YAML file */
        FILE * file = fdopen( fd, "wb" );
        fd_solcap_account_pretty_print( entry->key, meta->owner, acc_data, meta->data_sz, file );
        fclose( file );  /* closes fd */

        /* Inform user */
        printf( "                 cat '%s/%32J-%32J.yml'\n",
          diff->dump_dir, entry->key, entry->hash,
          diff->dump_dir, entry->key, entry->hash );
      }
    } FD_SCRATCH_SCOPE_END;
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
      if( diff->verbose >= 3 )
        fd_solcap_diff_missing_account( diff, tbl[0], chunk_goff[0], diff->iter[0].stream, '-' );
      tbl[0]++;
      continue;
    }

    if( key_cmp>0 ) {
      printf( "  +account: %32J\n", b->key );
      if( diff->verbose >= 3 )
        fd_solcap_diff_missing_account( diff, tbl[1], chunk_goff[1], diff->iter[1].stream, '+' );
      tbl[1]++;
      continue;
    }
  }
  while( tbl[0]!=tbl_end[0] ) {
    printf( "  -account: %32J\n", tbl[0]->key );
    if( diff->verbose >= 3 )
      fd_solcap_diff_missing_account( diff, tbl[0], chunk_goff[0], diff->iter[0].stream, '-' );
    tbl[0]++;
  }
  while( tbl[1]!=tbl_end[1] ) {
    printf( "  +account: %32J\n", tbl[1]->key );
    if( diff->verbose >= 3 )
      fd_solcap_diff_missing_account( diff, tbl[1], chunk_goff[1], diff->iter[1].stream, '+' );
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
  char const * dump_dir   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--dump-dir",   NULL, "dump"     );

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

  /* Create dump dir */

  if( mkdir( dump_dir, 0777 )<0 && errno!=EEXIST )
    FD_LOG_ERR(( "mkdir failed (%d-%s)", errno, strerror( errno ) ));
  int dump_dir_fd = open( dump_dir, O_DIRECTORY );
  if( FD_UNLIKELY( dump_dir_fd<0 ) )
    FD_LOG_ERR(( "open(%s) failed (%d-%s)", dump_dir, errno, strerror( errno ) ));

  /* Create differ */

  fd_solcap_differ_t diff[1];
  if( FD_UNLIKELY( !fd_solcap_differ_new( diff, cap_file ) ) )
    return 1;
  diff->verbose     = verbose;
  diff->dump_dir    = dump_dir;
  diff->dump_dir_fd = dump_dir_fd;
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

  close( dump_dir_fd );
  fclose( cap_file[1] );
  fclose( cap_file[0] );
  FD_TEST( fd_scratch_frame_used()==0UL );
  fd_wksp_free_laddr( fd_scratch_detach( NULL ) );
  fd_flamenco_halt();
  fd_halt();
  return 0;
}
