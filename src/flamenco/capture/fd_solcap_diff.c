#include "../fd_flamenco.h"
#include "fd_solcap_proto.h"
#include "fd_solcap_reader.h"
#include "fd_solcap.pb.h"
#include "../../ballet/base58/fd_base58.h"
#include "../runtime/fd_runtime.h"
#include "../types/fd_types.h"
#include "../types/fd_types_yaml.h"
#include "../nanopb/pb_decode.h"

#include <errno.h>
#include <stdio.h>
#include <sys/stat.h> /* mkdir(2) */
#include <fcntl.h>    /* open(2) */
#include <unistd.h>   /* close(2) */

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"

/* TODO: Ugly -- These should not be hard coded! */
#define SOLCAP_FILE_NAME_LEN (13UL)
#define SOLCAP_SUFFIX_LEN    (7UL) /* .solcap */

static const uchar
_vote_program_address[ 32 ] =
  "\x07\x61\x48\x1d\x35\x74\x74\xbb\x7c\x4d\x76\x24\xeb\xd3\xbd\xb3"
  "\xd8\x35\x5e\x73\xd1\x10\x43\xfc\x0d\xa3\x53\x80\x00\x00\x00\x00";

static const uchar
_stake_program_address[ 32 ] =
  "\x06\xa1\xd8\x17\x91\x37\x54\x2a\x98\x34\x37\xbd\xfe\x2a\x7a\xb2"
  "\x55\x7f\x53\x5c\x8a\x78\x72\x2b\x68\xa4\x9d\xc0\x00\x00\x00\x00";

static void
normalize_filename( const char * original_str, char * file_name, char prefix ) {
  /* We either need to truncate if too long or pad if too short (16 chars) */

  file_name[0] = prefix;
  ulong original_str_len = strlen( original_str ) - SOLCAP_SUFFIX_LEN + 1;
  if ( original_str_len <= SOLCAP_FILE_NAME_LEN ) {
    fd_memcpy( file_name + 1, original_str, original_str_len );
    for ( ulong i = original_str_len; i < SOLCAP_FILE_NAME_LEN; i++ ) {
      file_name[ i ] = ' ';
    }
  }
  else {
    ulong start_idx = original_str_len - SOLCAP_FILE_NAME_LEN;
    fd_memcpy( file_name + 1, original_str + start_idx, SOLCAP_FILE_NAME_LEN );

  }
  file_name[ SOLCAP_FILE_NAME_LEN ] = '\0';
}

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
        sense to move/copy it to fd_ledger.  Doing so would enable
        a fast feedback cycle wherein a developer supplies the expected
        (Labs) capture to fd_ledger, then automatically runs the
        differ after each execution. */

struct fd_solcap_differ {
  fd_solcap_chunk_iter_t iter    [2];
  fd_solcap_BankPreimage preimage[2];

  int          verbose;
  int          dump_dir_fd;
  char const * dump_dir;
  char const * file_paths[2];
};

typedef struct fd_solcap_differ fd_solcap_differ_t;

struct fd_solcap_txn_differ {
  FILE * file[2];
  fd_solcap_chunk_iter_t iter[2];
  long chunk_gaddr[2];
  fd_solcap_Transaction transaction[2];
  uchar meta_buf[128][2];
};

typedef struct fd_solcap_txn_differ fd_solcap_txn_differ_t;

static fd_solcap_differ_t *
fd_solcap_differ_new( fd_solcap_differ_t * diff,
                      FILE *               streams[2],
                      const char *         cap_path[2] ) {

  /* Attach to capture files */

  for( ulong i=0UL; i<2UL; i++ ) {
    FILE * stream = streams[i];

    /* Set file names */
    diff->file_paths[i] = cap_path[i];

    /* Read file header */
    fd_solcap_fhdr_t hdr[1];
    if( FD_UNLIKELY( 1UL!=fread( hdr, sizeof(fd_solcap_fhdr_t), 1UL, stream ) ) ) {
      FD_LOG_WARNING(( "Failed to read file=%s header (%d-%s)",
                       diff->file_paths[i], errno, strerror( errno ) ));
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
fd_solcap_differ_sync( fd_solcap_differ_t * diff, ulong start_slot, ulong end_slot ) {

  /* Seek to first bank preimage object */

  for( ulong i=0UL; i<2UL; i++ ) {
    int res = fd_solcap_differ_advance( diff, i );
    if( FD_UNLIKELY( res!=1 ) ) return res;
  }

  ulong prev_slot0 = diff->preimage[ 0 ].slot;
  ulong prev_slot1 = diff->preimage[ 1 ].slot;

  for(;;) {
    ulong slot0 = diff->preimage[ 0 ].slot;
    ulong slot1 = diff->preimage[ 1 ].slot;

    /* Handle cases where slot is skipped in one or the other */
    if ( FD_UNLIKELY( prev_slot0 < slot1 && slot0 > slot1 ) ) {
      FD_LOG_WARNING(("Slot range (%lu,%lu) skipped in file=%s\n",
                      diff->file_paths[0], prev_slot0, slot0));
    }
    else if ( FD_UNLIKELY( prev_slot1 < slot0 && slot1 > slot0 ) ) {
      FD_LOG_WARNING(("Slot range (%lu,%lu) skipped in file=%s\n",
                      diff->file_paths[1], prev_slot1, slot1));
    }

    if( slot0 == slot1 ) {
      if ( slot0 < start_slot ) {
        int res;
        res = fd_solcap_differ_advance( diff, 0 );
        if( FD_UNLIKELY( res <= 0 ) ) return res;
        res = fd_solcap_differ_advance( diff, 1 );
        if( FD_UNLIKELY( res <= 0 ) ) return res;
      }
      else if ( slot0 > end_slot ) {
        return 0;
      }
      else {
        return 1;
      }
    }
    else {
      ulong idx = slot0>slot1;
      int res = fd_solcap_differ_advance( diff, idx );
      if( FD_UNLIKELY( res<=0 ) ) return res;
    }
    prev_slot0 = slot0;
    prev_slot1 = slot1;
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
                             ulong const                           data_goff[ static 2 ] ) {\

  /* Streaming diff */
  int data_eq = meta[0].data_sz == meta[1].data_sz;
  if( data_eq ) {
    for( ulong i=0UL; i<2UL; i++ ) {
        if ( data_goff[i] == ULONG_MAX ) {
          continue;
        }
        FD_TEST( 0==fseek( diff->iter[ i ].stream, (long)data_goff[i], SEEK_SET ) );
    }

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
      fd_memset( acc_data[0], 0, meta[0].data_sz );
      fd_memset( acc_data[1], 0, meta[1].data_sz );

      for( ulong i=0UL; i<2UL; i++ ) {
        if ( data_goff[i] == ULONG_MAX ) {
          continue;
        }

        /* Rewind capture stream */
        FD_TEST( 0==fseek( diff->iter[ i ].stream, (long)data_goff[i], SEEK_SET ) );

        /* Copy data */
        FD_TEST( meta[i].data_sz == fread( acc_data[i], 1UL, meta[i].data_sz, diff->iter[i].stream ) );
      }

      for( ulong i=0; i<2; i++ ) {
        fd_solcap_dump_account_data( diff, meta+i, entry[i], acc_data[i] );
      }

      /* Inform user */
      printf( "        (%s) data:       %s/%32J-%32J.bin\n"
              "        (%s) data:       %s/%32J-%32J.bin\n"
              "                        vimdiff <(xxd '%s/%32J-%32J.bin') <(xxd '%s/%32J-%32J.bin')\n",
              diff->file_paths[0], diff->dump_dir, entry[0]->key, entry[0]->hash,
              diff->file_paths[1], diff->dump_dir, entry[1]->key, entry[1]->hash,
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
  ulong                 data_goff[2] = {ULONG_MAX, ULONG_MAX};
  for( ulong i=0UL; i<2UL; i++ ) {
    FILE * stream = diff->iter[ i ].stream;
    int err = fd_solcap_find_account( stream, meta+i, &data_goff[i], entry[i], acc_tbl_goff[i] );
    FD_TEST( err==0 );
  }
  if( 0!=memcmp( meta[0].owner, meta[1].owner, 32UL ) )
    printf( "%s        (%s)  owner:       %32J\n"
            "%s        (%s)  owner:       %32J\n%s",
            diff->file_paths[0], meta[0].owner,
            diff->file_paths[1], meta[1].owner );
  else
    printf( "        (both files   )  owner:      %32J\n", meta[0].owner );
    /* Even if the owner matches, still print it for convenience */
  if( meta[0].lamports != meta[1].lamports )
    printf( "        (%s)  lamports:   %lu\n"
            "        (%s)  lamports:   %lu\n",
            diff->file_paths[0], meta[0].lamports,
            diff->file_paths[1], meta[1].lamports );
  if( meta[0].data_sz != meta[1].data_sz )
    printf( "        (%s)  data_sz:     %lu\n"
            "        (%s)  data_sz:     %lu\n",
            diff->file_paths[0], meta[0].data_sz,
            diff->file_paths[1], meta[1].data_sz );
  if( meta[0].slot != meta[1].slot )
    printf( "        (%s)  slot:        %lu\n"
            "        (%s)  slot:        %lu\n",
            diff->file_paths[0], meta[0].slot,
            diff->file_paths[1], meta[1].slot );
  if( meta[0].rent_epoch != meta[1].rent_epoch )
    printf( "        (%s)  rent_epoch: %lu\n"
            "        (%s)  rent_epoch: %lu\n",
            diff->file_paths[0], meta[0].rent_epoch,
            diff->file_paths[1], meta[1].rent_epoch );
  if( meta[0].executable != meta[1].executable )
    printf( "        (%s)  executable:  %d\n"
            "        (%s)  executable:  %d\n",
            diff->file_paths[0], meta[0].executable,
            diff->file_paths[1], meta[1].executable );
  if( ( (meta[0].data_sz != 0UL) | fd_solcap_includes_account_data( &meta[0] ) )
    | ( (meta[1].data_sz != 0UL) | fd_solcap_includes_account_data( &meta[1] ) ) )
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
                                FILE *                                stream ) {

  /* Remember current file offset */
  long orig_off = ftell( stream );
  if( FD_UNLIKELY( orig_off<0L ) )
    FD_LOG_ERR(( "ftell failed (%d-%s)", errno, strerror( errno ) ));

  /* Read account meta */
  fd_solcap_AccountMeta meta[1];
  ulong                 data_goff[1];
  int err = fd_solcap_find_account( stream, meta, data_goff, entry, acc_tbl_goff );
  FD_TEST( err==0 );

  printf( "        lamports:   %lu\n",  meta->lamports );
  printf( "        data_sz:    %lu\n",  meta->data_sz );
  printf( "        owner:      %32J\n", meta->owner );
  printf( "        slot:       %lu\n",  meta->slot );
  printf( "        rent_epoch: %lu\n",  meta->rent_epoch );
  printf( "        executable: %d\n",   meta->executable );

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
      printf( "        data:       %s/%32J-%32J.bin\n"
              "               xxd '%s/%32J-%32J.bin'\n",
              diff->dump_dir, entry->key, entry->hash,
              diff->dump_dir, entry->key, entry->hash );
      printf( "        explorer:  'https://explorer.solana.com/block/%lu?accountFilter=%32J&filter=all'",
              meta->slot, entry->key );

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
        printf( "\n    (in both files) account:  %32J\n"
                "        (%s)  hash:       %32J\n"
                "        (%s)  hash:       %32J\n",
                a->key, diff->file_paths[0], a->hash,
                diff->file_paths[1], b->hash );

        if( diff->verbose >= 3 )
          fd_solcap_diff_account( diff, (fd_solcap_account_tbl_t const * const *)tbl, chunk_goff );
      }

      tbl[0]++;
      tbl[1]++;
      continue;
    }

    if( key_cmp<0 ) {
      printf( "\n    (%s) account:  %32J\n", diff->file_paths[0], a->key );
      if( diff->verbose >= 3 )
        fd_solcap_diff_missing_account( diff, tbl[0], chunk_goff[0], diff->iter[0].stream );
      tbl[0]++;
      continue;
    }

    if( key_cmp>0 ) {
      printf( "\n    (%s) account:  %32J\n", diff->file_paths[1],b->key );
      if( diff->verbose >= 3 )
        fd_solcap_diff_missing_account( diff, tbl[1], chunk_goff[1], diff->iter[1].stream );
      tbl[1]++;
      continue;
    }
  }
  while( tbl[0]!=tbl_end[0] ) {
    printf( "\n    (%s) account:  %32J\n", diff->file_paths[0],tbl[0]->key );
    if( diff->verbose >= 3 )
      fd_solcap_diff_missing_account( diff, tbl[0], chunk_goff[0], diff->iter[0].stream );
    tbl[0]++;
  }
  while( tbl[1]!=tbl_end[1] ) {
    printf( "\n    (%s) account:  %32J\n", diff->file_paths[1],tbl[1]->key );
    if( diff->verbose >= 3 )
      fd_solcap_diff_missing_account( diff, tbl[1], chunk_goff[1], diff->iter[1].stream );
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

  printf( "\nbank hash mismatch at slot=%lu\n", pre[0].slot );

  printf( "(%s) bank_hash:  %32J\n"
          "(%s) bank_hash:  %32J\n",
          diff->file_paths[0], pre[0].bank_hash, diff->file_paths[1], pre[1].bank_hash );

  int only_account_mismatch = 0;
  if( 0!=memcmp( pre[0].account_delta_hash, pre[1].account_delta_hash, 32UL ) ) {
    only_account_mismatch = 1;
    printf( "(%s) account_delta_hash:  %32J\n"
            "(%s) account_delta_hash:  %32J\n",
            diff->file_paths[0], pre[0].account_delta_hash,
            diff->file_paths[1], pre[1].account_delta_hash );
  }
  if( 0!=memcmp( pre[0].prev_bank_hash, pre[1].prev_bank_hash, 32UL ) ) {
    only_account_mismatch = 0;
    printf( "(%s) prev_bank_hash:      %32J\n"
            "(%s) prev_bank_hash:      %32J\n",
            diff->file_paths[0], pre[0].prev_bank_hash,
            diff->file_paths[1], pre[1].prev_bank_hash );
  }
  if( 0!=memcmp( pre[0].poh_hash, pre[1].poh_hash, 32UL ) ) {
    only_account_mismatch = 0;
    printf( "(%s) poh_hash:            %32J\n"
            "(%s) poh_hash:            %32J\n",
            diff->file_paths[0], pre[0].poh_hash,
            diff->file_paths[1], pre[1].poh_hash );
  }
  if( pre[0].signature_cnt != pre[1].signature_cnt ) {
    only_account_mismatch = 0;
    printf( "(%s) signature_cnt:       %lu\n"
            "(%s) signature_cnt:       %lu\n",
            diff->file_paths[0], pre[0].signature_cnt,
            diff->file_paths[1], pre[1].signature_cnt );
  }
  if( pre[0].account_cnt != pre[1].account_cnt ) {
    printf( "(%s) account_cnt:         %lu\n"
            "(%s) account_cnt:         %lu\n",
            diff->file_paths[0], pre[0].account_cnt,
            diff->file_paths[1], pre[1].account_cnt );
  }
  printf( "\n" );

  if( only_account_mismatch && diff->verbose >= 2 ) {
    fd_scratch_push();
    fd_solcap_diff_account_tbl( diff );
    fd_scratch_pop();
  }

  return 1;
}

/* Diffs two transaction results with each other. */
static void
fd_solcap_transaction_fd_diff( fd_solcap_txn_differ_t * txn_differ ) {
  if ( FD_UNLIKELY( memcmp( txn_differ->transaction[0].txn_sig,
                            txn_differ->transaction[1].txn_sig, 32UL ) != 0 ) ) {
    /* Transactions don't line up. */
    FD_LOG_WARNING(("Transaction signatures are different for slot=%lu, signature=(%32J != %32J)."
                    "It is possible that either the transactions are out of order or some transactions are missing.",
                    txn_differ->transaction[0].slot, txn_differ->transaction[0].txn_sig, txn_differ->transaction[1].txn_sig));
  }
  else {
    bool diff_txns = txn_differ->transaction[0].fd_txn_err != txn_differ->transaction[1].fd_txn_err;
    bool diff_cus = txn_differ->transaction[0].fd_cus_used != txn_differ->transaction[1].fd_cus_used;
    if ( diff_txns || diff_cus ) {
      printf(
        "\nslot:             %lu\n"
        "txn_sig:         '%64J'\n",
        txn_differ->transaction[0].slot,
        txn_differ->transaction[0].txn_sig );
    }
    if ( diff_txns ) {
      printf(
        "    (+) txn_err:  %d\n"
        "    (-) txn_err:  %d\n",
        txn_differ->transaction[0].fd_txn_err,
        txn_differ->transaction[1].fd_txn_err );
    }
    if ( diff_cus ) {
      printf(
        "    (+) cus_used: %lu\n"
        "    (-) cus_used: %lu\n",
        txn_differ->transaction[0].fd_cus_used,
        txn_differ->transaction[1].fd_cus_used );
    }
  }
}

/* Diffs firedancer transaction result with solana's result iff it is included
   in the solcap. The solana result comes from rocksdb. This diff is generated
   from just one fd_solcap_Transaction object */
static void
fd_solcap_transaction_solana_diff( fd_solcap_Transaction * transaction,
                                   ulong start_slot,
                                   ulong end_slot ) {
  if ( transaction->slot < start_slot || transaction->slot > end_slot ) {
    return;
  }

  if ( transaction->solana_txn_err == ULONG_MAX && transaction->solana_cus_used == ULONG_MAX ) {
    /* If solana_txn_err and solana_cus_used are both not populated, don't print diff */
    return;
  } else if ( transaction->solana_txn_err == ULONG_MAX ) {
    /* Print diff if the solana_txn_err is not set (txn executed successfully) */
    transaction->solana_txn_err = 0;
  }

  /* Only print a diff if cus or transaction result is different */
  if( !!( transaction->fd_txn_err ) != !!( transaction->solana_txn_err ) ||
       transaction->fd_cus_used != transaction->solana_cus_used ) {
    printf(
      "slot:                    %lu\n"
      "txn_sig:                '%64J'\n"
      "    (+) txn_err:         %d\n"
      "    (-) solana_txn_err:  %lu\n"
      "    (+) cus_used:        %lu\n"
      "    (-) solana_cus_used: %lu\n"
      "    explorer:           'https://explorer.solana.com/tx/%64J'\n"
      "    solscan:            'https://solscan.io/tx/%64J'\n"
      "    solanafm:           'https://solana.fm/tx/%64J'\n",
      transaction->slot,
      transaction->txn_sig,
      transaction->fd_txn_err,
      transaction->solana_txn_err,
      transaction->fd_cus_used,
      transaction->solana_cus_used,
      transaction->txn_sig,
      transaction->txn_sig,
      transaction->txn_sig );
  }
}

static void
fd_solcap_get_transaction_from_iter( fd_solcap_txn_differ_t * differ, ulong idx ) {
  if ( fd_solcap_chunk_iter_done( &differ->iter[idx] ) )
    return;

  fd_solcap_chunk_t const * chunk = fd_solcap_chunk_iter_item( &differ->iter[idx] );

  if( FD_UNLIKELY( 0!=fseek( differ->file[idx], differ->chunk_gaddr[idx] + (long)chunk->meta_coff, SEEK_SET ) ) ) {
    FD_LOG_ERR(( "fseek transaction meta failed (%d-%s)", errno, strerror( errno ) ));
  }
  if( FD_UNLIKELY( chunk->meta_sz != fread( &differ->meta_buf[idx], 1UL, chunk->meta_sz, differ->file[idx] ) ) ) {
    FD_LOG_ERR(( "fread transaction meta failed (%d-%s)", errno, strerror( errno ) ));
  }

  pb_istream_t stream = pb_istream_from_buffer( differ->meta_buf[idx], chunk->meta_sz );
  if( FD_UNLIKELY( !pb_decode( &stream, fd_solcap_Transaction_fields, &differ->transaction[idx] ) ) ) {
    FD_LOG_HEXDUMP_DEBUG(( "transaction meta", differ->meta_buf[idx], chunk->meta_sz ));
    FD_LOG_ERR(( "pb_decode transaction meta failed (%s)", PB_GET_ERROR(&stream) ));
  }
}

static void
fd_solcap_transaction_iter( fd_solcap_txn_differ_t * txn_differ, ulong idx ) {
  while ( !fd_solcap_chunk_iter_done( &txn_differ->iter[idx] ) ) {
    txn_differ->chunk_gaddr[idx] = fd_solcap_chunk_iter_find( &txn_differ->iter[idx], FD_SOLCAP_V1_TRXN_MAGIC );
    fd_solcap_get_transaction_from_iter( txn_differ, idx );
    fd_solcap_transaction_solana_diff( &txn_differ->transaction[idx], 0, ULONG_MAX );
  }
}

static void
fd_solcap_txn_differ_advance( fd_solcap_txn_differ_t * txn_differ ) {
  while ( !fd_solcap_chunk_iter_done( &txn_differ->iter[0] ) &&
          !fd_solcap_chunk_iter_done( &txn_differ->iter[1] ) ) {
    /* Diff transactions against both solana result (rocksdb) and against each other */
    fd_solcap_transaction_fd_diff( txn_differ );
    fd_solcap_transaction_solana_diff( &txn_differ->transaction[0], 0, ULONG_MAX );
    txn_differ->chunk_gaddr[0] = fd_solcap_chunk_iter_find( &txn_differ->iter[0], FD_SOLCAP_V1_TRXN_MAGIC );
    txn_differ->chunk_gaddr[1] = fd_solcap_chunk_iter_find( &txn_differ->iter[1], FD_SOLCAP_V1_TRXN_MAGIC );
    fd_solcap_get_transaction_from_iter( txn_differ, 0 );
    fd_solcap_get_transaction_from_iter( txn_differ, 1 );
  }
}

static void fd_solcap_txn_differ_sync( fd_solcap_txn_differ_t * txn_differ ) {
  /* Find first transaction for both files */
  for( int i=0; i<2; i++ ) {
    txn_differ->chunk_gaddr[i] = fd_solcap_chunk_iter_find( &txn_differ->iter[i], FD_SOLCAP_V1_TRXN_MAGIC );
    if( FD_UNLIKELY( txn_differ->chunk_gaddr[i] < 0L ) ) {
      int err = fd_solcap_chunk_iter_err( &txn_differ->iter[i] );
      if( err == 0 ) break;
      FD_LOG_ERR(( "fd_solcap_chunk_iter_next() failed (%d-%s)", err, strerror( err ) ));
    }
  }

  /* Get first transaction on both */
  fd_solcap_get_transaction_from_iter( txn_differ, 0 );
  fd_solcap_get_transaction_from_iter( txn_differ, 1 );

  for(;;) {
    /* If one is done but not the other, iterate through the rest of the
       transactions in order to generate a diff against solana's transactions */
    if( fd_solcap_chunk_iter_done( &txn_differ->iter[0] ) ) {
      fd_solcap_transaction_iter( txn_differ, 1 );
      break;
    } else if( fd_solcap_chunk_iter_done( &txn_differ->iter[1] ) ) {
      fd_solcap_transaction_iter( txn_differ, 0 );
      break;
    }

    /* Otherwise, try to sync up the two files, printing any solana diffs along the way */
    if( txn_differ->transaction[0].slot == txn_differ->transaction[1].slot ) {
      fd_solcap_txn_differ_advance( txn_differ );
    } else if( txn_differ->transaction[0].slot < txn_differ->transaction[1].slot ) {
      /* Advance index 0 only */
      fd_solcap_transaction_solana_diff( &txn_differ->transaction[0], 0, ULONG_MAX );
      txn_differ->chunk_gaddr[0] = fd_solcap_chunk_iter_find( &txn_differ->iter[0], FD_SOLCAP_V1_TRXN_MAGIC );
      fd_solcap_get_transaction_from_iter( txn_differ, 0 );
    } else if( txn_differ->transaction[1].slot < txn_differ->transaction[0].slot ) {
      /* Advance index 1 only */
      fd_solcap_transaction_solana_diff( &txn_differ->transaction[1], 0, ULONG_MAX );
      txn_differ->chunk_gaddr[1] = fd_solcap_chunk_iter_find( &txn_differ->iter[1], FD_SOLCAP_V1_TRXN_MAGIC );
      fd_solcap_get_transaction_from_iter( txn_differ, 1 );
    }
  }
}

static void fd_solcap_transaction_diff( FILE * file_zero, FILE * file_one ) {

  if ( FD_UNLIKELY( fseek( file_zero, 0, SEEK_SET ) != 0 ) ) {
    FD_LOG_ERR(( "fseek to start of file failed (%d-%s)", errno, strerror( errno ) ));
  }
  if ( FD_UNLIKELY( fseek( file_one, 0, SEEK_SET ) != 0 ) ) {
    FD_LOG_ERR(( "fseek to start of file failed (%d-%s)", errno, strerror( errno ) ));
  }

  /* Read file header and seek to first chunk to begin interation */
  fd_solcap_fhdr_t fhdr_zero[1];
  fd_solcap_fhdr_t fhdr_one[1];
  ulong n_zero = fread( fhdr_zero, sizeof(fd_solcap_fhdr_t), 1UL, file_zero );
  ulong n_one  = fread( fhdr_one, sizeof(fd_solcap_fhdr_t), 1UL, file_one );

  if ( FD_UNLIKELY( n_zero != 1UL ) ) {
    FD_LOG_ERR(( "fread file header failed (%d-%s)", errno, strerror( errno ) ));
  }
  if ( FD_UNLIKELY( n_one != 1UL ) ) {
    FD_LOG_ERR(( "fread file header failed (%d-%s)", errno, strerror( errno ) ));
  }
  int err;
  err = fseek( file_zero, (long)fhdr_zero->chunk0_foff - (long)sizeof(fd_solcap_fhdr_t), SEEK_CUR );
  if( FD_UNLIKELY( err < 0L ) ) {
    FD_LOG_ERR(( "fseek chunk0 failed (%d-%s)", errno, strerror( errno ) ));
  }
  err = fseek( file_one, (long)fhdr_one->chunk0_foff - (long)sizeof(fd_solcap_fhdr_t), SEEK_CUR );
  if( FD_UNLIKELY( err < 0L ) ) {
    FD_LOG_ERR(( "fseek chunk0 failed (%d-%s)", errno, strerror( errno ) ));
  }

  /* Setup txn_differ */
  fd_solcap_txn_differ_t txn_differ;
  txn_differ.file[0] = file_zero;
  txn_differ.file[1] = file_one;
  fd_solcap_chunk_iter_new( &txn_differ.iter[0], file_zero );
  fd_solcap_chunk_iter_new( &txn_differ.iter[1], file_one );

  /* Iterate and diff throught the transactions */
  fd_solcap_txn_differ_sync( &txn_differ );
}

void
fd_solcap_one_file_transaction_diff( FILE * file, ulong start_slot, ulong end_slot ) {
  /* Open and read the header */
  fd_solcap_fhdr_t fhdr[1];
  ulong n = fread( fhdr, sizeof(fd_solcap_fhdr_t), 1UL, file );
  if( FD_UNLIKELY( n!=1UL ) ) {
    FD_LOG_ERR(( "fread file header failed (%d-%s)", errno, strerror( errno ) ));
  }

  /* Seek to the first chunk */
  int err = fseek( file, (long)fhdr->chunk0_foff - (long)sizeof(fd_solcap_fhdr_t), SEEK_CUR );
  if( FD_UNLIKELY( err<0L ) ) {
    FD_LOG_ERR(( "fseek chunk0 failed (%d-%s)", errno, strerror( errno ) ));
  }

  /* Iterate through the chunks diffing the trnasactions */
  fd_solcap_chunk_iter_t iter[1];
  fd_solcap_chunk_iter_new( iter, file );
  while( !fd_solcap_chunk_iter_done( iter ) ) {
    long chunk_gaddr = fd_solcap_chunk_iter_find( iter, FD_SOLCAP_V1_TRXN_MAGIC );
    if( FD_UNLIKELY( chunk_gaddr<0L ) ) {
      int err = fd_solcap_chunk_iter_err( iter );
      if( err==0 ) break;
      FD_LOG_ERR(( "fd_solcap_chunk_iter_next() failed (%d-%s)", err, strerror( err ) ));
    }

    fd_solcap_chunk_t const * chunk = fd_solcap_chunk_iter_item( iter );
    if( FD_UNLIKELY( !chunk ) ) FD_LOG_ERR(( "fd_solcap_chunk_item() failed" ));

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

    if( meta.slot < start_slot || meta.slot > end_slot ) {
      continue;
    }

    fd_solcap_transaction_solana_diff( &meta, start_slot, end_slot );
  }
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
    "  --dump-dir     {dir}                     Dump directory\n"
    "  --start-slot   {slot}                    Start slot\n"
    "  --end-slot     {slot}                    End slot\n"
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
  ulong        start_slot = fd_env_strip_cmdline_ulong( &argc, &argv, "--start-slot", NULL, 0UL        );
  ulong        end_slot   = fd_env_strip_cmdline_ulong( &argc, &argv, "--end-slot",   NULL, ULONG_MAX  );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  char const * cap_path[2] = {0};
  int          caps_found  = 0;

  for( int i=1; i<argc; i++ ) {
    if( 0==strncmp( argv[i], "--", 2 ) ) continue;
    if( caps_found>=2 ) { usage(); return 1; }
    cap_path[ caps_found++ ] = argv[i];
  }

  if( caps_found==1 ) { /* Support one file being passed in to see transaction diff */
    cap_path[ caps_found++ ] = cap_path[ 0 ];
  }
  else if( caps_found!=2 ) {
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
  cap_file[1] = strcmp( cap_path[0], cap_path[1] ) ? fopen( cap_path[1], "rb" ) : cap_file[0];

  if ( FD_UNLIKELY( !cap_file[0] ) )
    FD_LOG_ERR(( "fopen failed (%d-%s) on file=%s", errno, strerror( errno ), cap_path[0] ));
  if ( FD_UNLIKELY( !cap_file[1] ) )
    FD_LOG_ERR(( "fopen failed (%d-%s) on file=%s", errno, strerror( errno ), cap_path[1] ));

  /* Create dump dir */

  if( mkdir( dump_dir, 0777 )<0 && errno!=EEXIST )
    FD_LOG_ERR(( "mkdir failed (%d-%s)", errno, strerror( errno ) ));
  int dump_dir_fd = open( dump_dir, O_DIRECTORY );
  if( FD_UNLIKELY( dump_dir_fd<0 ) )
    FD_LOG_ERR(( "open(%s) failed (%d-%s)", dump_dir, errno, strerror( errno ) ));

  /* Handle the one file case before diffing for accounts/hashes */
  if( cap_file[0] == cap_file[1] ) {
    FD_LOG_NOTICE(( "Only one file was passed in. Will only print transaction diffs." ));
    fd_solcap_one_file_transaction_diff( cap_file[0], start_slot, end_slot );

    /* Cleanup*/
    close( dump_dir_fd );
    fclose( cap_file[0] );
    FD_TEST( fd_scratch_frame_used()==0UL );
    fd_wksp_free_laddr( fd_scratch_detach( NULL ) );
    fd_flamenco_halt();
    fd_halt();
    return 0;
  }

  /* Create differ */

  fd_solcap_differ_t diff[1];

  /* Copy over up to last 16 chars */
  char file_name_zero[SOLCAP_FILE_NAME_LEN + 1];
  char file_name_one[SOLCAP_FILE_NAME_LEN + 1];
  char * normalized_file_paths[2] = {file_name_zero, file_name_one};
  normalize_filename( cap_path[0], normalized_file_paths[0], '+' );
  normalize_filename( cap_path[1], normalized_file_paths[1], '-' );

  printf( "++%s\n", normalized_file_paths[0] );
  printf( "--%s\n\n", normalized_file_paths[1] );

  if( FD_UNLIKELY( !fd_solcap_differ_new( diff, cap_file, (const char **)normalized_file_paths ) ) )
    return 1;
  diff->verbose     = verbose;
  diff->dump_dir    = dump_dir;
  diff->dump_dir_fd = dump_dir_fd;
  int res = fd_solcap_differ_sync( diff, start_slot, end_slot );
  if( res <0 ) FD_LOG_ERR(( "fd_solcap_differ_sync failed (%d-%s)",
                            -res, strerror( -res ) ));
  if( res==0 ) FD_LOG_ERR(( "Captures don't share any slots" ));

  /* Diff each block for accounts and hashes */

  for(;;) {
    if( FD_UNLIKELY( fd_solcap_diff_bank( diff ) ) ) break;
    printf( "Slot % 10lu: OK\n", diff->preimage[0].slot );
    /* Advance to next slot. */
    int res = fd_solcap_differ_sync( diff, start_slot, end_slot );
    if( FD_UNLIKELY( res<0 ) )
      FD_LOG_ERR(( "fd_solcap_differ_sync failed (%d-%s)",
                   -res, strerror( -res ) ));
    if( res==0 ) break;
  }

  /* Check both files for transaction and produce a diff if possible. If both
     files contain transaction info, this will produce a diff between the two
     files. If one of the files contains the solana transaction info, then we
     will also print the diffs between the solana and firedancer execution.  */
  if ( verbose >= 3 ) {
    printf( "\nTransaction diffs:\n" );
    fd_solcap_transaction_diff( cap_file[0], cap_file[1] );
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
