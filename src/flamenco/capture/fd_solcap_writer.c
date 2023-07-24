#include "fd_solcap_writer.h"
#include "fd_solcap_proto.h"

#if !FD_HAS_HOSTED
#error "fd_solcap_writer requires FD_HAS_HOSTED"
#endif

#include <errno.h>
#include <stdio.h>

#define FD_SOLCAP_SLOT_BUF_CNT (64U)

static int
_align_file( FILE * file,
             ulong  align ) {

  long pos = ftell( file );
  if( FD_UNLIKELY( pos<0L ) ) {
    FD_LOG_WARNING(( "ftell failed (%d-%s)", errno, strerror( errno ) ));
    return EIO;
  }

  ulong skip = fd_ulong_align_up( (ulong)pos, align ) - (ulong)pos;
  uchar const pad[ 8 ] = {0};
  FD_TEST( skip<8UL );
  ulong n = fwrite( pad, 1UL, skip, file );
  if( FD_UNLIKELY( n!=skip ) ) {
    FD_LOG_WARNING(( "fwrite failed (%d-%s)", errno, strerror( errno ) ));
    return EIO;
  }

  return 0;
}

struct fd_solcap_writer {
  FILE * file;

  ulong block_off;
  ulong slot0;
  ulong slot_cnt;

  uchar                     bank_hash[ FD_SOLCAP_SLOT_BUF_CNT ][ 32 ];
  fd_solcap_bank_preimage_t bank_pre [ FD_SOLCAP_SLOT_BUF_CNT ];
};

ulong
fd_solcap_writer_align( void ) {
  return alignof(fd_solcap_writer_t);
}

ulong
fd_solcap_writer_footprint( void ) {
  return sizeof(fd_solcap_writer_t);
}

void *
fd_solcap_writer_new( void * mem ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  memset( mem, 0, sizeof(fd_solcap_writer_t) );
  return mem;
}

fd_solcap_writer_t *
fd_solcap_writer_join( void * mem ) {
  return (fd_solcap_writer_t *)mem;
}

void *
fd_solcap_writer_leave( fd_solcap_writer_t * writer ) {
  return (void *)writer;
}

void *
fd_solcap_writer_delete( void * mem ) {
  return mem;
}


fd_solcap_writer_t *
fd_solcap_writer_init( fd_solcap_writer_t * writer,
                       void *               file ) {

  if( FD_UNLIKELY( !writer ) ) {
    FD_LOG_WARNING(( "NULL writer" ));
    return NULL;
  }
  if( FD_UNLIKELY( !file ) ) {
    FD_LOG_WARNING(( "NULL file" ));
    return NULL;
  }

  /* Leave space for block header */

  long fpos = ftell( file );
  if( FD_UNLIKELY( fpos<0L ) ) {
    FD_LOG_WARNING(( "ftell failed (%d-%s)", errno, strerror( errno ) ));
    return NULL;
  }

  fd_solcap_fhdr_t hdr = {0};
  ulong n = fwrite( &hdr, sizeof(fd_solcap_fhdr_t), 1UL, file );
  if( FD_UNLIKELY( n!=1UL ) ) {
    FD_LOG_WARNING(( "fwrite failed (%d-%s)", errno, strerror( errno ) ));
    return NULL;
  }

  /* Init writer */

  *writer = (fd_solcap_writer_t) {
    .file      = (FILE *)file,
    .block_off = (ulong)fpos,
    .slot0     = ULONG_MAX,
  };

  return writer;
}


static int
fd_solcap_writer_flush_block( fd_solcap_writer_t * writer ) {

  if( FD_LIKELY( !writer ) ) return 0;

  /* Write bank hash table */

  long bankhash_pos = ftell( writer->file );
  if( FD_UNLIKELY( bankhash_pos<0L ) ) {
    FD_LOG_WARNING(( "ftell failed (%d-%s)", errno, strerror( errno ) ));
    return errno;
  }

  ulong n = fwrite(
      writer->bank_hash,
      32UL, writer->slot_cnt,
      writer->file );
  if( FD_UNLIKELY( n != writer->slot_cnt ) ) {
    FD_LOG_WARNING(( "fwrite failed (%d-%s)", errno, strerror( errno ) ));
    return errno;
  }

  /* Write bank preimage table */

  long preimage_pos = ftell( writer->file );
  if( FD_UNLIKELY( preimage_pos<0L ) ) {
    FD_LOG_WARNING(( "ftell failed (%d-%s)", errno, strerror( errno ) ));
    return errno;
  }

  n = fwrite(
      writer->bank_pre,
      sizeof(fd_solcap_bank_preimage_t), writer->slot_cnt,
      writer->file );
  if( FD_UNLIKELY( n != writer->slot_cnt ) ) {
    FD_LOG_WARNING(( "fwrite failed (%d-%s)", errno, strerror( errno ) ));
    return errno;
  }

  long block_end = ftell( writer->file );
  if( FD_UNLIKELY( block_end<0L ) ) {
    FD_LOG_WARNING(( "ftell failed (%d-%s)", errno, strerror( errno ) ));
    return errno;
  }

  /* Write block header */

  int err = fseek( writer->file, (long)writer->block_off, SEEK_SET );
  if( FD_UNLIKELY( err<0L ) ) return errno;

  fd_solcap_fhdr_t fhdr = {
    .magic    = FD_SOLCAP_MAGIC,
    .version  = 0UL,
    .total_sz = (ulong)block_end - writer->block_off,
    .v0 = {
      .slot0             = writer->slot0,
      .slot_cnt          = writer->slot_cnt,
      .bank_hash_off     = (ulong)bankhash_pos - writer->block_off,
      .bank_preimage_off = (ulong)preimage_pos - writer->block_off
    }
  };
  n = fwrite( &fhdr, sizeof(fd_solcap_fhdr_t), 1UL, writer->file );
  if( FD_UNLIKELY( n!=1UL ) ) {
    FD_LOG_WARNING(( "fwrite failed (%d-%s)", errno, strerror( errno ) ));
    return errno;
  }

  /* Wind up for next block */

  err = fseek( writer->file, block_end, SEEK_SET );
  if( FD_UNLIKELY( err<0L ) ) return errno;

  writer->slot0     = ULONG_MAX;
  writer->slot_cnt  = 0UL;
  writer->block_off = (ulong)block_end;

  return 0;
}

fd_solcap_writer_t *
fd_solcap_writer_fini( fd_solcap_writer_t * writer ) {

  if( FD_LIKELY( !writer ) ) return NULL;

  if( writer->slot_cnt ) {
    int err = fd_solcap_writer_flush_block( writer );
    if( FD_UNLIKELY( err!=0 ) )
      FD_LOG_WARNING(( "fd_solcap_writer_flush_block failed (%d)", err ));
  }

  fflush( writer->file );
  return NULL;
}

int
fd_solcap_write_set_slot( fd_solcap_writer_t * writer,
                          ulong                target_slot ) {

  /* TODO handle skipped slots */

  if( FD_LIKELY( !writer ) ) return 0;

  if( writer->slot_cnt >= FD_SOLCAP_SLOT_BUF_CNT ) {
    int err = fd_solcap_writer_flush_block( writer );
    if( FD_UNLIKELY( err!=0 ) ) return err;
  }

  if( writer->slot0 == ULONG_MAX )
    writer->slot0 = target_slot;

  ulong slot1 = writer->slot0 + writer->slot_cnt;
  if( slot1>target_slot ) {
    FD_LOG_WARNING(( "cannot seek backwards (slot1=%lu target=%lu)",
                     slot1, target_slot ));
    return EINVAL;
  }

  fd_solcap_bank_preimage_t * preimage = &writer->bank_pre[ writer->slot_cnt ];
  preimage->skipped_slot = (uchar)0;

  long pos = ftell( writer->file );
  if( FD_UNLIKELY( pos<0L ) ) {
    FD_LOG_WARNING(( "ftell failed (%d-%s)", errno, strerror( errno ) ));
    return EIO;
  }
  preimage->account_off = (ulong)pos - writer->block_off;

  writer->slot_cnt++;
  return 0;
}

int
fd_solcap_write_account( fd_solcap_writer_t *        writer,
                         fd_solcap_account_t const * account,
                         void const *                data,
                         ulong                       data_sz ) {

  if( FD_LIKELY( !writer ) ) return 0;

  /* Update account count */

  writer->bank_pre[ writer->slot_cnt ].account_cnt++;

  /* Write account header */

  fd_solcap_account_t _account = {
    .footprint  = fd_ulong_align_up( sizeof(fd_solcap_account_t) + data_sz, 8UL ),
    .lamports   = account->lamports,
    .slot       = account->slot,
    .rent_epoch = account->rent_epoch,
    .executable = account->executable,
  };
  memcpy( _account.key,   account->key,   32UL );
  memcpy( _account.owner, account->owner, 32UL );
  memcpy( _account.hash,  account->hash,  32UL );

  ulong n = fwrite( &_account, sizeof(fd_solcap_account_t), 1UL, writer->file );
  if( FD_UNLIKELY( n!=1UL ) ) {
    FD_LOG_WARNING(( "fwrite failed (%d-%s)", errno, strerror( errno ) ));
    return EIO;
  }

  /* Write account data */

  n = fwrite( data, data_sz, 1UL, writer->file );
  if( FD_UNLIKELY( n != fd_ulong_if( !!data_sz, 1UL, 0UL ) ) ) {
    FD_LOG_WARNING(( "fwrite failed (%d-%s)", errno, strerror( errno ) ));
    return EIO;
  }

  return _align_file( writer->file, 8UL );
}

void
fd_solcap_write_bank_preimage( fd_solcap_writer_t * writer,
                               void const *         prev_bank_hash,
                               void const *         account_delta_hash,
                               void const *         poh_hash ) {

  if( FD_LIKELY( !writer ) ) return;

  fd_solcap_bank_preimage_t * preimage = &writer->bank_pre[ writer->slot_cnt ];
  memcpy( preimage->prev_bank_hash,     prev_bank_hash,     32UL );
  memcpy( preimage->account_delta_hash, account_delta_hash, 32UL );
  memcpy( preimage->poh_hash,           poh_hash,           32UL );
}

void
fd_solcap_write_bank_hash( fd_solcap_writer_t * writer,
                           uchar const *        hash ) {

  if( FD_LIKELY( !writer ) ) return;

  memcpy( writer->bank_hash[ writer->slot_cnt - 1UL ], hash, 32UL );
}
