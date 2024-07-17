#include "fd_funk.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include "../util/io/fd_io.h"

#define FD_ARCH_MAGIC 0x92a1234fU

int
fd_funk_archive( fd_funk_t *  funk,
                 char const * filename ) {
  fd_wksp_t *     wksp        = fd_funk_wksp( funk );
  fd_funk_rec_t * rec_map     = fd_funk_rec_map( funk, wksp );
  fd_funk_partvec_t * partvec = fd_funk_get_partvec( funk, wksp );

  FD_LOG_NOTICE(( "writing %s ...", filename ));

  int fd = open( filename, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH );
  if( fd == -1 ) {
    FD_LOG_WARNING(( "failed to open %s: %s", filename, strerror(errno) ));
    return FD_FUNK_ERR_SYS;
  }

  fd_io_buffered_ostream_t str;
  uchar wbuf[1<<17];
  fd_io_buffered_ostream_init( &str, fd, wbuf, sizeof(wbuf) );
  ulong tot = 0;

#define ARCH_WRITE(buf, sz) \
  do {                                                                  \
    int err = fd_io_buffered_ostream_write( &str, buf, sz);             \
    if( err ) {                                                         \
      FD_LOG_WARNING(( "failed to write %s: %s", filename, fd_io_strerror(err) )); \
      close( fd );                                                      \
      unlink( filename );                                               \
      return FD_FUNK_ERR_SYS;                                           \
    }                                                                   \
    tot += sz;                                                          \
  } while(0)

  uint magic = FD_ARCH_MAGIC;
  ARCH_WRITE( &magic, sizeof(magic) );
  ARCH_WRITE( &partvec->num_part, sizeof(partvec->num_part) );

  for( fd_funk_rec_map_iter_t iter = fd_funk_rec_map_iter_init( rec_map );
       !fd_funk_rec_map_iter_done( rec_map, iter );
       iter = fd_funk_rec_map_iter_next( rec_map, iter ) ) {
    fd_funk_rec_t * rec     = fd_funk_rec_map_iter_ele( rec_map, iter );
    ulong           txn_idx = fd_funk_txn_idx( rec->txn_cidx );
    if( fd_funk_txn_idx_is_null( txn_idx ) ) { /* This is a record from the last published transaction */
      uchar type = (uchar)0xa5;
      ARCH_WRITE( &type, sizeof(type) );
      ARCH_WRITE( rec->pair.key, sizeof(rec->pair.key) );
      ARCH_WRITE( &rec->part, sizeof(rec->part) );
      ARCH_WRITE( &rec->val_sz, sizeof(rec->val_sz) );
      if( rec->val_sz ) {
        ARCH_WRITE( fd_wksp_laddr_fast( wksp, rec->val_gaddr ), rec->val_sz );
      }
    }
  }

  uchar type = (uchar)0x5a;
  ARCH_WRITE( &type, sizeof(type) );

  int err = fd_io_buffered_ostream_flush( &str );
  if( err ) {
    FD_LOG_WARNING(( "failed to write %s: %s", filename, fd_io_strerror(err) ));
    close( fd );
    unlink( filename );
    return FD_FUNK_ERR_SYS;
  }
  close( fd );

  FD_LOG_NOTICE(( "wrote %lu bytes to %s", tot, filename ));

  return FD_FUNK_SUCCESS;
}

int
fd_funk_unarchive( fd_funk_t *  funk,
                   char const * filename ) {
  fd_wksp_t * wksp = fd_funk_wksp( funk );
  fd_funk_rec_t * rec_map = fd_funk_rec_map( funk, wksp );
  ulong rec_max = funk->rec_max;
  fd_alloc_t * alloc = fd_funk_alloc( funk, wksp );

  FD_LOG_NOTICE(( "reading %s ...", filename ));

  int fd = open( filename, O_RDONLY );
  if( fd == -1 ) {
    FD_LOG_WARNING(( "failed to open %s: %s", filename, strerror(errno) ));
    return FD_FUNK_ERR_SYS;
  }

  fd_io_buffered_istream_t str;
  uchar rbuf[1<<17];
  fd_io_buffered_istream_init( &str, fd, rbuf, sizeof(rbuf) );
  ulong tot = 0;

#define ARCH_READ(buf, sz)                                              \
  do {                                                                  \
    int err = fd_io_buffered_istream_read( &str, buf, sz);              \
    if( err ) {                                                         \
      FD_LOG_WARNING(( "failed to read %s: %s", filename, fd_io_strerror(err) )); \
      close( fd );                                                      \
      return FD_FUNK_ERR_SYS;                                           \
    }                                                                   \
    tot += sz;                                                          \
  } while(0)

  uint magic;
  ARCH_READ( &magic, sizeof(magic) );
  if( magic != FD_ARCH_MAGIC ) {
    FD_LOG_WARNING(( "archive %s has wrong magic number", filename ));
    close( fd );
    return FD_FUNK_ERR_SYS;
  }
  uint num_part;
  ARCH_READ( &num_part, sizeof(num_part) );
  fd_funk_set_num_partitions( funk, num_part );
  fd_funk_partvec_t * partvec = fd_funk_get_partvec( funk, wksp );

  uchar type;
  fd_funk_xid_key_pair_t pair;
  fd_memset( &pair, 0, sizeof(pair) );
  uint part;
  uint val_sz;

  for(;;) {
    ARCH_READ( &type, sizeof(type) );
    if( type == (uchar)0x5a ) break;
    switch( type ) {

    case (uchar)0xa5: {
      ARCH_READ( pair.key, sizeof(pair.key) );
      ARCH_READ( &part, sizeof(part) );
      ARCH_READ( &val_sz, sizeof(val_sz) );

      if( FD_UNLIKELY( fd_funk_rec_map_is_full( rec_map ) ) ) {
        FD_LOG_WARNING(( "archive %s has too many records to fit in given funk", filename ));
        close( fd );
        return FD_FUNK_ERR_MEM;
      }

      fd_funk_rec_t * rec     = fd_funk_rec_map_insert( rec_map, &pair );
      ulong           rec_idx = (ulong)(rec - rec_map);
      if( FD_UNLIKELY( rec_idx>=rec_max ) ) FD_LOG_CRIT(( "memory corruption detected (bad idx)" ));

      ulong rec_prev_idx = funk->rec_tail_idx;

      rec->prev_idx = rec_prev_idx;
      rec->next_idx = FD_FUNK_REC_IDX_NULL;
      rec->txn_cidx = fd_funk_txn_cidx( FD_FUNK_TXN_IDX_NULL );
      rec->tag      = 0U;
      rec->flags    = 0UL;

      int first_born = fd_funk_rec_idx_is_null( rec_prev_idx );
      if( first_born ) funk->rec_head_idx               = rec_idx;
      else             rec_map[ rec_prev_idx ].next_idx = rec_idx;

      funk->rec_tail_idx = rec_idx;

      fd_funk_val_init( rec );
      if( val_sz ) {
        int err;
        if( !fd_funk_val_truncate( rec, val_sz, alloc, wksp, &err ) ) {
          FD_LOG_WARNING(( "archive %s has too much data to fit in given funk wksp", filename ));
          close( fd );
          return err;
        }
        ARCH_READ( fd_wksp_laddr_fast( wksp, rec->val_gaddr ), val_sz );
      }

      fd_funk_part_init( rec );
      if( part != FD_FUNK_PART_NULL ) {
        fd_funk_part_set_intern( partvec, rec_map, rec, part );
      }
      break;
    }

    default:
      FD_LOG_WARNING(( "archive %s has unknown record type", filename ));
      close( fd );
      return FD_FUNK_ERR_SYS;
    }
  }

  close( fd );

  FD_LOG_NOTICE(( "read %lu bytes from %s", tot, filename ));

return FD_FUNK_SUCCESS;
}
