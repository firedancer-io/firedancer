#include "fd_funk.h"
#include "fd_funk_persist.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#define __USE_MISC 1 /* For pwritev */
#include <sys/uio.h>

/* On-disk header for a chunk of free space */
struct __attribute__((packed)) fd_funk_persist_free_head {
#define FD_FUNK_PERSIST_FREE_TYPE 872042957
    uint type;                       /* FD_FUNK_PERSIST_FREE_TYPE */
    ulong alloc_sz;                  /* Actual allocation size, including header */
};

/* On-disk header for a record */
struct __attribute__((packed)) fd_funk_persist_record_head {
#define FD_FUNK_PERSIST_RECORD_TYPE 497505361
    uint type;                           /* FD_FUNK_PERSIST_RECORD_TYPE */
    ulong alloc_sz;                      /* Actual allocation size, including header */
    char key[sizeof(fd_funk_rec_key_t)]; /* Record identifier */
    uint val_sz;                         /* Num bytes in record value, in [0,val_max] */
    /* Record data follows */
};

/* On-disk header for a record erasure */
struct __attribute__((packed)) fd_funk_persist_erase_head {
#define FD_FUNK_PERSIST_ERASE_TYPE 127491733
    uint type;                           /* FD_FUNK_PERSIST_ERASE_TYPE */
    ulong alloc_sz;                      /* Actual allocation size, including header */
    char key[sizeof(fd_funk_rec_key_t)]; /* Record identifier */
};

/* On-disk header for a transaction write-ahead log */
struct __attribute__((packed)) fd_funk_persist_walog_head {
#define FD_FUNK_PERSIST_WALOG_TYPE 161299373
    uint type;                           /* FD_FUNK_PERSIST_WALOG_TYPE */
    ulong alloc_sz;                      /* Actual allocation size, including header */
    char xid[sizeof(fd_funk_txn_xid_t)]; /* Transaction identifier */
    ulong used_sz;                       /* Number of bytes of content in the walog */
    /* Nested instances of fd_funk_persist_record_head and
       fd_funk_persist_erase_head follow. */
};

/* Allocate a chunk of disk space. Returns the position on the disk
   and the actual size of the allocation. Returns ULONG_MAX on failure. */
ulong
fd_funk_persist_alloc( fd_funk_t * funk, ulong needed, ulong * actual );

/* Remember that a chunk of disk space is free. Takes the position and
   size of the allocation. */
void
fd_funk_persist_remember_free( fd_funk_t * funk, ulong pos, ulong sz );

/* Free a chunk of disk space. Takes the position and size of the
   allocation. */
void
fd_funk_persist_free( fd_funk_t * funk, ulong pos, ulong sz );

int
fd_funk_persist_open( fd_funk_t * funk, const char * filename ) {
  funk->persistfd = open(filename, O_CREAT, 0600);
  if (funk->persistfd == -1) {
    FD_LOG_ERR(( "failed to open %s: %s", filename, strerror(errno) ));
    return FD_FUNK_ERR_SYS;
  }
  return FD_FUNK_SUCCESS;
}

void
fd_funk_persist_close( fd_funk_t * funk ) {
  close(funk->persistfd);
  funk->persistfd = -1;
}

int
fd_funk_rec_persist( fd_funk_t *     funk,
                     fd_funk_rec_t * rec ) {
  if( FD_UNLIKELY( !funk ) ) return FD_FUNK_ERR_INVAL;

  fd_wksp_t * wksp = fd_funk_wksp( funk );

  fd_funk_rec_t * rec_map = fd_funk_rec_map( funk, wksp );

  ulong rec_max = funk->rec_max;

  ulong rec_idx = (ulong)(rec - rec_map);

  if( FD_UNLIKELY( (rec_idx>=rec_max) /* Out of map (incl NULL) */ | (rec!=(rec_map+rec_idx)) /* Bad alignment */ ) )
    return FD_FUNK_ERR_INVAL;

  if( FD_UNLIKELY( rec!=fd_funk_rec_map_query( rec_map, fd_funk_rec_pair( rec ), NULL ) ) )
    return FD_FUNK_ERR_INVAL;

  return fd_funk_rec_persist_unsafe( funk, rec );
}
  
int
fd_funk_rec_persist_unsafe( fd_funk_t *     funk,
                            fd_funk_rec_t * rec ) {

  if ( funk->persistfd == -1 ||
       !fd_funk_txn_idx_is_null( fd_funk_txn_idx( rec->txn_cidx ) ) ) {
    /* Not useful in this case */
    return FD_FUNK_SUCCESS;
  }
  
  struct fd_funk_persist_record_head head;
  head.type = FD_FUNK_PERSIST_RECORD_TYPE;
  fd_memcpy( head.key, &rec->pair.key, sizeof(head.key) );
  head.val_sz = rec->val_sz;

  ulong pos;
  if ( rec->persist_pos != FD_FUNK_REC_IDX_NULL &&
       rec->persist_alloc_sz >= rec->val_sz ) {
    /* We can update the record in place. There is enough space in the
       existing allocation. */
    head.alloc_sz = rec->persist_alloc_sz;
    pos = rec->persist_pos;
  } else {
    /* There is no existing allocation or it's too small. Make a new
       one. */
    ulong alloc_sz;
    pos = fd_funk_persist_alloc( funk, rec->val_sz, &alloc_sz );
    if ( pos == ULONG_MAX )
      return FD_FUNK_ERR_SYS;
    head.alloc_sz = alloc_sz;
  }

  /* Write the data */
  struct iovec iov[2];
  iov[0].iov_base = &head;
  iov[0].iov_len = sizeof(head);
  if ( rec->val_sz ) {
    fd_wksp_t * wksp = fd_funk_wksp( funk );
    iov[1].iov_base = fd_wksp_laddr_fast( wksp, rec->val_gaddr );
    iov[1].iov_len = rec->val_sz;
    if ( pwritev( funk->persistfd, iov, 2, (long)pos ) != (long)(iov[0].iov_len + iov[1].iov_len) ) {
      FD_LOG_ERR(( "failed to write persistence file: %s", strerror(errno) ));
      return FD_FUNK_ERR_SYS;
    }
  } else {
    if ( pwritev( funk->persistfd, iov, 1, (long)pos ) != (long)iov[0].iov_len ) {
      FD_LOG_ERR(( "failed to write persistence file: %s", strerror(errno) ));
      return FD_FUNK_ERR_SYS;
    }
  }

  /* At this point we may have two versions of the same record. If we
   * crash here, this will get cleaned up during recovery. */ 

  if ( rec->persist_pos != FD_FUNK_REC_IDX_NULL &&
       rec->persist_pos != pos ) {
    /* Delete the old instance */
    fd_funk_persist_free( funk, rec->persist_pos, rec->persist_alloc_sz );
  }

  rec->persist_pos = pos;
  rec->persist_alloc_sz = head.alloc_sz;
  return FD_FUNK_SUCCESS;
}

int
fd_funk_rec_persist_erase( fd_funk_t *     funk,
                           fd_funk_rec_t * rec ) {
  if( FD_UNLIKELY( !funk ) ) return FD_FUNK_ERR_INVAL;

  fd_wksp_t * wksp = fd_funk_wksp( funk );

  fd_funk_rec_t * rec_map = fd_funk_rec_map( funk, wksp );

  ulong rec_max = funk->rec_max;

  ulong rec_idx = (ulong)(rec - rec_map);

  if( FD_UNLIKELY( (rec_idx>=rec_max) /* Out of map (incl NULL) */ | (rec!=(rec_map+rec_idx)) /* Bad alignment */ ) )
    return FD_FUNK_ERR_INVAL;

  if( FD_UNLIKELY( rec!=fd_funk_rec_map_query( rec_map, fd_funk_rec_pair( rec ), NULL ) ) )
    return FD_FUNK_ERR_INVAL;

  return fd_funk_rec_persist_erase_unsafe( funk, rec );
}
  
int
fd_funk_rec_persist_erase_unsafe( fd_funk_t *     funk,
                                  fd_funk_rec_t * rec ) {
  if ( funk->persistfd == -1 ||
       !fd_funk_txn_idx_is_null( fd_funk_txn_idx( rec->txn_cidx ) ) ||
       rec->persist_pos == FD_FUNK_REC_IDX_NULL ) {
    /* Not useful in this case */
    return FD_FUNK_SUCCESS;
  }

  /* Mark the allocation on disk as free */
  fd_funk_persist_free( funk, rec->persist_pos, rec->persist_alloc_sz );
  rec->persist_pos = FD_FUNK_REC_IDX_NULL;
  rec->persist_alloc_sz = FD_FUNK_REC_IDX_NULL;

  return FD_FUNK_SUCCESS;
}
