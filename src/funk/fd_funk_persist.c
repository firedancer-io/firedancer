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
    uint type;                           /* FD_FUNK_PERSIST_FREE_TYPE */
    ulong alloc_sz;                      /* Actual allocation size, including header */
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

typedef struct fd_funk_persist_free_entry fd_funk_persist_free_entry_t;
#define REDBLK_T fd_funk_persist_free_entry_t
#define REDBLK_NAME fd_funk_persist_free_map
#include "../util/tmpl/fd_redblack.h"
struct fd_funk_persist_free_entry {
    ulong alloc_sz;
    ulong pos;
    redblack_member_t redblack;
};
#include "../util/tmpl/fd_redblack.c"

long fd_funk_persist_free_map_compare(fd_funk_persist_free_entry_t* left, fd_funk_persist_free_entry_t* right) {
  return (long)(left->alloc_sz - right->alloc_sz);
}

/* Allocate a chunk of disk space. Returns the position on the disk
   and the actual size of the allocation. Returns ULONG_MAX on failure. */
static ulong
fd_funk_persist_alloc( fd_funk_t * funk, ulong needed, ulong * actual ) {
  /* Avoid micro allocations and make sure that regions align with
     disk block boundaries */
  needed = fd_ulong_align_up( needed, 128U );

  if ( funk->persist_frees_root != -1 ) {
    fd_wksp_t * wksp = fd_funk_wksp( funk );
    fd_funk_persist_free_entry_t * pool = (fd_funk_persist_free_entry_t *)
      fd_wksp_laddr_fast( wksp, funk->persist_frees_gaddr );
    fd_funk_persist_free_entry_t * root = pool + funk->persist_frees_root;
    
    /* Find the best fit from the existing free blocks */
    fd_funk_persist_free_entry_t key;
    key.alloc_sz = needed;
    fd_funk_persist_free_entry_t * node = fd_funk_persist_free_map_nearby(pool, root, &key);
    if ( node && node->alloc_sz < needed )
      node = fd_funk_persist_free_map_successor(pool, node);
    if ( node && node->alloc_sz < needed )
      FD_LOG_CRIT(( "corrupt fd_funk_persist_free_map" ));
    
    /* See if we found a good fit without too much slop */
    if ( node && node->alloc_sz <= needed + (needed>>2) ) { /* 25% slop */
      *actual = node->alloc_sz;
      ulong pos = node->pos;
      node = fd_funk_persist_free_map_delete(pool, &root, node);
      funk->persist_frees_root = (root == NULL ? -1 : root - pool);
      fd_funk_persist_free_map_pool_release(pool, node);
      return pos;
    }
  }

  /* Allocate off the end */
  ulong pos = funk->persist_size;
  funk->persist_size += needed;
  *actual = needed;
  return pos;
}

/* Remember that a chunk of disk space is free. Takes the position and
   size of the allocation. */
static void
fd_funk_persist_remember_free( fd_funk_t * funk, ulong pos, ulong alloc_sz ) {
  fd_wksp_t * wksp = fd_funk_wksp( funk );
  fd_funk_persist_free_entry_t * pool = (fd_funk_persist_free_entry_t *)
    fd_wksp_laddr_fast( wksp, funk->persist_frees_gaddr );
  fd_funk_persist_free_entry_t * node = fd_funk_persist_free_map_pool_allocate( pool );
  if ( node == NULL ) {
    FD_LOG_WARNING(( "too many free spaces in persistence file" ));
    return;
  }
  node->pos = pos;
  node->alloc_sz = alloc_sz;
  fd_funk_persist_free_entry_t * root = (funk->persist_frees_root == -1 ? NULL :
                                         pool + funk->persist_frees_root);
  fd_funk_persist_free_map_insert(pool, &root, node);
  funk->persist_frees_root = root - pool;
}

/* Free a chunk of disk space. Takes the position and size of the
   allocation. */
static void
fd_funk_persist_free( fd_funk_t * funk, ulong pos, ulong alloc_sz ) {
  struct fd_funk_persist_free_head head;
  head.type = FD_FUNK_PERSIST_FREE_TYPE;
  head.alloc_sz = alloc_sz;
  if ( pwrite( funk->persist_fd, &head, sizeof(head), (long)pos ) != (long)sizeof(head) )
    FD_LOG_ERR(( "failed to update persistence file: %s", strerror(errno) ));
  fd_funk_persist_remember_free( funk, pos, alloc_sz );
}

static void
fd_funk_persist_recover_record( fd_funk_t * funk, ulong pos,
                                struct fd_funk_persist_record_head * head,
                                const uchar * value ) {
  int err = 0;
  fd_funk_rec_key_t key;
  fd_memcpy(&key, head->key, sizeof(key));
  fd_funk_rec_t const * rec_con = fd_funk_rec_query(funk, NULL, &key);
  if ( FD_LIKELY ( !rec_con ) ) {
    rec_con = fd_funk_rec_insert(funk, NULL, &key, &err);
    if ( !rec_con ) {
      FD_LOG_ERR(( "failed to recover record, code %s", fd_funk_strerror( err ) ));
      return;
    }
  } else {
    /* We have duplicate record keys, indicating we crashed during an
       update. Use the version that has the larger allocation size since
       this must be more recent. */
    if ( rec_con->persist_alloc_sz >= head->alloc_sz ) {
      fd_funk_persist_free( funk, pos, head->alloc_sz );
      return;
    }
    /* Delete the previous incarnation */
    fd_funk_persist_free( funk, rec_con->persist_pos, rec_con->persist_alloc_sz );
  }
  fd_funk_rec_t * rec = fd_funk_rec_modify(funk, rec_con);
  if ( !rec ) {
    FD_LOG_ERR(( "failed to recover record, code %s", fd_funk_strerror( FD_FUNK_ERR_FROZEN ) ));
    return;
  }
  fd_wksp_t * wksp = fd_funk_wksp( funk );
  fd_alloc_t * alloc = fd_funk_alloc( funk, wksp );
  rec = fd_funk_val_copy( rec, value, head->val_sz, head->val_sz, alloc, wksp, &err);
  if ( !rec ) {
    FD_LOG_ERR(( "failed to recover record, code %s", fd_funk_strerror( err ) ));
    return;
  }
  rec->persist_alloc_sz = head->alloc_sz;
  rec->persist_pos = pos;
}

int
fd_funk_persist_open( fd_funk_t * funk, const char * filename ) {
  funk->persist_fd = open(filename, O_CREAT|O_RDWR, 0600);
  if ( funk->persist_fd == -1 ) {
    FD_LOG_ERR(( "failed to open %s: %s", filename, strerror(errno) ));
    return FD_FUNK_ERR_SYS;
  }
  struct stat statbuf;
  if ( fstat( funk->persist_fd, &statbuf ) == -1) {
    FD_LOG_ERR(( "failed to open %s: %s", filename, strerror(errno) ));
    return FD_FUNK_ERR_SYS;
  }
  funk->persist_size = (ulong)statbuf.st_size;

  fd_wksp_t * wksp = fd_funk_wksp( funk );
  if ( funk->persist_frees_gaddr == 0 ) {
    ulong max = fd_ulong_min ( funk->rec_max + 1, 1000000 );
    void * mem = fd_wksp_alloc_laddr(wksp, fd_funk_persist_free_map_pool_align(),
                                     fd_funk_persist_free_map_pool_footprint(max), funk->wksp_tag );
    if ( mem == NULL ) {
      FD_LOG_ERR(( "failed to allocate free list" ));
      return FD_FUNK_ERR_MEM;
    }
    fd_funk_persist_free_entry_t * pool = fd_funk_persist_free_map_pool_join( fd_funk_persist_free_map_pool_new( mem, max ) );
    funk->persist_frees_gaddr = fd_wksp_gaddr_fast( wksp, pool );
    funk->persist_frees_root = -1;
  }

  /* Allocate a 10MB temp buffer */
  fd_alloc_t * alloc = fd_funk_alloc( funk, wksp );
  ulong tmp_max = 10UL<<20;
  uchar * tmp = (uchar *)fd_alloc_malloc_at_least( alloc, 1UL, tmp_max, &tmp_max );
  if ( tmp == NULL )
    FD_LOG_ERR(( "failed to allocate temp buffer" ));

  ulong pos = 0;
  while ( pos < funk->persist_size ) {
    long res = pread( funk->persist_fd, tmp, tmp_max, (long)pos );
    if ( res == -1) {
      FD_LOG_ERR(( "failed to open %s: %s", filename, strerror(errno) ));
      return FD_FUNK_ERR_SYS;
    }

    const uchar* tmpptr = tmp;
    const uchar* tmpend = tmp + res;
    ulong new_tmp_max = 0;
    while ( tmpptr < tmpend ) {

      if ( FD_UNLIKELY( tmpptr + sizeof(struct fd_funk_persist_free_head) <= tmpend &&
                        ((struct fd_funk_persist_free_head *)tmpptr)->type == FD_FUNK_PERSIST_FREE_TYPE ) ) {
        struct fd_funk_persist_free_head * head = (struct fd_funk_persist_free_head *)tmpptr;
        fd_funk_persist_remember_free( funk, pos, head->alloc_sz );
        tmpptr += head->alloc_sz;

      } else if ( FD_LIKELY( tmpptr + sizeof(struct fd_funk_persist_record_head) <= tmpend &&
                             ((struct fd_funk_persist_record_head *)tmpptr)->type == FD_FUNK_PERSIST_RECORD_TYPE ) ) {
        struct fd_funk_persist_record_head * head = (struct fd_funk_persist_record_head *)tmpptr;
        if ( tmpptr + sizeof(struct fd_funk_persist_record_head) + head->val_sz <= tmpend ) {
          fd_funk_persist_recover_record( funk, pos + (ulong)(tmpptr - tmp), head,
                                          tmpptr + sizeof(struct fd_funk_persist_record_head) );
          tmpptr += head->alloc_sz;
        } else {
          /* Incomplete record */
          if ( sizeof(struct fd_funk_persist_record_head) + head->val_sz > tmp_max )
            /* Need a bigger buffer */
            new_tmp_max = sizeof(struct fd_funk_persist_record_head) + head->val_sz;
          break;
        }

      } else
        /* Corrupt or incomplete entry */
        break;
    }

    /* Update the current position */
    pos += (ulong)(tmpptr - tmp);

    if ( new_tmp_max ) {
      /* Grow the temp buffer */
      fd_alloc_free( alloc, tmp );
      tmp_max = new_tmp_max;
      tmp = (uchar *)fd_alloc_malloc_at_least( alloc, 1UL, tmp_max, &tmp_max );
      if ( tmp == NULL )
        FD_LOG_ERR(( "failed to allocate temp buffer" ));

    } else if (tmpptr == tmp) {
      /* We are stalled. Database must be corrupt. */
      FD_LOG_ERR(( "corrupt persistence file" ));
      break;
    }
  }
  
  /* Free the temp buffer */
  fd_alloc_free( alloc, tmp );

  /* The logical size might be bigger than the actual size if the last
     record had some padding that was never actually used. */
  funk->persist_size = pos;
  return FD_FUNK_SUCCESS;
}

void
fd_funk_persist_close( fd_funk_t * funk ) {
  close(funk->persist_fd);
  funk->persist_fd = -1;
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

  if ( funk->persist_fd == -1 ||
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
       rec->persist_alloc_sz >= sizeof(head) + rec->val_sz ) {
    /* We can update the record in place. There is enough space in the
       existing allocation. */
    head.alloc_sz = rec->persist_alloc_sz;
    pos = rec->persist_pos;
  } else {
    /* There is no existing allocation or it's too small. Make a new
       one. */
    ulong alloc_sz;
    pos = fd_funk_persist_alloc( funk, sizeof(head) + rec->val_sz, &alloc_sz );
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
    if ( pwritev( funk->persist_fd, iov, 2, (long)pos ) != (long)(iov[0].iov_len + iov[1].iov_len) ) {
      FD_LOG_ERR(( "failed to write persistence file: %s", strerror(errno) ));
      return FD_FUNK_ERR_SYS;
    }
  } else {
    if ( pwritev( funk->persist_fd, iov, 1, (long)pos ) != (long)iov[0].iov_len ) {
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
  if ( funk->persist_fd == -1 ||
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
