/*
  The on-disk data structure is very simple. Under normal conditions,
  it is just a series of entries where each entry is either a "free
  space" or a record. Free space entries are prefixed with a
  fd_funk_persist_free_head header. Ordinary records have a
  fd_funk_persist_record_head header. In either case, disk allocations
  start on offsets which are multiples of 128. The point is to align
  with disk block boundaries and provide for easier space reuse.

  All types of entries have an alloc_sz value, which is the total size
  of the entry, including header. The next entry is always exactly
  alloc_sz away (starting at the prior header). In the case of a
  record, alloc_sz may be larger than is strictly necessary for the
  content (which has length val_sz). This padding can be consumed if
  the record grows.

  The current set of free spaces is kept in memory, sorted by
  alloc_sz. When new space is needed, the code looks for a free space
  which is big enough but not more the 25% too large. If such a space
  can't be found, the file is extended to provide the required
  space. Allocations are never split or recombined. The assumption is
  that entries are allocated with a typical set of sizes, so keeping a
  free space at its original size make sense. This approach makes the
  code simple and robust at the potential cost of wasted disk space,
  but disk space is free.

  When a transaction is published, the first thing that happens is a
  "write-ahead log" is written. This is a compact list of record
  updates and erasures in the transaction. If the application crashes
  in the middle of a commit, the write-ahead log allows for
  transactionally safe recovery. The transaction will either happen
  entirely or be completely ignored. A write-ahead log has a
  fd_funk_persist_walog_head header. It contains a nested list of
  records (fd_funk_persist_record_head) or erasures
  (fd_funk_persist_erase_head).

  To start using persistance, call fd_funk_persist_open with a file
  name. This will recover any records found in the file. Future
  transactions are then automatically written to the file.

  If transactions aren't being used (the root transaction is being
  updated directly), the persistence layer must be explicitly notified
  when a record should be persisted. Use fd_funk_rec_persist to write
  the current version of a record to disk. Use
  fd_funk_rec_persist_erase to erase the on-disk representation. These
  APIs are reasonably robust against crashes but don't provide any
  transactional guarantee.
*/

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
    uint val_sz;                         /* Num bytes in record value */
    /* Record data follows */
};

/* On-disk header for a record erasure or removal */
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

/* Map of free spaces on disk sorted by size. We use fancy red-black
   pointers to save memory. */
struct fd_funk_persist_free_entry {
    ulong alloc_sz;
    ulong pos;
    union {
        struct {
            uint parent;
            uint left;
            uint right;
            int color;
        } rb;
        ulong nf;
    } u;
};
typedef struct fd_funk_persist_free_entry fd_funk_persist_free_entry_t;
#define REDBLK_T fd_funk_persist_free_entry_t
#define REDBLK_NAME fd_funk_persist_free_map
#define REDBLK_PARENT u.rb.parent
#define REDBLK_LEFT u.rb.left
#define REDBLK_RIGHT u.rb.right
#define REDBLK_COLOR u.rb.color
#define REDBLK_NEXTFREE u.nf
#include "../util/tmpl/fd_redblack.c"

/* Compare the allocation size of two free list entries. Needed by
   redblack. */
long fd_funk_persist_free_map_compare(fd_funk_persist_free_entry_t* left, fd_funk_persist_free_entry_t* right) {
  return (long)(left->alloc_sz - right->alloc_sz);
}

/* Allocate a chunk of disk space. Returns the position on the disk
   and the actual size of the allocation. */
static ulong
fd_funk_persist_alloc( fd_funk_t * funk, ulong needed, ulong * actual ) {
  /* Avoid micro allocations and make sure that regions align with
     disk block boundaries */
  needed = fd_ulong_align_up( needed, 128U );

  /* Check if the free list is empty */
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
    if ( node && node->alloc_sz <= needed + (needed>>2) ) { /* max 25% slop */
      *actual = node->alloc_sz;
      ulong pos = node->pos;
      /* release the free list node */
      node = fd_funk_persist_free_map_remove(pool, &root, node);
      funk->persist_frees_root = (root == NULL ? -1 : root - pool);
      fd_funk_persist_free_map_release(pool, node);
      return pos;
    }
  }

  /* Allocate off the end of the file. Note that the physical length of
     the file might be less than persist_size if the final record
     doesn't completely consume all its space. */
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
  /* create the free list node */
  fd_funk_persist_free_entry_t * node = fd_funk_persist_free_map_acquire( pool );
  if ( node == NULL ) {
    FD_LOG_WARNING(( "too many free spaces in persistence file" ));
    return;
  }
  node->pos = pos;
  node->alloc_sz = alloc_sz;
  /* add it to the map. persist_frees_root in the index of the root node. */
  fd_funk_persist_free_entry_t * root = (funk->persist_frees_root == -1 ? NULL :
                                         pool + funk->persist_frees_root);
  fd_funk_persist_free_map_insert(pool, &root, node);
  funk->persist_frees_root = root - pool;
}

/* Free a chunk of disk space. Takes the position and size of the
   allocation. */
static void
fd_funk_persist_free( fd_funk_t * funk, ulong pos, ulong alloc_sz ) {
  /* write the free space header */
  struct fd_funk_persist_free_head head;
  head.type = FD_FUNK_PERSIST_FREE_TYPE;
  head.alloc_sz = alloc_sz;
  if ( pwrite( funk->persist_fd, &head, sizeof(head), (long)pos ) != (long)sizeof(head) )
    FD_LOG_ERR(( "failed to update persistence file: %s", strerror(errno) ));
  /* add it to the map */
  fd_funk_persist_remember_free( funk, pos, alloc_sz );
}

/* Process a record found during persistence recovery */
static void
fd_funk_persist_recover_record( fd_funk_t * funk, ulong pos,
                                struct fd_funk_persist_record_head * head,
                                const uchar * value, int cache_all ) {
  /* See if we already saw the key */
  int err = 0;
  fd_funk_rec_key_t key;
  fd_memcpy(&key, head->key, sizeof(key));
  fd_funk_rec_t const * rec_con = fd_funk_rec_query(funk, NULL, &key);
  if ( FD_LIKELY ( !rec_con ) ) {
    /* New key */
    rec_con = fd_funk_rec_insert(funk, NULL, &key, &err);
    if ( !rec_con ) {
      FD_LOG_ERR(( "failed to recover record, code %s", fd_funk_strerror( err ) ));
      return;
    }
  } else if ( rec_con->persist_pos != FD_FUNK_REC_IDX_NULL ) {
    if ( rec_con->persist_alloc_sz == head->alloc_sz &&
         rec_con->persist_pos == pos ) {
      /* We are recovering an already known record */
      return;
    }
    /* We have duplicate record keys, indicating we crashed during an
       update. The larger allocation must be more recent. */
    if ( rec_con->persist_alloc_sz >= head->alloc_sz ) {
      fd_funk_persist_free( funk, pos, head->alloc_sz );
      return;
    }
    /* Delete the previous incarnation */
    fd_funk_persist_free( funk, rec_con->persist_pos, rec_con->persist_alloc_sz );
  }
  /* Update the record in memory */
  fd_funk_rec_t * rec = fd_funk_rec_modify(funk, rec_con);
  if ( !rec ) {
    FD_LOG_ERR(( "failed to recover record, code %s", fd_funk_strerror( FD_FUNK_ERR_FROZEN ) ));
    return;
  }
  fd_wksp_t * wksp = fd_funk_wksp( funk );
  fd_alloc_t * alloc = fd_funk_alloc( funk, wksp );
  if ( cache_all ) {
    rec = fd_funk_val_copy( rec, value, head->val_sz, head->val_sz, alloc, wksp, &err);
    if ( !rec ) {
      FD_LOG_ERR(( "failed to recover record, code %s", fd_funk_strerror( err ) ));
      return;
    }
  } else {
    /* Just set the size */
    fd_funk_val_flush( rec, alloc, wksp );
    rec->val_sz    = head->val_sz;
    rec->val_max   = 0U;
    rec->val_gaddr = 0UL;
  }
  /* Remember where we found the data */
  rec->persist_alloc_sz = head->alloc_sz;
  rec->persist_pos = pos;
}

/* Process a record found in a write-ahead log during persistence recovery */
static void
fd_funk_persist_recover_walog_record( fd_funk_t * funk,
                                      struct fd_funk_persist_record_head * head,
                                      const uchar * value ) {
  /* get/create the record */
  fd_funk_rec_key_t key;
  fd_memcpy(&key, head->key, sizeof(key));
  fd_funk_rec_t const * rec_con = fd_funk_rec_query( funk, NULL, &key );
  int err;
  if ( !rec_con ) {
    rec_con = fd_funk_rec_insert( funk, NULL, &key, &err );
    if ( !rec_con ) {
      FD_LOG_ERR(( "failed to recover record, code %s", fd_funk_strerror( err ) ));
      return;
    }
  }
  /* write the data to the record */
  fd_funk_rec_t * rec = fd_funk_rec_modify( funk, rec_con );
  if ( !rec ) {
    FD_LOG_ERR(( "failed to recover record, code %s", fd_funk_strerror( FD_FUNK_ERR_FROZEN ) ));
    return;
  }
  fd_wksp_t * wksp = fd_funk_wksp(funk);
  fd_funk_rec_t * rec2 = fd_funk_val_copy(rec, value, head->val_sz, head->val_sz, fd_funk_alloc(funk, wksp), wksp, &err);
  if ( !rec2 ) {
    FD_LOG_ERR(( "failed to recover record, code %s", fd_funk_strerror( err ) ));
    return;
  }
  /* update the record in the file. we need an ordinary record
     instead of one found in the write-ahead log. */
  err = fd_funk_rec_persist_unsafe( funk, rec );
  if ( err ) {
    FD_LOG_ERR(( "failed to recover record, code %s", fd_funk_strerror( err ) ));
    return;
  }
}

/* Process an erase found in a write-ahead log during persistence recovery */
static void
fd_funk_persist_recover_walog_erase( fd_funk_t * funk,
                                     struct fd_funk_persist_erase_head * head ) {
  /* find the record */
  fd_funk_rec_key_t key;
  fd_memcpy(&key, head->key, sizeof(key));
  fd_funk_rec_t const * rec_con = fd_funk_rec_query( funk, NULL, &key );
  if ( !rec_con ) {
    /* Already erased */
    return;
  }
  fd_funk_rec_t * rec = fd_funk_rec_modify( funk, rec_con );
  if ( !rec ) {
    FD_LOG_ERR(( "failed to recover erase, code %s", fd_funk_strerror( FD_FUNK_ERR_FROZEN ) ));
    return;
  }
  /* erase the on-disk version */
  int err = fd_funk_rec_persist_erase_unsafe( funk, rec );
  if ( err ) {
    FD_LOG_ERR(( "failed to recover erase, code %s", fd_funk_strerror( err ) ));
    return;
  }
  /* erase the in-memory version */
  fd_funk_rec_remove( funk, rec, 1 );
}

/* Process a write-ahead log found during persistence recovery */
static void
fd_funk_persist_recover_walog( fd_funk_t * funk, struct fd_funk_persist_walog_head * wahead ) {
  /* Loop through the contents. In this case, we don't use the
     alloc_sz fields because the data is fully compacted, and we can
     rely on val_sz. */
  FD_LOG_WARNING(( "recovering write-ahead log of size %lu", wahead->used_sz ));
  const uchar* tmpptr = (const uchar*)(wahead + 1);
  const uchar* tmpend = tmpptr + wahead->used_sz;
  while ( tmpptr < tmpend ) {

    /* Use magic numbers to determine the type of the next header */
    if ( FD_LIKELY( tmpptr + sizeof(struct fd_funk_persist_record_head) <= tmpend &&
                    ((struct fd_funk_persist_record_head *)tmpptr)->type == FD_FUNK_PERSIST_RECORD_TYPE ) ) {
      /* Ordinary record */
      struct fd_funk_persist_record_head * head = (struct fd_funk_persist_record_head *)tmpptr;
      if ( tmpptr + sizeof(struct fd_funk_persist_record_head) + head->val_sz <= tmpend ) {
        fd_funk_persist_recover_walog_record( funk, head, tmpptr + sizeof(struct fd_funk_persist_record_head) );
        tmpptr += sizeof(struct fd_funk_persist_record_head) + head->val_sz;
      } else {
        /* Incomplete record */
        FD_LOG_ERR(( "corrupt write-ahead log" ));
        break;
      }

    } else if ( FD_LIKELY( tmpptr + sizeof(struct fd_funk_persist_erase_head) <= tmpend &&
                           ((struct fd_funk_persist_erase_head *)tmpptr)->type == FD_FUNK_PERSIST_ERASE_TYPE ) ) {
      struct fd_funk_persist_erase_head * head = (struct fd_funk_persist_erase_head *)tmpptr;
      fd_funk_persist_recover_walog_erase( funk, head );
      tmpptr += sizeof(struct fd_funk_persist_erase_head);

    } else {
      /* Bad magic number */
      FD_LOG_ERR(( "corrupt write-ahead log" ));
      break;
    }
  }
}

/* Recover the state of the database by reading a persistence
   file. The database typically is empty to start with. Future updates
   are written back to the file. */
int
fd_funk_persist_open( fd_funk_t * funk, const char * filename, int cache_all ) {
  /* Open the file */
  funk->persist_fd = open(filename, O_CREAT|O_RDWR, 0600);
  if ( funk->persist_fd == -1 ) {
    FD_LOG_ERR(( "failed to open %s: %s", filename, strerror(errno) ));
    return FD_FUNK_ERR_SYS;
  }
  /* Get the physical size of the file. The "logical" size may be
     slightly larger if the final record has unused padding. */
  struct stat statbuf;
  if ( fstat( funk->persist_fd, &statbuf ) == -1) {
    FD_LOG_ERR(( "failed to open %s: %s", filename, strerror(errno) ));
    return FD_FUNK_ERR_SYS;
  }
  funk->persist_size = (ulong)statbuf.st_size;

  /* Allocate the map of free disk space */
  fd_wksp_t * wksp = fd_funk_wksp( funk );
  if ( funk->persist_frees_gaddr != 0 ) {
    /* Free the previous incarnation of the free pool */
    fd_funk_persist_free_entry_t * pool = (fd_funk_persist_free_entry_t *)
      fd_wksp_laddr_fast( wksp, funk->persist_frees_gaddr );
    fd_wksp_free_laddr( fd_funk_persist_free_map_delete( fd_funk_persist_free_map_leave( pool ) ) );
  }
  /* Pessimisticaly estimate the maximum number of free spaces. If
     the pool runs out, we will be forced to throw away spaces and
     leak disk space. */
  ulong max = fd_ulong_min ( funk->rec_max, 1000000 );
  void * mem = fd_wksp_alloc_laddr(wksp, fd_funk_persist_free_map_align(),
                                   fd_funk_persist_free_map_footprint(max), funk->wksp_tag );
  if ( mem == NULL ) {
    FD_LOG_ERR(( "failed to allocate free list" ));
    return FD_FUNK_ERR_MEM;
  }
  fd_funk_persist_free_entry_t * pool = fd_funk_persist_free_map_join( fd_funk_persist_free_map_new( mem, max ) );
  funk->persist_frees_gaddr = fd_wksp_gaddr_fast( wksp, pool );
  funk->persist_frees_root = -1;

  /* Allocate a 10MB temp buffer */
  fd_alloc_t * alloc = fd_funk_alloc( funk, wksp );
  ulong tmp_max = 10UL<<20;
  uchar * tmp = (uchar *)fd_alloc_malloc_at_least( alloc, 1UL, tmp_max, &tmp_max );
  if ( tmp == NULL )
    FD_LOG_ERR(( "failed to allocate temp buffer" ));

  /* List of write-ahead logs. We remember up to 16 just to be safe
     even though there should be no more than 1 in practice. */
  static const unsigned MAX_WALOGS = 16;
  struct {
      ulong pos, sz;
  } walogs[MAX_WALOGS];
  unsigned num_walogs = 0;

  /* Loop through the file */
  ulong pos = 0;
  while ( pos < funk->persist_size ) {
    /* Read a big chunk */
    long res = pread( funk->persist_fd, tmp, tmp_max, (long)pos );
    if ( res == -1) {
      FD_LOG_ERR(( "failed to read %s: %s", filename, strerror(errno) ));
      return FD_FUNK_ERR_SYS;
    }

    /* Loop through the chunk */
    const uchar* tmpptr = tmp;
    const uchar* tmpend = tmp + res;
    ulong new_tmp_max = 0;
    while ( tmpptr < tmpend ) {

      /* Use magic numbers to determine the type of the next header */
      if ( FD_UNLIKELY( tmpptr + sizeof(struct fd_funk_persist_free_head) <= tmpend &&
                        ((struct fd_funk_persist_free_head *)tmpptr)->type == FD_FUNK_PERSIST_FREE_TYPE ) ) {
        /* Free space */
        struct fd_funk_persist_free_head * head = (struct fd_funk_persist_free_head *)tmpptr;
        fd_funk_persist_remember_free( funk, pos + (ulong)(tmpptr - tmp), head->alloc_sz );
        tmpptr += head->alloc_sz;

      } else if ( FD_LIKELY( tmpptr + sizeof(struct fd_funk_persist_record_head) <= tmpend &&
                             ((struct fd_funk_persist_record_head *)tmpptr)->type == FD_FUNK_PERSIST_RECORD_TYPE ) ) {
        /* Ordinary record (published) */
        struct fd_funk_persist_record_head * head = (struct fd_funk_persist_record_head *)tmpptr;
        if ( tmpptr + sizeof(struct fd_funk_persist_record_head) + head->val_sz <= tmpend ) {
          fd_funk_persist_recover_record( funk, pos + (ulong)(tmpptr - tmp), head,
                                          tmpptr + sizeof(struct fd_funk_persist_record_head),
                                          cache_all );
          tmpptr += head->alloc_sz;
        } else {
          /* Incomplete record */
          if ( sizeof(struct fd_funk_persist_record_head) + head->val_sz > tmp_max )
            /* Need a bigger buffer */
            new_tmp_max = sizeof(struct fd_funk_persist_record_head) + head->val_sz;
          break;
        }

      } else if ( FD_LIKELY( tmpptr + sizeof(struct fd_funk_persist_walog_head) <= tmpend &&
                             ((struct fd_funk_persist_walog_head *)tmpptr)->type == FD_FUNK_PERSIST_WALOG_TYPE ) ) {
        /* Write-ahead log */
        struct fd_funk_persist_walog_head * head = (struct fd_funk_persist_walog_head *)tmpptr;
        if ( tmpptr + sizeof(struct fd_funk_persist_walog_head) + head->used_sz <= tmpend ) {
          /* Save write-ahead logs until after we have recovered all regular records */
          if (num_walogs < MAX_WALOGS) {
            walogs[num_walogs].pos = pos + (ulong)(tmpptr - tmp);
            walogs[num_walogs].sz = sizeof(struct fd_funk_persist_walog_head) + head->used_sz;
            ++num_walogs;
          }
          tmpptr += head->alloc_sz;
        } else {
          /* Incomplete write-ahead log */
          if ( sizeof(struct fd_funk_persist_walog_head) + head->used_sz > tmp_max )
            /* Need a bigger buffer */
            new_tmp_max = sizeof(struct fd_funk_persist_walog_head) + head->used_sz;
          break;
        }

      } else
        /* Corrupt or incomplete entry */
        break;
    }

    /* Update the current position based on how much data was processed */
    pos += (ulong)(tmpptr - tmp);

    if ( new_tmp_max ) {
      /* Grow the temp buffer */
      fd_alloc_free( alloc, tmp );
      tmp_max = new_tmp_max;
      tmp = (uchar *)fd_alloc_malloc_at_least( alloc, 1UL, tmp_max, &tmp_max );
      if ( tmp == NULL )
        FD_LOG_ERR(( "failed to allocate temp buffer" ));

    } else if (tmpptr == tmp) {
      /* We are unable to make progress. Database must be corrupt. */
      FD_LOG_ERR(( "corrupt persistence file" ));
      break;
    }
  }

  /* Recover write-ahead logs */
  for (unsigned i = 0; i < num_walogs; ++i) {
    /* Read the log. tmp is guaranteed to be big enough here. */
    long res = pread( funk->persist_fd, tmp, walogs[i].sz, (long)walogs[i].pos );
    if ( res != (long)walogs[i].sz) {
      FD_LOG_ERR(( "failed to read %s: %s", filename, strerror(errno) ));
      return FD_FUNK_ERR_SYS;
    }
    struct fd_funk_persist_walog_head * head = (struct fd_funk_persist_walog_head *)tmp;
    fd_funk_persist_recover_walog( funk, head );
    /* Recovery complete. Delete the log. */
    fd_funk_persist_free( funk, walogs[i].pos, head->alloc_sz );
  }

  /* Free the temp buffer */
  fd_alloc_free( alloc, tmp );

  /* The logical size might be bigger than the actual size if the last
     record had some padding that was never actually used. */
  funk->persist_size = pos;
  return FD_FUNK_SUCCESS;
}

/* Open a persistent store file but don't bother recovering
   records. This API assumes that the shared memory version of the
   database matches the persistence file, and everything was
   previously shutdown in good order. This is the typical,
   nothing-on-fire case. */

int
fd_funk_persist_open_fast( fd_funk_t * funk, const char * filename ) {
  funk->persist_fd = open(filename, O_CREAT|O_RDWR, 0600);
  if ( funk->persist_fd == -1 ) {
    FD_LOG_ERR(( "failed to open %s: %s", filename, strerror(errno) ));
    return FD_FUNK_ERR_SYS;
  }
  return FD_FUNK_SUCCESS;
}

/* Close the persistence file */
void
fd_funk_persist_close( fd_funk_t * funk ) {
  close(funk->persist_fd);
  funk->persist_fd = -1;
}

/* Private API called from fd_funk_new */
void
fd_funk_persist_new( fd_funk_t * funk ) {
  funk->persist_fd = -1; /* Process specific */
  funk->persist_size = 0;
  funk->persist_frees_gaddr = 0;
  funk->persist_frees_root = -1;
}

/* Private API called from fd_funk_join */
void
fd_funk_persist_join( fd_funk_t * funk ) {
  funk->persist_fd = -1; /* Process specific */
}

/* Private API called from fd_funk_leave */
void
fd_funk_persist_leave( fd_funk_t * funk ) {
  if (funk->persist_fd != -1) {
    close(funk->persist_fd);
    funk->persist_fd = -1;
  }
}

/* Private API called from fd_funk_delete */
void
fd_funk_persist_delete( fd_funk_t * funk ) {
  if ( funk->persist_frees_gaddr != 0 ) {
    fd_wksp_t * wksp = fd_funk_wksp( funk );
    fd_funk_persist_free_entry_t * pool = (fd_funk_persist_free_entry_t *)
      fd_wksp_laddr_fast( wksp, funk->persist_frees_gaddr );
    fd_wksp_free_laddr( fd_funk_persist_free_map_delete( fd_funk_persist_free_map_leave( pool ) ) );
    funk->persist_frees_gaddr = 0;
  }
}

/* Update the disk representation of a record from the in-memory
   content. Unpublished records are ignored. */
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

/* Version of fd_funk_rec_persist that skips argument checking */
int
fd_funk_rec_persist_unsafe( fd_funk_t *     funk,
                            fd_funk_rec_t * rec ) {

  if ( funk->persist_fd == -1 ||
       !fd_funk_txn_idx_is_null( fd_funk_txn_idx( rec->txn_cidx ) ) ||
       rec->val_gaddr == 0UL ) {
    /* Not useful in this case. We only save published records. */
    return FD_FUNK_SUCCESS;
  }

  /* Start building the header */
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
    /* Naked header */
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

  /* Remember where we put the data */
  rec->persist_pos = pos;
  rec->persist_alloc_sz = head.alloc_sz;
  return FD_FUNK_SUCCESS;
}

/* Remove the on-disk data associated with a record. The space can be
   reused after. */
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

/* Version of fd_funk_rec_persist_erase that skips argument checking */
int
fd_funk_rec_persist_erase_unsafe( fd_funk_t *     funk,
                                  fd_funk_rec_t * rec ) {
  if ( funk->persist_fd == -1 ||
       !fd_funk_txn_idx_is_null( fd_funk_txn_idx( rec->txn_cidx ) ) ||
       rec->persist_pos == FD_FUNK_REC_IDX_NULL ) {
    /* Not useful in this case. There is nothing to erase. */
    return FD_FUNK_SUCCESS;
  }

  /* Mark the allocation on disk as free */
  fd_funk_persist_free( funk, rec->persist_pos, rec->persist_alloc_sz );
  rec->persist_pos = FD_FUNK_REC_IDX_NULL;
  rec->persist_alloc_sz = FD_FUNK_REC_IDX_NULL;

  return FD_FUNK_SUCCESS;
}

int
fd_funk_persist_load( fd_funk_t *           funk,
                      fd_funk_rec_t const * rec,
                      ulong                 val_sz,
                      uchar *               val ) {
  if ( rec->persist_pos == FD_FUNK_REC_IDX_NULL || funk->persist_fd == -1 )
    return FD_FUNK_ERR_INVAL; /* Not persisted */

  struct fd_funk_persist_record_head head;
  struct iovec iov[2];
  iov[0].iov_base = &head;
  iov[0].iov_len = sizeof(head);
  iov[1].iov_base = val;
  iov[1].iov_len = val_sz;
  if ( preadv( funk->persist_fd, iov, 2, (long)rec->persist_pos ) != (long)(iov[0].iov_len + iov[1].iov_len) ) {
    FD_LOG_WARNING(( "failed to read persistence file: %s", strerror(errno) ));
    return FD_FUNK_ERR_SYS;
  }

  if ( head.type != FD_FUNK_PERSIST_RECORD_TYPE ||
       memcmp( head.key, &rec->pair.key, sizeof(head.key) ) != 0 ||
       head.val_sz != rec->val_sz ) {
    FD_LOG_WARNING(( "did not find expected record header in file" ));
    return FD_FUNK_ERR_INVAL;
  }

  return FD_FUNK_SUCCESS;
}

/* Create a write-ahead log entry for a transaction */
int
fd_funk_txn_persist_writeahead( fd_funk_t *     funk,
                                fd_funk_txn_t * map,
                                ulong           txn_idx,
                                ulong *         wa_pos,
                                ulong *         wa_alloc ) {
  /* Initialize the result values just to be safe */
  *wa_pos = FD_FUNK_REC_IDX_NULL;
  *wa_alloc = FD_FUNK_REC_IDX_NULL;
  if ( funk->persist_fd == -1 ||
       fd_funk_txn_idx_is_null( txn_idx ) ) {
    /* Not useful in this case. Persistence isn't turned on. */
    return FD_FUNK_SUCCESS;
  }

  /* Compute the data size of the log entry */
  ulong data_sz = 0;
  ulong rec_idx = map[ txn_idx ].rec_head_idx;
  fd_wksp_t * wksp = fd_funk_wksp( funk );
  fd_funk_rec_t * rec_map = fd_funk_rec_map( funk, wksp );
  while( !fd_funk_rec_idx_is_null( rec_idx ) ) {

    if ( FD_UNLIKELY( rec_map[ rec_idx ].flags & FD_FUNK_REC_FLAG_ERASE ) ) /* Erase a published key */
      data_sz += sizeof(struct fd_funk_persist_erase_head);
    else
      data_sz += sizeof(struct fd_funk_persist_record_head) + rec_map[ rec_idx ].val_sz;

    rec_idx = rec_map[ rec_idx ].next_idx;
  }

  /* Allocate space for the log entry */
  *wa_pos = fd_funk_persist_alloc( funk, sizeof(struct fd_funk_persist_walog_head) + data_sz, wa_alloc );
  if ( *wa_pos == ULONG_MAX )
    return FD_FUNK_ERR_SYS;

  /* Make the space as free initially in case we crash during this
     operation. If a crash does happen, the transaction will get
     thrown away. */
  {
    struct fd_funk_persist_free_head head;
    head.type = FD_FUNK_PERSIST_FREE_TYPE;
    head.alloc_sz = *wa_alloc;
    if ( pwrite( funk->persist_fd, &head, sizeof(head), (long)*wa_pos ) != (long)sizeof(head) ) {
      FD_LOG_WARNING(( "failed to update persistence file: %s", strerror(errno) ));
      return FD_FUNK_ERR_SYS;
    }
  }

  /* Fill in the data */
  ulong pos = *wa_pos + sizeof(struct fd_funk_persist_walog_head);
  rec_idx = map[ txn_idx ].rec_head_idx;
  while( !fd_funk_rec_idx_is_null( rec_idx ) ) {
    fd_funk_rec_t * rec = &rec_map[ rec_idx ];

    if ( FD_UNLIKELY( rec->flags & FD_FUNK_REC_FLAG_ERASE ) ) { /* Erase a published key */

      struct fd_funk_persist_erase_head head;
      head.type = FD_FUNK_PERSIST_ERASE_TYPE;
      fd_memcpy( head.key, &rec->pair.key, sizeof(head.key) );
      head.alloc_sz = sizeof(struct fd_funk_persist_erase_head);

      if ( pwrite( funk->persist_fd, &head, sizeof(head), (long)pos ) != (long)sizeof(head) ) {
        FD_LOG_WARNING(( "failed to update persistence file: %s", strerror(errno) ));
        return FD_FUNK_ERR_SYS;
      }

      pos += sizeof(struct fd_funk_persist_erase_head);

    } else {
      /* Start building the header */
      struct fd_funk_persist_record_head head;
      head.type = FD_FUNK_PERSIST_RECORD_TYPE;
      fd_memcpy( head.key, &rec->pair.key, sizeof(head.key) );
      head.val_sz = rec->val_sz;
      head.alloc_sz = sizeof(struct fd_funk_persist_record_head) + rec->val_sz;

      /* Write the data */
      struct iovec iov[2];
      iov[0].iov_base = &head;
      iov[0].iov_len = sizeof(head);
      if ( rec->val_sz ) {
        fd_wksp_t * wksp = fd_funk_wksp( funk );
        iov[1].iov_base = fd_wksp_laddr_fast( wksp, rec->val_gaddr );
        iov[1].iov_len = rec->val_sz;
        if ( pwritev( funk->persist_fd, iov, 2, (long)pos ) != (long)(iov[0].iov_len + iov[1].iov_len) ) {
          FD_LOG_WARNING(( "failed to write persistence file: %s", strerror(errno) ));
          return FD_FUNK_ERR_SYS;
        }
      } else {
        /* Naked header */
        if ( pwritev( funk->persist_fd, iov, 1, (long)pos ) != (long)iov[0].iov_len ) {
          FD_LOG_WARNING(( "failed to write persistence file: %s", strerror(errno) ));
          return FD_FUNK_ERR_SYS;
        }
      }

      pos += sizeof(struct fd_funk_persist_record_head) + rec->val_sz;
    }

    rec_idx = rec->next_idx;
  }

  /* The data is written. Write the final header. */
  {
    struct fd_funk_persist_walog_head head;
    head.type = FD_FUNK_PERSIST_WALOG_TYPE;
    head.alloc_sz = *wa_alloc;
    fd_memcpy(head.xid, &map[ txn_idx ].xid, sizeof(head.xid));
    head.used_sz = data_sz;
    if ( pwrite( funk->persist_fd, &head, sizeof(head), (long)*wa_pos ) != (long)sizeof(head) ) {
      FD_LOG_WARNING(( "failed to update persistence file: %s", strerror(errno) ));
      return FD_FUNK_ERR_SYS;
    }
  }

  return FD_FUNK_SUCCESS;
}

void
fd_funk_txn_persist_writeahead_erase( fd_funk_t * funk,
                                      ulong       wa_pos,
                                      ulong       wa_alloc) {
  if ( funk->persist_fd == -1 ||
       wa_pos == FD_FUNK_REC_IDX_NULL ||
       wa_alloc == FD_FUNK_REC_IDX_NULL ) {
    /* Not useful in this case. Nothing to erase. */
    return;
  }
  /* Mark the entry as free space */
  fd_funk_persist_free( funk, wa_pos, wa_alloc );
}

/* Verify the integrity of the persistence layer */
int
fd_funk_persist_verify( fd_funk_t * funk ) {
# define TEST(c) do {                                                   \
    if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: %s", #c )); return FD_FUNK_ERR_INVAL; } \
  } while(0)

  fd_wksp_t * wksp = fd_funk_wksp( funk );
  fd_funk_persist_free_entry_t * pool = (fd_funk_persist_free_entry_t *)
    fd_wksp_laddr_fast( wksp, funk->persist_frees_gaddr );
  fd_funk_persist_free_entry_t * root = (funk->persist_frees_root == -1 ? NULL :
                                         pool + funk->persist_frees_root);
  int err = fd_funk_persist_free_map_verify(pool, root);
  if (err) return err;

  ulong tot_used = 0;
  ulong tot_free = 0;

  for ( fd_funk_persist_free_entry_t * n = fd_funk_persist_free_map_minimum(pool, root);
        n; n = fd_funk_persist_free_map_successor(pool, n) ) {
    struct fd_funk_persist_free_head head;
    long r = pread( funk->persist_fd, &head, sizeof(head), (long)n->pos );
    TEST( r == (long)sizeof(head) );
    TEST( head.type == FD_FUNK_PERSIST_FREE_TYPE );
    TEST( head.alloc_sz == n->alloc_sz );
    tot_free += n->alloc_sz;
  }

  fd_funk_rec_t * rec_map  = fd_funk_rec_map( funk, wksp ); /* Previously verified */
  for( fd_funk_rec_map_iter_t iter = fd_funk_rec_map_iter_init( rec_map );
       !fd_funk_rec_map_iter_done( rec_map, iter );
       iter = fd_funk_rec_map_iter_next( rec_map, iter ) ) {
    fd_funk_rec_t * rec = fd_funk_rec_map_iter_ele( rec_map, iter );
    if ( rec->persist_pos != FD_FUNK_REC_IDX_NULL ) {
      struct fd_funk_persist_record_head head;
      long r = pread( funk->persist_fd, &head, sizeof(head), (long)rec->persist_pos );
      TEST( r == (long)sizeof(head) );
      TEST( head.type == FD_FUNK_PERSIST_RECORD_TYPE );
      TEST( head.alloc_sz == rec->persist_alloc_sz );
      TEST( memcmp( head.key, &rec->pair.key, sizeof(head.key) ) == 0 );
      TEST( head.val_sz == rec->val_sz );
      tot_used += rec->persist_alloc_sz ;
    }
  }

  TEST( tot_used + tot_free == funk->persist_size );

  return FD_FUNK_SUCCESS;

#undef TEST
}
