#include "fd_shredcap.h"

#define BUF_ALIGN               (16UL)
#define WBUF_FOOTPRINT          (65536UL)
#define MANIFEST_BUF_FOOTPRINT  (512UL)
#define BANK_HASH_BUF_FOOTPRINT (64UL)
#define RBUF_FOOTPRINT          (65536UL)
#define FILE_SLOT_NUM_DIGITS    (20UL) /* Max number of digits in a ulong */

/**** Helpers *****************************************************************/
void
set_file_name( char * file_name_ptr, ulong start_slot, ulong end_slot ) {
  /* File name should be "startslot_endslot" */
  fd_memset( file_name_ptr, '\0', FD_SHREDCAP_CAPTURE_FILE_NAME_LENGTH );
  fd_cstr_append_ulong_as_text( file_name_ptr, '0', '\0', start_slot, FILE_SLOT_NUM_DIGITS );
  fd_cstr_append_char( file_name_ptr + FILE_SLOT_NUM_DIGITS, '_' );
  fd_cstr_append_ulong_as_text( file_name_ptr + FILE_SLOT_NUM_DIGITS + 1, 
                                '0', '\0', end_slot, FILE_SLOT_NUM_DIGITS );
}

void 
fd_shredcap_concat( char * buf, const char * dir, const char * file ) {
  fd_memset( buf, '\0', FD_SHREDCAP_CAPTURE_PATH_NAME_LENGTH );
  fd_cstr_append_cstr( buf, dir );
  fd_cstr_append_cstr( buf + strlen( dir ), file );
}

/**** Ingest ******************************************************************/
void 
fd_shredcap_ingest_rocksdb_to_capture( const char * rocksdb_dir,
                                         const char * capture_dir,
                                         ulong        max_file_sz,
                                         ulong        start_slot,
                                         ulong        end_slot ) {
  /* Setup and start rocksdb ingest */
  fd_rocksdb_t rocks_db;
  char * rocksdb_err = fd_rocksdb_init( &rocks_db, rocksdb_dir );
  if ( rocksdb_err != NULL ) {
    FD_LOG_ERR(( "fd_rocksdb_init returned %s", rocksdb_err ));
  }

  if ( rocksdb_err != NULL ) {
    FD_LOG_ERR(( "fd_rocksdb_last_slot returned %s", rocksdb_err ));
  }

  if ( end_slot < start_slot ) {
    FD_LOG_ERR(( "rocksdb blocks are older than snapshot. first=%lu last=%lu wanted=%lu",
                 fd_rocksdb_first_slot(&rocks_db, &rocksdb_err), end_slot, start_slot ));
  }

  fd_rocksdb_root_iter_t iter;
  fd_rocksdb_root_iter_new( &iter );

  fd_slot_meta_t metadata;
  fd_memset( &metadata, 0, sizeof(metadata) );

  fd_valloc_t valloc = fd_libc_alloc_virtual();

  int ret = fd_rocksdb_root_iter_seek( &iter, &rocks_db, start_slot, &metadata, valloc );
  if ( ret != 0 ) {
    FD_LOG_ERR(( "fd_rocksdb_root_iter_seek returned %d", ret ));
  }

  /* Create directory for shredcap capture */
  int mkdir_res = mkdir( capture_dir, 0777 );
  if ( mkdir_res ) {
    FD_LOG_ERR(( "unable to create directory=%s", capture_dir ));
  }

  /* Setup manifest file and buffered I/O. Write out header. */
  char manifest_path_buf[ FD_SHREDCAP_CAPTURE_PATH_NAME_LENGTH ];
  fd_shredcap_concat( manifest_path_buf, capture_dir, "manifest" );
  int manifest_fd = open( manifest_path_buf, O_CREAT|O_WRONLY, (mode_t)0666 );
  if( FD_UNLIKELY( manifest_fd == -1 ) ) {
    FD_LOG_WARNING(( "open(\"%s\",O_CREAT|O_WRONLY|,0%03lo) failed (%i-%s)",
                     manifest_path_buf, 0666, errno, fd_io_strerror( errno ) ));
    return;
  }
  uchar manifest_buf[ WBUF_FOOTPRINT ] __attribute__((aligned(BUF_ALIGN)));
  fd_io_buffered_ostream_t manifest_ostream[ 1 ];
  fd_io_buffered_ostream_init( manifest_ostream, manifest_fd, manifest_buf, WBUF_FOOTPRINT );
  int err;

  fd_shredcap_manifest_hdr_t manifest_hdr;
  manifest_hdr.magic      = FD_SHREDCAP_MANIFEST_MAGIC;
  manifest_hdr.version    = FD_SHREDCAP_MANIFEST_VERSION;
  manifest_hdr.num_files  = UINT_MAX; /* This is written after the fact */
  manifest_hdr.start_slot = start_slot;
  manifest_hdr.end_slot   = end_slot;
  err = fd_io_buffered_ostream_write( manifest_ostream, &manifest_hdr, 
                                      FD_SHREDCAP_MANIFEST_HDR_FOOTPRINT );
  if ( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "error writing manifest header" ));
  }

  /* Create and setup bank hash file */
  char bank_hash_path_buf[ FD_SHREDCAP_CAPTURE_PATH_NAME_LENGTH ];
  fd_shredcap_concat( bank_hash_path_buf, capture_dir, "bank_hash" );
  int bank_hash_fd = open( bank_hash_path_buf, O_CREAT|O_WRONLY, (mode_t)0666 );
  if( FD_UNLIKELY( bank_hash_fd == -1 ) ) {
    FD_LOG_WARNING(( "open(\"%s\",O_CREAT|O_WRONLY|,0%03lo) failed (%i-%s)",
                     bank_hash_path_buf, 0666, errno, fd_io_strerror( errno ) ));
    FD_LOG_ERR(( "can't create and open bank hash file" ));
  }
  uchar bank_hash_buf[ WBUF_FOOTPRINT ] __attribute__((aligned(BUF_ALIGN)));
  fd_io_buffered_ostream_t bank_hash_ostream[ 1 ];
  fd_io_buffered_ostream_init( bank_hash_ostream, bank_hash_fd, bank_hash_buf, WBUF_FOOTPRINT );

  fd_shredcap_bank_hash_hdr_t bank_hash_hdr;
  bank_hash_hdr.magic      = FD_SHREDCAP_BANK_HASH_MAGIC;
  bank_hash_hdr.version    = FD_SHREDCAP_BANK_HASH_VERSION;
  bank_hash_hdr.start_slot = start_slot;
  bank_hash_hdr.end_slot   = end_slot;
  err = fd_io_buffered_ostream_write( bank_hash_ostream, &bank_hash_hdr, 
                                      FD_SHREDCAP_BANK_HASH_HDR_FOOTPRINT );
  if ( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "error writing bank hash file header" ));
  }

  /* The file size limit should be able to hold at least one full sized block (~40MiB) */
  long real_max_file_sz = (long)fd_ulong_if( max_file_sz < FD_SHREDCAP_MAX_BLOCK_STORAGE_FOOTPRINT, 
                                             FD_SHREDCAP_MAX_BLOCK_STORAGE_FOOTPRINT, max_file_sz );
  uint num_files = 0;
  ulong block_count = 0;

  /* Create temporary name file for writing out shreds */
  char tmp_path_buf[ FD_SHREDCAP_CAPTURE_PATH_NAME_LENGTH ];
  fd_shredcap_concat( tmp_path_buf, capture_dir, "temp" );
  uchar wbuf[ WBUF_FOOTPRINT ] __attribute__((aligned(BUF_ALIGN)));

  ulong sz;
  long file_start_offset;

  /* Stop iterating when we current slot reaches end slot of end of rocksdb*/
  while( metadata.slot < end_slot && ret == 0 ) {
    ++num_files;

    /* Setup output file and I/O streaming */
    ulong file_block_count = 0;
    int fd = open( tmp_path_buf, O_CREAT|O_WRONLY, (mode_t)0666 );
    if( FD_UNLIKELY( fd == -1 ) ) {
      FD_LOG_ERR(( "open(\"%s\",O_CREAT|O_WRONLY|,0%03lo) failed (%i-%s)", 
                   tmp_path_buf, 0666, errno, fd_io_strerror( errno ) ));
    }
    fd_io_buffered_ostream_t ostream[ 1 ];
    fd_io_buffered_ostream_init( ostream, fd, wbuf, WBUF_FOOTPRINT );

    /* File header and write it out */
    fd_shredcap_file_hdr_t file_hdr;
    file_hdr.magic      = FD_SHREDCAP_FILE_MAGIC;
    file_hdr.version    = FD_SHREDCAP_FILE_VERSION;
    file_hdr.start_slot = metadata.slot;
    file_hdr.end_slot   = ULONG_MAX; /* This is updated after file is populated */
    file_hdr.num_blocks = ULONG_MAX; /* This is updated after file is populated */
    err = fd_io_buffered_ostream_write( ostream, &file_hdr, FD_SHREDCAP_FILE_HDR_FOOTPRINT );
    if ( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "error writing capture file header" ));
    }
    
    /* Start iterating through slots*/
    ulong file_start_slot = metadata.slot;
    ulong file_end_slot   = 0;

    /* Keep adding to the file unless max file size is exceeded or current slot 
       exceeeds the range */
    while ( metadata.slot < end_slot && lseek( ostream->fd, 0, SEEK_CUR ) < real_max_file_sz  ) {
      ulong cur_slot = metadata.slot;
      /* Import shreds for entire slot */
      
      int err = fd_rocksdb_import_block_shredcap( &rocks_db, &metadata, ostream, bank_hash_ostream );
      if( FD_UNLIKELY( err ) ) { 
        FD_LOG_ERR(( "fd_rocksdb_get_block failed at slot=%lu", cur_slot ));
      }

      file_end_slot = metadata.slot;
      ++file_block_count;
      
      fd_bincode_destroy_ctx_t ctx = { .valloc = valloc };
      fd_slot_meta_destroy( &metadata, &ctx );

      /* Get next slot and handle case where end_slot is larger than the last
         slot in the rocksdb */
      ret = fd_rocksdb_root_iter_next( &iter, &metadata, valloc );
      if ( ret != 0 ) {
        ret = fd_rocksdb_get_meta( &rocks_db, cur_slot + 1, &metadata, valloc );
        if ( ret != 0 ) {
          break;
        }
      }
    }
    block_count += file_block_count;

    /* To finish out writing to capture file, copy the header into the footer,
       flush the buffer. The header needs to be updated to include the payload 
       size. Clear any fd_io and close the fd. Rename the file. */
    file_hdr.end_slot   = file_end_slot;
    file_hdr.num_blocks = file_block_count;
    err = fd_io_buffered_ostream_write( ostream, &file_hdr, FD_SHREDCAP_FILE_FTR_FOOTPRINT );
    if ( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "error writing capture file footer" ));
    }

    if( FD_UNLIKELY( fd_io_buffered_ostream_flush( ostream ) ) ) {
      FD_LOG_ERR(( "error during fd_io_buffered_ostream_flush" ));
    }
    fd_io_buffered_ostream_fini( ostream );

    file_start_offset = lseek( ostream->fd, 0, SEEK_SET );
    if ( FD_UNLIKELY( file_start_offset == -1 ) ) {
      FD_LOG_ERR(( "lseek error when moving to start of file" ));
    }
    err = fd_io_write( ostream->fd, &file_hdr, FD_SHREDCAP_FILE_FTR_FOOTPRINT, 
                       FD_SHREDCAP_FILE_FTR_FOOTPRINT, &sz );
    if ( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "error when writing to update file header" ));
    }
    if ( FD_UNLIKELY( sz != FD_SHREDCAP_FILE_FTR_FOOTPRINT ) ) {
      FD_LOG_ERR(( "unexpected size written when updating file header" ));
    }
      
    if ( FD_UNLIKELY( close( fd ) ) ) {
      FD_LOG_ERR(( "error while closing file descriptor" ));
    }

    char new_path_buf[ FD_SHREDCAP_CAPTURE_FILE_NAME_LENGTH ];
    set_file_name( new_path_buf, file_start_slot, file_end_slot );
    char new_file_name[ FD_SHREDCAP_CAPTURE_PATH_NAME_LENGTH ];
    fd_shredcap_concat( new_file_name, capture_dir, new_path_buf );
    rename( tmp_path_buf, new_file_name );

    /* Add a directory manifest entry */
    fd_shredcap_manifest_entry_t manifest_entry;
    manifest_entry.start_slot = file_start_slot;
    manifest_entry.end_slot   = file_end_slot;
    fd_memcpy( &manifest_entry.path, &new_path_buf, strlen( new_path_buf ) );
    err = fd_io_buffered_ostream_write( manifest_ostream, &manifest_entry, 
                                        FD_SHREDCAP_MANIFEST_ENTRY_FOOTPRINT );
    if ( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "error writing manifest entry" ));
    }

    FD_LOG_NOTICE(( "ingested %lu blocks at file=%s", block_count, new_file_name ));
  }

  /* Write manifest footer and update header */
  manifest_hdr.num_files = num_files;
  err = fd_io_buffered_ostream_write( manifest_ostream, &manifest_hdr, 
                                      FD_SHREDCAP_MANIFEST_FTR_FOOTPRINT );
  if ( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "error writing manifest footer" ));
  }
  fd_io_buffered_ostream_flush( manifest_ostream );
  fd_io_buffered_ostream_fini( manifest_ostream );
  
  file_start_offset = lseek( manifest_fd, 0, SEEK_SET );
  if ( FD_UNLIKELY( file_start_offset == -1 ) ) {
    FD_LOG_ERR(( "lseek failed when seeking to start of manifest", file_start_offset ));
  }

  err = fd_io_write( manifest_fd, &manifest_hdr, FD_SHREDCAP_MANIFEST_HDR_FOOTPRINT, 
                     FD_SHREDCAP_MANIFEST_HDR_FOOTPRINT, &sz );
  if ( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "unable to write num_files=%lu to manifest header", num_files ));
  }
  if ( FD_UNLIKELY( sz != FD_SHREDCAP_MANIFEST_HDR_FOOTPRINT ) ) {
    FD_LOG_ERR(( "size=%lu doesn't match expected size of manifest header=%lu", 
                 sz, FD_SHREDCAP_MANIFEST_HDR_FOOTPRINT ));
  }
  if ( FD_UNLIKELY( close( manifest_fd ) ) ) {
    FD_LOG_ERR(( "unable to close the manifest file" ));
  }

  /* Write bank hash footer and update header */
  bank_hash_hdr.num_blocks = block_count;
  err = fd_io_buffered_ostream_write( bank_hash_ostream, &bank_hash_hdr, 
                                      FD_SHREDCAP_BANK_HASH_FTR_FOOTPRINT );
  if ( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "error writing bank hash file footer" ));
  }
  fd_io_buffered_ostream_flush( bank_hash_ostream );
  fd_io_buffered_ostream_fini( bank_hash_ostream );

  file_start_offset = lseek( bank_hash_fd, 0, SEEK_SET );
  if ( FD_UNLIKELY( file_start_offset == -1 ) ) {
    FD_LOG_ERR(( "lseek error when seeking to start of bank hash" ));
  }

  err = fd_io_write( bank_hash_fd, &bank_hash_hdr, FD_SHREDCAP_BANK_HASH_HDR_FOOTPRINT, 
                               FD_SHREDCAP_BANK_HASH_HDR_FOOTPRINT, &sz );
  if ( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "unable to write num_blocks=%lu for bank hash file header", num_files ));
  }
  if ( FD_UNLIKELY( sz != FD_SHREDCAP_BANK_HASH_HDR_FOOTPRINT ) ) {
    FD_LOG_ERR(( "size=%lu doesn't match expected size of bank hash header=%lu", 
                 sz, FD_SHREDCAP_BANK_HASH_HDR_FOOTPRINT ));
  }
  if ( FD_UNLIKELY( close( bank_hash_fd ) ) ) {
    FD_LOG_ERR(( "unable to close the bank_hash file" ));
  }

  fd_rocksdb_root_iter_destroy( &iter );
  fd_rocksdb_destroy( &rocks_db );                             
}

/***************** Verify Helpers *********************************************/
void
fd_shredcap_verify_slot( fd_shredcap_slot_hdr_t * slot_hdr, 
                           fd_blockstore_t *          blockstore,
                           int                        fd, 
                           char *                     rbuf ) {

          
  if ( FD_UNLIKELY( slot_hdr->magic != FD_SHREDCAP_SLOT_HDR_MAGIC ) ) {
    FD_LOG_ERR(( "slot header magic=%lu doesn't match expected magic=%lu",
                  slot_hdr->magic, FD_SHREDCAP_SLOT_HDR_MAGIC ));
  }
  if ( FD_UNLIKELY( slot_hdr->version != FD_SHREDCAP_SLOT_HDR_VERSION ) ) {
    FD_LOG_ERR(( "slot header version=%lu doesn't match expected version=%lu",
                  slot_hdr->version, FD_SHREDCAP_SLOT_HDR_VERSION ));
  }
  if ( FD_UNLIKELY( slot_hdr->payload_sz == ULONG_MAX ) ) {
    FD_LOG_ERR(( "slot payload_sz=%lu is at default value=%lu", slot_hdr->payload_sz ));
  }

  ulong slot       = slot_hdr->slot;
  ulong max_idx    = slot_hdr->received;
  ulong payload_sz = slot_hdr->payload_sz;

  int err;
  ulong sz;
  for ( ulong idx = 0; idx < max_idx; ++idx ) {
    /* Read shred header */
    err = fd_io_read( fd, rbuf, FD_SHREDCAP_SHRED_HDR_FOOTPRINT, 
                      FD_SHREDCAP_SHRED_HDR_FOOTPRINT, &sz );
    if ( FD_UNLIKELY( err != 0 ) ) {
      FD_LOG_ERR(( "unable to read shred hdr" ));
    }
    if ( FD_UNLIKELY( sz != FD_SHREDCAP_SHRED_HDR_FOOTPRINT ) ) {
      FD_LOG_ERR(( "read in size=%lu not equal to shred header footprint=%lu",
                   sz, FD_SHREDCAP_SHRED_HDR_FOOTPRINT ));
    }

    fd_shredcap_shred_hdr_t * shred_hdr = (fd_shredcap_shred_hdr_t*)rbuf;

    /* Read shred body and verify slot number */
    ulong shred_boundary_sz = shred_hdr->shred_boundary_sz;
    err = fd_io_read( fd, rbuf, shred_boundary_sz, shred_boundary_sz, &sz );
    if ( FD_UNLIKELY( err != 0 ) ) {
      FD_LOG_ERR(( "unable to read shred" ));
    }
    if ( FD_UNLIKELY( sz != shred_boundary_sz ) ) {
      FD_LOG_ERR(( "read in size=%lu not equal to shred footprint=%lu", sz, shred_boundary_sz ));
    }

    fd_shred_t * shred = (fd_shred_t*)rbuf;
    if ( FD_UNLIKELY( blockstore != NULL ) ) {
      fd_blockstore_shred_insert( blockstore, shred );
    }
    if ( FD_UNLIKELY( slot != shred->slot ) ) {
      FD_LOG_ERR(( "slot header's slot=%lu doesn't match shred's slot=%lu", slot, shred->slot ));
    }
  }

  /* Ensure that a block exists for the given slot */
  fd_block_t * block = fd_blockstore_block_query( blockstore, slot );
  if ( FD_UNLIKELY( block == NULL) ) {
    FD_LOG_ERR(( "block doesn't exist for slot=%lu", slot ));
  }

  /* Validate slot footer */
  err = fd_io_read( fd, rbuf, 0, FD_SHREDCAP_SLOT_FTR_FOOTPRINT, &sz );
  if ( FD_UNLIKELY( err != 0 ) ) {
    FD_LOG_ERR(( "unable to read slot footer" ));
  }
  if ( FD_UNLIKELY( sz != FD_SHREDCAP_SLOT_FTR_FOOTPRINT ) ) {
    FD_LOG_ERR(( "read in size=%lu not equal to slot footer footprint=%lu",
                  sz, FD_SHREDCAP_SLOT_FTR_FOOTPRINT ));
  }

  fd_shredcap_slot_ftr_t * slot_ftr = (fd_shredcap_slot_ftr_t*)rbuf;

  if ( FD_UNLIKELY( slot_ftr->magic != FD_SHREDCAP_SLOT_FTR_MAGIC ) ) {
    FD_LOG_ERR(( "slot footer's magic=%lu doesn't match expected magic=%lu", 
                 slot_ftr->magic, FD_SHREDCAP_SLOT_FTR_MAGIC ));
  }
  if ( FD_UNLIKELY( slot_ftr->payload_sz != payload_sz ) ) {
    FD_LOG_ERR(( "slot header's payload_sz=%lu doesn't match block footers's payload_sz=%lu",
                 slot_hdr->payload_sz, slot_ftr->payload_sz ));
  }
}

void 
fd_shredcap_verify_capture_file( const char *      capture_dir,
                                   const char *      capture_file, 
                                   fd_blockstore_t * blockstore,
                                   ulong             expected_start_slot,
                                   ulong             expected_end_slot,
                                   int               bank_hash_fd,
                                   char *            bank_hash_buf,
                                   ulong *           slots_seen ) {

  char capture_file_buf[ FD_SHREDCAP_CAPTURE_PATH_NAME_LENGTH ];
  fd_shredcap_concat( capture_file_buf, capture_dir, capture_file );
  
  int capture_fd = open( capture_file_buf, O_RDONLY, (mode_t)0 );
  if( FD_UNLIKELY( capture_fd == -1 ) ) {
    FD_LOG_WARNING(( "open(\"%s\",O_RDONLY,0) failed (%i-%s)", capture_file_buf, errno, fd_io_strerror( errno ) ));
    FD_LOG_ERR(( "can't read capture file, may not exist" ));
  }

  char rbuf[ RBUF_FOOTPRINT ] __attribute__((aligned(BUF_ALIGN)));

  /* Restore Header */
  ulong sz;
  int err = fd_io_read( capture_fd, &rbuf, 0, FD_SHREDCAP_FILE_HDR_FOOTPRINT, &sz );
  if ( FD_UNLIKELY( err != 0 ) ) {
    FD_LOG_ERR(( "unable to read file header" ));
  }
  if ( FD_UNLIKELY( sz != FD_SHREDCAP_FILE_HDR_FOOTPRINT ) ) {
    FD_LOG_ERR(( "read in size=%lu not equal to file header footprint=%lu",
                  sz, FD_SHREDCAP_FILE_HDR_FOOTPRINT ));
  }
  fd_shredcap_file_hdr_t * file_hdr_ptr = (fd_shredcap_file_hdr_t*)rbuf;

  /* Verifying file header */
  if ( FD_UNLIKELY( file_hdr_ptr->magic != FD_SHREDCAP_FILE_MAGIC ) ) {
    FD_LOG_ERR(( "file header magic=%lu doesn't match expected magic=%lu",
                 file_hdr_ptr->magic, FD_SHREDCAP_FILE_MAGIC ));
  }
  if ( FD_UNLIKELY( file_hdr_ptr->version != FD_SHREDCAP_FILE_VERSION ) ) {
    FD_LOG_ERR(( "file header version=%lu doesn't match expected version=%lu",
                 file_hdr_ptr->version, FD_SHREDCAP_FILE_VERSION ));
  }
  if ( FD_UNLIKELY( file_hdr_ptr->start_slot != expected_start_slot ) ) {
    FD_LOG_ERR(( "file header start_slot=%lu doesn't match manifest entry's start_slot=%lu",
                 file_hdr_ptr->start_slot, expected_start_slot ));
  }
  if ( FD_UNLIKELY( file_hdr_ptr->end_slot != expected_end_slot ) ) {
    FD_LOG_ERR(( "file header end_slot=%lu doesn't match manifest entry's end_slot=%lu",
                 file_hdr_ptr->end_slot, expected_end_slot ));
  }
  
  fd_shredcap_file_hdr_t file_hdr;
  fd_memcpy( &file_hdr, file_hdr_ptr, FD_SHREDCAP_FILE_HDR_FOOTPRINT );

  /* Want to create a loop here for the slot_hdr */
  ulong cur_slot = 0;
  while( cur_slot < expected_end_slot ) {
    ++(*slots_seen);
    err = fd_io_read( capture_fd, rbuf, FD_SHREDCAP_SLOT_HDR_FOOTPRINT, 
                      FD_SHREDCAP_SLOT_HDR_FOOTPRINT, &sz );
    if ( FD_UNLIKELY( err != 0 ) ) {
      FD_LOG_ERR(( "unable to read slot header" ));
    }
    if ( FD_UNLIKELY( sz != FD_SHREDCAP_SLOT_HDR_FOOTPRINT ) ) {
      FD_LOG_ERR(( "read in size=%lu not equal to slot header footprint=%lu",
                    sz, FD_SHREDCAP_SLOT_HDR_FOOTPRINT ));
    }

    /* Verify header contents and assemble blocks from shreds */
    fd_shredcap_slot_hdr_t * slot_hdr = (fd_shredcap_slot_hdr_t*)rbuf;
    cur_slot = slot_hdr->slot;
    fd_shredcap_verify_slot( slot_hdr, blockstore, capture_fd, rbuf );

    err = fd_io_read( bank_hash_fd, bank_hash_buf, FD_SHREDCAP_BANK_HASH_ENTRY_FOOTPRINT, 
                      FD_SHREDCAP_BANK_HASH_ENTRY_FOOTPRINT, &sz );
    if ( FD_UNLIKELY( err != 0 ) ) {
      FD_LOG_ERR(( "unable to read bank hash entry" ));
    }
    if ( FD_UNLIKELY( sz != FD_SHREDCAP_BANK_HASH_ENTRY_FOOTPRINT ) ) {
      FD_LOG_ERR(( "read in size=%lu not equal to bank hash entry footprint=%lu",
                    sz, FD_SHREDCAP_BANK_HASH_ENTRY_FOOTPRINT ));
    }
    fd_shredcap_bank_hash_entry_t * bank_hash_entry = (fd_shredcap_bank_hash_entry_t *)bank_hash_buf;
    if ( FD_UNLIKELY( bank_hash_entry->slot != cur_slot ) ) {
      FD_LOG_ERR(( "bank hash entry slot=%lu does not match capture file slot=%lu",
                   bank_hash_entry->slot, cur_slot ));
    }
  }

  /* Verify num blocks */
  if ( FD_UNLIKELY( file_hdr.num_blocks != *slots_seen ) ) {
    FD_LOG_ERR(( "file header num_blocks=%lu not equal to number of seen slots=%lu", 
                 file_hdr.num_blocks, *slots_seen ));
  }

  /* Verify file footer */
  err = fd_io_read( capture_fd, &rbuf, 0, FD_SHREDCAP_FILE_FTR_FOOTPRINT, &sz );
  if ( FD_UNLIKELY( err != 0 ) ) {
    FD_LOG_ERR(( "unable to read file footer" ));
  }
  if ( FD_UNLIKELY( sz != FD_SHREDCAP_FILE_FTR_FOOTPRINT ) ) {
    FD_LOG_ERR(( "read in size=%lu not equal to file footer footprint=%lu",
                  sz, FD_SHREDCAP_FILE_FTR_FOOTPRINT ));
  }

  fd_shredcap_file_ftr_t * file_ftr = (fd_shredcap_file_ftr_t*)rbuf;

  if ( FD_UNLIKELY( file_hdr.magic != file_ftr->magic ) ) {
    FD_LOG_ERR(( "file header magic=%lu doesn't match file footer magic=%lu",
                 file_hdr.magic, file_ftr->magic ));
  }
  if ( FD_UNLIKELY( file_hdr.version != file_ftr->version ) ) {
    FD_LOG_ERR(( "file header version=%lu doesn't match file footer version=%lu",
                 file_hdr.version, file_ftr->version ));
  }
  if ( FD_UNLIKELY( file_hdr.start_slot != file_ftr->start_slot ) ) {
    FD_LOG_ERR(( "file header start_slot=%lu doesn't match file footer start_slot=%lu",
                 file_hdr.start_slot, file_ftr->start_slot ));
  }
  if ( FD_UNLIKELY( file_hdr.end_slot != file_ftr->end_slot ) ) {
    FD_LOG_ERR(( "file header end_slot=%lu doesn't match file footer end_slot=%lu",
                 file_hdr.end_slot, file_ftr->end_slot ));
  }
  if ( FD_UNLIKELY( file_hdr.num_blocks != file_ftr->num_blocks ) ) {
    FD_LOG_ERR(( "file header num_blocks=%lu doesn't match file footer num_blocks=%lu",
                 file_hdr.num_blocks, file_ftr->num_blocks ));
  }

  if ( FD_UNLIKELY( close( capture_fd ) ) ) {
    FD_LOG_ERR(( "unable to close capture file=%s", capture_file ));
  }
}

void 
fd_shredcap_verify( const char * capture_dir, fd_blockstore_t * blockstore ) {
  FD_LOG_NOTICE(( "starting verify" ));
  /* Take the manifest file as the source of truth for what files we expect to
    read. This means we don't check for the case in which there are any files
    not described in the manifest. */
  char manifest_file_buf[ FD_SHREDCAP_CAPTURE_PATH_NAME_LENGTH ];
  fd_shredcap_concat( manifest_file_buf, capture_dir, "manifest" );

 /* Want to iterate through the manifest and make sure that every entry
     corresponds to a file. Also need to ensure that every file in the directory
     maps back to a manifest entry */
  int manifest_fd = open( manifest_file_buf, O_RDONLY, (mode_t)0 );
  if( FD_UNLIKELY( manifest_fd == -1 ) ) {
    FD_LOG_WARNING(( "open(\"%s\",O_RDONLY,0) failed (%i-%s)", 
                     manifest_file_buf, errno, fd_io_strerror( errno ) ));
    FD_LOG_ERR(( "can't open manifest file, may not exist" ));
  }

  /* Iterate through each entry on the bank_hash file and ensure that there is 
     a corresponding 1-to-1 entry for the capture*/
  char bank_hash_file_buf[ FD_SHREDCAP_CAPTURE_PATH_NAME_LENGTH ];
  fd_shredcap_concat( bank_hash_file_buf, capture_dir, "bank_hash" );

  int bank_hash_fd = open( bank_hash_file_buf, O_RDONLY, (mode_t)0 );
  if( FD_UNLIKELY( bank_hash_fd == -1 ) ) {
    FD_LOG_WARNING(( "open(\"%s\",O_RDONLY,0) failed (%i-%s)", 
                     bank_hash_file_buf, errno, fd_io_strerror( errno ) ));
    FD_LOG_ERR(( "can't open manifest file, may not exist" ));
  }

  char manifest_rbuf[ MANIFEST_BUF_FOOTPRINT ] __attribute__((aligned(BUF_ALIGN)));
  char bank_hash_rbuf[ BANK_HASH_BUF_FOOTPRINT ] __attribute__((aligned(BUF_ALIGN)));
  
  /* Read in manifest header */
  ulong sz;
  int err;
  err = fd_io_read( manifest_fd, &manifest_rbuf, FD_SHREDCAP_MANIFEST_HDR_FOOTPRINT, 
                    FD_SHREDCAP_MANIFEST_HDR_FOOTPRINT, &sz );
  if ( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "unable to read manifest header" ));
  }
  if ( FD_UNLIKELY( sz != FD_SHREDCAP_MANIFEST_HDR_FOOTPRINT ) ) {
    FD_LOG_ERR(( "read in size=%lu not equal to manifest header footprint=%lu",
                 sz, FD_SHREDCAP_MANIFEST_HDR_FOOTPRINT ));
  }

  fd_shredcap_manifest_hdr_t * manifest_hdr = (fd_shredcap_manifest_hdr_t*)manifest_rbuf;
  if ( FD_UNLIKELY( manifest_hdr->magic != FD_SHREDCAP_MANIFEST_MAGIC ) ) {
    FD_LOG_ERR(( "manifest header magic=%lu doesn't match expected value=%lu",
                 manifest_hdr->magic, FD_SHREDCAP_MANIFEST_MAGIC ));
  }
  if ( FD_UNLIKELY( manifest_hdr->version != FD_SHREDCAP_MANIFEST_VERSION ) ) {
    FD_LOG_ERR(( "manifest header version=%lu doesn't match expected version=%lu",
                 manifest_hdr->magic, FD_SHREDCAP_MANIFEST_VERSION ));
  }

  /* Read in bank hash header*/
  err = fd_io_read( bank_hash_fd, &bank_hash_rbuf, FD_SHREDCAP_BANK_HASH_HDR_FOOTPRINT, 
                    FD_SHREDCAP_BANK_HASH_HDR_FOOTPRINT, &sz );
  if ( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "unable to read bank hash header" ));
  }
  if ( FD_UNLIKELY( sz != FD_SHREDCAP_BANK_HASH_HDR_FOOTPRINT ) ) {
    FD_LOG_ERR(( "read in size=%lu not equal to bank hash header footprint=%lu",
                 sz, FD_SHREDCAP_BANK_HASH_HDR_FOOTPRINT ));
  }

  fd_shredcap_bank_hash_hdr_t * bank_hash_hdr = (fd_shredcap_bank_hash_hdr_t*)bank_hash_rbuf;
  if ( FD_UNLIKELY( bank_hash_hdr->magic != FD_SHREDCAP_BANK_HASH_MAGIC ) ) {
    FD_LOG_ERR(( "bank hash header magic=%lu is not equal to the expected magic=%lu",
                 bank_hash_hdr->magic, FD_SHREDCAP_BANK_HASH_MAGIC ));
  }
  if ( FD_UNLIKELY( bank_hash_hdr->version != FD_SHREDCAP_BANK_HASH_VERSION ) ) {
    FD_LOG_ERR(( "bank hash header version=%lu is not equal to the expected version=%lu",
                 bank_hash_hdr->version, FD_SHREDCAP_BANK_HASH_VERSION ));
  }
  if ( FD_UNLIKELY( manifest_hdr->start_slot != bank_hash_hdr->start_slot ) ) {
    FD_LOG_ERR(( "manifest header start_slot=%lu is not equal to bank hash start_slot=%lu",
                 manifest_hdr->start_slot, bank_hash_hdr->start_slot ));
  }
  if ( FD_UNLIKELY( manifest_hdr->end_slot != bank_hash_hdr->end_slot ) ) {
    FD_LOG_ERR(( "manifest header end_slot=%lu is not equal to bank hash start_slot=%lu",
                 manifest_hdr->end_slot, bank_hash_hdr->end_slot ));
  }
  /* Count slots seen to make sure that it matches with the bank hash header */
  ulong num_blocks = bank_hash_hdr->num_blocks;
  ulong slots_seen = 0;

  ulong start_slot = manifest_hdr->start_slot;
  ulong end_slot   = manifest_hdr->end_slot;
  uint  num_files  = manifest_hdr->num_files;

  for ( ulong i = 0; i < num_files; ++i ) {
    err = fd_io_read( manifest_fd, &manifest_rbuf, FD_SHREDCAP_MANIFEST_ENTRY_FOOTPRINT, 
                      FD_SHREDCAP_MANIFEST_ENTRY_FOOTPRINT, &sz );
    if ( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "unable to read manifest entry" ));
    }
    if ( FD_UNLIKELY( sz != FD_SHREDCAP_MANIFEST_ENTRY_FOOTPRINT ) ) {
      FD_LOG_ERR(( "read in size=%lu not equal to manifest entry footprint=%lu",
                  sz, FD_SHREDCAP_MANIFEST_ENTRY_FOOTPRINT ));
    }

    FD_TEST( sz == FD_SHREDCAP_MANIFEST_ENTRY_FOOTPRINT );
    fd_shredcap_manifest_entry_t * entry = (fd_shredcap_manifest_entry_t*)manifest_rbuf;
    ulong file_slots_seen = 0;
    fd_shredcap_verify_capture_file( capture_dir, entry->path, blockstore, 
                                       entry->start_slot, entry->end_slot,
                                       bank_hash_fd, bank_hash_rbuf, &file_slots_seen );
    slots_seen += file_slots_seen;
  }

  if ( ( FD_UNLIKELY( num_blocks != slots_seen ) ) ) {
    FD_LOG_ERR(( "expected block count=%lu, seen=%lu", num_blocks, slots_seen ));
  }

  err = fd_io_read( manifest_fd, &manifest_rbuf, FD_SHREDCAP_MANIFEST_FTR_FOOTPRINT, 
                    FD_SHREDCAP_MANIFEST_FTR_FOOTPRINT, &sz );
  if ( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "unable to read manifest footer" ));
  }
  if ( FD_UNLIKELY( sz != FD_SHREDCAP_MANIFEST_FTR_FOOTPRINT ) ) {
    FD_LOG_ERR(( "read in size=%lu not equal to manifest footer footprint=%lu",
                 sz, FD_SHREDCAP_MANIFEST_FTR_FOOTPRINT ));
  }

  fd_shredcap_manifest_ftr_t * manifest_ftr = (fd_shredcap_manifest_ftr_t*)manifest_rbuf;
  if ( FD_UNLIKELY( manifest_ftr->magic != FD_SHREDCAP_MANIFEST_MAGIC ) ) {
    FD_LOG_ERR(( "manifest footer magic=%lu doesn't match expected value=%lu",
                 manifest_ftr->magic, FD_SHREDCAP_MANIFEST_MAGIC ));
  }
  if ( FD_UNLIKELY( manifest_ftr->version != FD_SHREDCAP_SLOT_HDR_VERSION ) ) {
    FD_LOG_ERR(( "manifest footer version=%lu doesn't match expected version=%lu",
                 manifest_ftr->magic, FD_SHREDCAP_SLOT_HDR_VERSION ));
  }
  if ( FD_UNLIKELY( start_slot != manifest_ftr->start_slot ) ) {
    FD_LOG_ERR(( "manifest footer start_slot=%lu doesn't match manifest footer start_slot=%lu",
                 start_slot, manifest_ftr->start_slot ));
  }
  if ( FD_UNLIKELY( end_slot != manifest_ftr->end_slot ) ) {
    FD_LOG_ERR(( "manifest footer end_slot=%lu doesn't match manifest footer end_slot=%lu",
                 end_slot, manifest_ftr->end_slot ));
  }
  if ( FD_UNLIKELY( num_files != manifest_ftr->num_files ) ) {
    FD_LOG_ERR(( "manifest footer end_slot=%lu doesn't match manifest footer end_slot=%lu",
                 num_files, manifest_ftr->num_files ));
  }

  if ( FD_UNLIKELY( close( manifest_fd ) ) ) {
    FD_LOG_ERR(( "unable to successfully close manifest file %s", manifest_file_buf ));
  }

  err = fd_io_read( bank_hash_fd, bank_hash_rbuf, FD_SHREDCAP_BANK_HASH_FTR_FOOTPRINT,
                    FD_SHREDCAP_BANK_HASH_FTR_FOOTPRINT, &sz );
  if ( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "unable to read bank hash footer" ));
  }
  if ( FD_UNLIKELY( sz != FD_SHREDCAP_BANK_HASH_FTR_FOOTPRINT ) ) {
    FD_LOG_ERR(( "read in size=%lu not equal to bank hash footer footprint=%lu",
                  sz, FD_SHREDCAP_BANK_HASH_FTR_FOOTPRINT ));
  }

  fd_shredcap_bank_hash_ftr_t * bank_hash_ftr = (fd_shredcap_bank_hash_ftr_t*)bank_hash_rbuf;
  if ( FD_UNLIKELY( bank_hash_ftr->magic != FD_SHREDCAP_BANK_HASH_MAGIC ) ) {
    FD_LOG_ERR(( "bank hash footer magic=%lu is not equal to the expected magic=%lu",
                 bank_hash_ftr->magic, FD_SHREDCAP_BANK_HASH_MAGIC ));
  }
  if ( FD_UNLIKELY( bank_hash_ftr->num_blocks != num_blocks ) ) {
    FD_LOG_ERR(( "bank hash footer num blocks=%lu is not equal to the header's num_blocks=%lu",
                 bank_hash_ftr->num_blocks, num_blocks ));
  }
  if ( FD_UNLIKELY( manifest_ftr->start_slot != bank_hash_ftr->start_slot ) ) {
    FD_LOG_ERR(( "manifest footer start_slot=%lu is not equal to bank hash start_slot=%lu",
                 manifest_hdr->start_slot, bank_hash_ftr->start_slot ));
  }
  if ( FD_UNLIKELY( manifest_ftr->end_slot != bank_hash_ftr->end_slot ) ) {
    FD_LOG_ERR(( "manifest footer end_slot=%lu is not equal to bank hash start_slot=%lu",
                 manifest_hdr->end_slot, bank_hash_ftr->end_slot ));
  }

  if ( FD_UNLIKELY( close( bank_hash_fd ) ) ) {
    FD_LOG_ERR(( "unable to close the bank hash file" ));
  }
}
/******************************************************************************/
void
fd_shredcap_manifest_seek_range( const char * capture_dir,
                                 char * manifest_buf,
                                 ulong start_slot,
                                 ulong end_slot,
                                 ulong * start_file_idx,
                                 ulong * end_file_idx,
                                 int * manifest_fd ) {

  char manifest_file_buf[ FD_SHREDCAP_CAPTURE_PATH_NAME_LENGTH ];
  fd_shredcap_concat( manifest_file_buf, capture_dir, "manifest" );

  *manifest_fd = open( manifest_file_buf, O_RDONLY, (mode_t)0 );
  if( FD_UNLIKELY( *manifest_fd == -1 ) ) {
    FD_LOG_WARNING(( "open(\"%s\",O_RDONLY,0) failed (%i-%s)", 
                     manifest_file_buf, errno, fd_io_strerror( errno ) ));
    FD_LOG_ERR(( "unable to open manifest file for blockstore range" ));
  }

  ulong sz;
  int err;
  err = fd_io_read( *manifest_fd, manifest_buf, FD_SHREDCAP_MANIFEST_HDR_FOOTPRINT, 
                    FD_SHREDCAP_MANIFEST_HDR_FOOTPRINT, &sz );
  if ( FD_UNLIKELY( err != 0 ) ) {
    FD_LOG_ERR(( "unable to read manifest header" ));
  }
  if ( FD_UNLIKELY( sz != FD_SHREDCAP_MANIFEST_HDR_FOOTPRINT ) ) {
    FD_LOG_ERR(( "read in size=%lu not equal to manifest header footprint=%lu",
                  sz, FD_SHREDCAP_MANIFEST_HDR_FOOTPRINT ));
  }
    
  /* Do basic checks on user input */
  fd_shredcap_manifest_hdr_t * manifest_hdr = (fd_shredcap_manifest_hdr_t*)manifest_buf;
  ulong num_files = manifest_hdr->num_files;

  if ( FD_UNLIKELY( start_slot < manifest_hdr->start_slot ) ) {
    FD_LOG_ERR(( "start_slot=%lu is less than the capture's first slot=%lu", 
                 start_slot, manifest_hdr->start_slot ));
  }
  if ( FD_UNLIKELY( start_slot > manifest_hdr->end_slot ) ) {
    FD_LOG_ERR(( "start_slot=%lu is greater than the capture's last slot=%lu",
                 start_slot, manifest_hdr->start_slot ));
  }
  if ( FD_UNLIKELY( end_slot < manifest_hdr->start_slot ) ) {
    FD_LOG_ERR(( "end_slot=%lu is less than the capture's first slot=%lu",
                 end_slot, manifest_hdr->start_slot ));
  }
  if ( FD_UNLIKELY( end_slot > manifest_hdr->end_slot ) ) {
    FD_LOG_ERR(( "end_slot=%lu is greater than the capture's last slot=%lu",
                 end_slot, manifest_hdr->end_slot ));
  }

  /* Binary search through the manifest for the start_file */
  ulong left  = 0;
  ulong right = num_files - 1;
  while ( left < right ) {
    ulong middle = ( left + right ) / 2;
    /* Seek to correct offset */
    ulong middle_offset = middle * FD_SHREDCAP_MANIFEST_ENTRY_FOOTPRINT + 
                          FD_SHREDCAP_MANIFEST_HDR_FOOTPRINT;
    long offset = lseek( *manifest_fd, (long)middle_offset, SEEK_SET );
    if ( FD_UNLIKELY( offset == -1 ) ) {
      FD_LOG_ERR(( "unable to lseek to manifest entry offset=%ld", middle_offset ));
    }

    err = fd_io_read( *manifest_fd, manifest_buf, FD_SHREDCAP_MANIFEST_ENTRY_FOOTPRINT, 
                      FD_SHREDCAP_MANIFEST_ENTRY_FOOTPRINT, &sz );
    if ( FD_UNLIKELY( err != 0 ) ) {
      FD_LOG_ERR(( "unable to read manifest entry for file index=%lu", middle ));
    }
    if ( FD_UNLIKELY( sz != FD_SHREDCAP_MANIFEST_ENTRY_FOOTPRINT ) ) {
      FD_LOG_ERR(( "read in size=%lu not equal to manifest entry footprint=%lu",
                   sz, FD_SHREDCAP_MANIFEST_ENTRY_FOOTPRINT ));
    }
    fd_shredcap_manifest_entry_t * entry = (fd_shredcap_manifest_entry_t*)manifest_buf;

    if ( start_slot <= entry->end_slot ) {
      right = middle;
    }
    else {
      left = middle + 1;
    }
  }
  *start_file_idx = left;

  /* Repeat binary search for the end file */
  left  = 0;
  right = num_files - 1;
  while ( left < right ) {
    ulong middle = ( left + right ) / 2;
    /* Seek to correct offset */
    ulong middle_offset = middle * FD_SHREDCAP_MANIFEST_ENTRY_FOOTPRINT + 
                          FD_SHREDCAP_MANIFEST_HDR_FOOTPRINT;
    long offset = lseek( *manifest_fd, (long)middle_offset, SEEK_SET );
    if ( FD_UNLIKELY( offset == -1 ) ) {
      FD_LOG_ERR(( "unable to lseek to manifest entry offset=%ld", middle_offset ));
    }

    err = fd_io_read( *manifest_fd, manifest_buf, FD_SHREDCAP_MANIFEST_ENTRY_FOOTPRINT, 
                      FD_SHREDCAP_MANIFEST_ENTRY_FOOTPRINT, &sz );
    if ( FD_UNLIKELY( err != 0 ) ) {
      FD_LOG_ERR(( "unable to read manifest entry for file index=%lu", middle ));
    }
    if ( FD_UNLIKELY( sz != FD_SHREDCAP_MANIFEST_ENTRY_FOOTPRINT ) ) {
      FD_LOG_ERR(( "read in size=%lu not equal to manifest entry footprint=%lu",
                   sz, FD_SHREDCAP_MANIFEST_ENTRY_FOOTPRINT ));
    }
    fd_shredcap_manifest_entry_t * entry = (fd_shredcap_manifest_entry_t*)manifest_buf;
    
    if ( end_slot <= entry->end_slot ) {
      right = middle;
    }
    else {
      left = middle + 1;
    }
  }
  *end_file_idx = left;
}

void
fd_shredcap_bank_hash_seek_first( const char * capture_dir,
                                  char * bank_hash_buf,
                                  ulong start_slot,
                                  ulong end_slot,
                                  ulong * first_slot_idx,
                                  int * bank_hash_fd ) {

  char bank_hash_file_buf[ FD_SHREDCAP_CAPTURE_PATH_NAME_LENGTH ];
  fd_shredcap_concat( bank_hash_file_buf, capture_dir,"bank_hash" );

  *bank_hash_fd = open( bank_hash_file_buf, O_RDONLY, (mode_t)0 );
  if( FD_UNLIKELY( *bank_hash_fd == -1 ) ) {
    FD_LOG_WARNING(( "open(\"%s\",O_RDONLY,0) failed (%i-%s)", 
                     bank_hash_file_buf, errno, fd_io_strerror( errno ) ));
    FD_LOG_ERR(( "unable to open bank hash file for blockstore range" ));
  }

  ulong sz;
  int err;
  err = fd_io_read( *bank_hash_fd, bank_hash_buf, FD_SHREDCAP_BANK_HASH_HDR_FOOTPRINT, 
                    FD_SHREDCAP_BANK_HASH_HDR_FOOTPRINT, &sz );
  if ( FD_UNLIKELY( err != 0 ) ) {
    FD_LOG_ERR(( "unable to read bank hash header" ));
  }
  if ( FD_UNLIKELY( sz != FD_SHREDCAP_BANK_HASH_HDR_FOOTPRINT ) ) {
    FD_LOG_ERR(( "read in size=%lu not equal to bank hash header footprint=%lu",
                 sz, FD_SHREDCAP_BANK_HASH_HDR_FOOTPRINT ));
  }
    
  /* Do basic checks on user input */
  fd_shredcap_bank_hash_hdr_t * bank_hash_hdr = (fd_shredcap_bank_hash_hdr_t*)bank_hash_buf;
  ulong num_blocks = bank_hash_hdr->num_blocks;

  /* Leaving these as warnings because bank hashes aren't needed to populate a
     blockstore. This should really not be happening however. */
  if ( FD_UNLIKELY( start_slot < bank_hash_hdr->start_slot ) ) {
    FD_LOG_WARNING(( "start_slot=%lu is less than the bank_hash's first slot=%lu", 
                 start_slot, bank_hash_hdr->start_slot ));
  }
  if ( FD_UNLIKELY( start_slot > bank_hash_hdr->end_slot ) ) {
    FD_LOG_ERR(( "start_slot=%lu is greater than the bank_hash's last slot=%lu",
                 start_slot, bank_hash_hdr->start_slot ));
  }
  if ( FD_UNLIKELY( end_slot < bank_hash_hdr->start_slot ) ) {
    FD_LOG_ERR(( "end_slot=%lu is less than the bank_hash's first slot=%lu",
                 end_slot, bank_hash_hdr->start_slot ));
  }
  if ( FD_UNLIKELY( end_slot > bank_hash_hdr->end_slot ) ) {
    FD_LOG_ERR(( "end_slot=%lu is greater than the bank_hash's last slot=%lu",
                 end_slot, bank_hash_hdr->start_slot ));
  }

  /* Binary search through the bank hash file */
  ulong left  = 0;
  ulong right = num_blocks - 1;
  while ( left < right ) {
    ulong middle = ( left + right ) / 2;
    /* Seek to correct offset*/
    ulong middle_offset = middle * FD_SHREDCAP_BANK_HASH_ENTRY_FOOTPRINT + 
                          FD_SHREDCAP_BANK_HASH_HDR_FOOTPRINT;
    long offset = lseek( *bank_hash_fd, (long)middle_offset, SEEK_SET );
    if ( FD_UNLIKELY( offset == -1 ) ) {
      FD_LOG_ERR(( "unable to lseek to bank hash file offset=%ld", offset ));
    }

    err = fd_io_read( *bank_hash_fd, bank_hash_buf, FD_SHREDCAP_BANK_HASH_ENTRY_FOOTPRINT, 
                      FD_SHREDCAP_BANK_HASH_ENTRY_FOOTPRINT, &sz );
    if ( FD_UNLIKELY( err != 0 ) ) {
      FD_LOG_ERR(( "unable to read bank hash entry at slot index=%lu", middle ));
    }
    if ( FD_UNLIKELY( sz != FD_SHREDCAP_BANK_HASH_ENTRY_FOOTPRINT ) ) {
      FD_LOG_ERR(( "read in size=%lu not equal to bank hash entry footprint=%lu",
                  sz, FD_SHREDCAP_BANK_HASH_ENTRY_FOOTPRINT ));
    }

    fd_shredcap_bank_hash_entry_t * entry = (fd_shredcap_bank_hash_entry_t*)bank_hash_buf;
    if ( entry->slot >= start_slot ) {
      right = middle;
    }
    else {
      left = middle + 1;
    }
  }

  /* left corresponds to the index in the bank hash file which is the smallest
     slot number greater than or equal to start_slot */
  *first_slot_idx = left;
}

void
fd_shredcap_populate_blockstore( const char *      capture_dir, 
                                   fd_blockstore_t * blockstore, 
                                   ulong             start_slot,
                                   ulong             end_slot ) {
  if ( FD_UNLIKELY( start_slot > end_slot ) ) {
    FD_LOG_ERR(( "start_slot=%lu must be less than the end_slot=%lu", start_slot, end_slot ));
  }

  /* Get start file idx from the manifest */
  char manifest_buf[ MANIFEST_BUF_FOOTPRINT ];
  ulong start_file_idx;
  ulong end_file_idx;
  int manifest_fd;
  fd_shredcap_manifest_seek_range( capture_dir, manifest_buf, start_slot, end_slot, 
                                   &start_file_idx, &end_file_idx, &manifest_fd );

  /* Get first relevant slot and idx from the bank hash file */
  char bank_hash_buf[ BANK_HASH_BUF_FOOTPRINT ];
  ulong first_slot_idx;
  int bank_hash_fd;
  fd_shredcap_bank_hash_seek_first( capture_dir, bank_hash_buf, start_slot, end_slot, 
                                    &first_slot_idx, &bank_hash_fd );
  ulong cur_bank_hash_slot_idx = first_slot_idx;

  char capture_buf[ RBUF_FOOTPRINT ];  

  ulong sz;
  int err;
  long offset;

  /* Open and iterate through as many files as necesary to build up blockstore */
  for ( ulong file_idx = start_file_idx; file_idx <= end_file_idx; ++file_idx ) {
    ulong file_offset = file_idx * FD_SHREDCAP_MANIFEST_ENTRY_FOOTPRINT + 
                        FD_SHREDCAP_MANIFEST_HDR_FOOTPRINT;
    offset = lseek( manifest_fd, (long)file_offset, SEEK_SET );
    if ( FD_UNLIKELY( offset == -1 ) ) {
      FD_LOG_ERR(( "unable to seek to offset=%lu in manifest", file_offset ));
    }

    err = fd_io_read( manifest_fd, manifest_buf, FD_SHREDCAP_MANIFEST_ENTRY_FOOTPRINT, 
                      FD_SHREDCAP_MANIFEST_ENTRY_FOOTPRINT, &sz );
    if ( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "error when reading manifest entry" ));
    }
    if ( FD_UNLIKELY( sz != FD_SHREDCAP_MANIFEST_ENTRY_FOOTPRINT ) ) {
      FD_LOG_ERR(( "unexpected size read=%lu for manifest entry", sz ));
    }

    fd_shredcap_manifest_entry_t * entry = (fd_shredcap_manifest_entry_t*)manifest_buf;

    char file_path_buf[ FD_SHREDCAP_CAPTURE_PATH_NAME_LENGTH ];
    fd_memset( file_path_buf, '\0', FD_SHREDCAP_CAPTURE_PATH_NAME_LENGTH );
    fd_cstr_append_text( file_path_buf, capture_dir, strlen( capture_dir ) );
    fd_cstr_append_cstr( file_path_buf + strlen( capture_dir ), entry->path );

    int capture_fd = open( file_path_buf, O_RDONLY, (mode_t)0 );
    if( FD_UNLIKELY( capture_fd == -1 ) ) {
      FD_LOG_WARNING(( "open(\"%s\",O_RDONLY,0) failed (%i-%s)", 
                       file_path_buf, errno, fd_io_strerror( errno ) ));
      FD_LOG_ERR(( "unable to open capture file for blockstore range" ));
    }

    err = fd_io_read( capture_fd, capture_buf, FD_SHREDCAP_FILE_HDR_FOOTPRINT, 
                      FD_SHREDCAP_FILE_HDR_FOOTPRINT, &sz );
    if ( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "error when reading shredcap file header" ));
    }
    if ( FD_UNLIKELY( sz != FD_SHREDCAP_FILE_HDR_FOOTPRINT ) ) {
      FD_LOG_ERR(( "unexpected size read=%lu for capture file header", sz ));
    }
    fd_shredcap_file_hdr_t * file_hdr = (fd_shredcap_file_hdr_t*)capture_buf;
    FD_TEST((file_hdr->magic == FD_SHREDCAP_FILE_MAGIC));

    ulong cur_slot      = file_hdr->start_slot;
    ulong file_end_slot = file_hdr->end_slot;

    while ( cur_slot < file_end_slot ) {
      /* Read in block header */
      err = fd_io_read( capture_fd, capture_buf, FD_SHREDCAP_SLOT_HDR_FOOTPRINT, 
                        FD_SHREDCAP_SLOT_HDR_FOOTPRINT, &sz );
      if ( FD_UNLIKELY( err ) ) {
        FD_LOG_ERR(( "error when reading shredcap slot header" ));
      }
      if ( FD_UNLIKELY( sz != FD_SHREDCAP_SLOT_HDR_FOOTPRINT ) ) {
        FD_LOG_ERR(( "unexpected size read=%lu for capture slot header", sz ));
      }
                        
      fd_shredcap_slot_hdr_t * slot_hdr = (fd_shredcap_slot_hdr_t*)capture_buf;
      cur_slot = slot_hdr->slot;
      ulong max_idx = slot_hdr->received;
      FD_TEST((slot_hdr->magic == FD_SHREDCAP_SLOT_HDR_MAGIC));
      if ( cur_slot > end_slot ) {
        break;
      }

      if ( cur_slot < start_slot ) {
        /* Skip forward to next slot*/
        offset = lseek( capture_fd, (long)(slot_hdr->payload_sz + FD_SHREDCAP_SLOT_FTR_FOOTPRINT), SEEK_CUR );
        if ( FD_UNLIKELY( offset == -1 ) ) {
          FD_LOG_ERR(( "unable to lseek to next slot entry from slot=%lu", cur_slot ));
        }
        continue;
      }

      /* Read in shreds and assemble */
      for ( ulong shred_idx = 0; shred_idx < max_idx; ++shred_idx ) {
        err = fd_io_read( capture_fd, capture_buf, FD_SHREDCAP_SHRED_HDR_FOOTPRINT, 
                          FD_SHREDCAP_SHRED_HDR_FOOTPRINT, &sz );
        if ( FD_UNLIKELY( err ) ) {
          FD_LOG_ERR(( "error when reading shredcap shred header" ));
        }
        if ( FD_UNLIKELY( sz != FD_SHREDCAP_SHRED_HDR_FOOTPRINT ) ) {
          FD_LOG_ERR(( "unexpected size read=%lu for shred header", sz ));
        }

        fd_shredcap_shred_hdr_t * shred_hdr = (fd_shredcap_shred_hdr_t*)capture_buf;
        ulong shred_boundary_sz = shred_hdr->shred_boundary_sz;
        FD_TEST((shred_hdr->hdr_sz == FD_SHREDCAP_SHRED_HDR_FOOTPRINT));
        err = fd_io_read( capture_fd, capture_buf, shred_boundary_sz, shred_boundary_sz, &sz );
        if ( FD_UNLIKELY( err ) ) {
          FD_LOG_ERR(( "error when reading shredcap shred for slot=%lu", cur_slot ));
        }
        if ( FD_UNLIKELY( sz != shred_boundary_sz ) ) {
          FD_LOG_ERR(( "unexpected size read=%lu for shred", sz ));
        }
        
        fd_shred_t * shred = (fd_shred_t*)capture_buf;
        fd_blockstore_shred_insert( blockstore, shred );
      }

      offset = lseek( capture_fd, (long)FD_SHREDCAP_SLOT_FTR_FOOTPRINT, SEEK_CUR );
      if ( FD_UNLIKELY( offset == -1 ) ) {
        FD_LOG_ERR(( "unable to lseek past slot footer for slot=%lu", cur_slot ));
      }

      /* Populate bank hash for each slot */
      ulong cur_bank_hash_slot_offset = cur_bank_hash_slot_idx * FD_SHREDCAP_BANK_HASH_ENTRY_FOOTPRINT + 
                                FD_SHREDCAP_BANK_HASH_HDR_FOOTPRINT;
      offset = lseek( bank_hash_fd, (long)cur_bank_hash_slot_offset, SEEK_SET );
      if ( FD_UNLIKELY( offset == -1 ) ) {
        FD_LOG_ERR(( "unable to lseek to bank hash_slot at index=%lu", cur_bank_hash_slot_idx ));
      }

      err = fd_io_read( bank_hash_fd, bank_hash_buf, FD_SHREDCAP_BANK_HASH_ENTRY_FOOTPRINT, 
                        FD_SHREDCAP_BANK_HASH_ENTRY_FOOTPRINT, &sz );
      if ( FD_UNLIKELY( err ) ) {
        FD_LOG_ERR(( "error when reading bank hash entry" ));
      }
      if ( FD_UNLIKELY( sz != FD_SHREDCAP_BANK_HASH_ENTRY_FOOTPRINT ) ) {
        FD_LOG_ERR(( "unexpected size read=%lu for bank hash entry", sz ));
      }

      fd_shredcap_bank_hash_entry_t * entry = (fd_shredcap_bank_hash_entry_t*)bank_hash_buf;
      fd_blockstore_slot_map_t * block_map = fd_blockstore_slot_map( blockstore );
      fd_blockstore_slot_map_t * block_entry = fd_blockstore_slot_map_query( block_map, cur_slot, NULL );
      fd_memcpy( block_entry->block.bank_hash.hash, &entry->bank_hash.hash, 32UL );

      ++cur_bank_hash_slot_idx;
    }

    if ( FD_UNLIKELY( close( capture_fd ) ) ) {
      FD_LOG_ERR(( "unable to close the capture file=%s", file_path_buf ));
    }
    if ( cur_slot > end_slot ) {
      break;
    }
  }
  if ( FD_UNLIKELY( close( manifest_fd ) ) ) {
    FD_LOG_ERR(( "unable to close the manifest file" ));
  }
  if ( FD_UNLIKELY( close( bank_hash_fd ) ) ) {
    FD_LOG_ERR(( "unable to close the bank hash file" ));
  }
}
