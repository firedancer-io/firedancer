#include "fd_groove.h"

#include "fd_groove_data.h"

void *
fd_groove_new( void * shmem,
               ulong meta_map_ele_max,
               ulong meta_map_seed ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_groove_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( shmem );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "shmem must be part of a workspace" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_groove_t *          groove             = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_groove_t), sizeof(fd_groove_t) );
  void *                 meta_map_ele_shmem = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_groove_meta_t), fd_ulong_sat_mul( meta_map_ele_max, sizeof(fd_groove_meta_t) ) );
  void *                 meta_map           = FD_SCRATCH_ALLOC_APPEND( l, fd_groove_meta_map_align(), fd_groove_meta_map_footprint(
        meta_map_ele_max,
        fd_groove_meta_map_lock_cnt_est( meta_map_ele_max ),
        fd_groove_meta_map_probe_max_est( meta_map_ele_max ) ) );
  void *                data_shmem          = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_groove_data_t), fd_groove_data_footprint() );
  FD_SCRATCH_ALLOC_FINI( l, fd_groove_align() );

  /* Initialize the Groove object */
  memset( groove, 0, sizeof(fd_groove_t) );
  groove->magic = FD_GROOVE_MAGIC;

  /* Initialize the Groove metadata map element store */
  memset( meta_map_ele_shmem, 0, fd_ulong_sat_mul( meta_map_ele_max, sizeof(fd_groove_meta_t) ) );

  /* Initialize the metadata map */
  ulong meta_map_lock_cnt  = fd_groove_meta_map_lock_cnt_est( meta_map_ele_max );
  ulong meta_map_probe_max = fd_groove_meta_map_probe_max_est( meta_map_ele_max );
  if( FD_UNLIKELY( !fd_groove_meta_map_new( meta_map,
                                            meta_map_ele_max,
                                            meta_map_lock_cnt,
                                            meta_map_probe_max,
                                            meta_map_seed ) ) ) {
    FD_LOG_WARNING(( "fd_groove_meta_map_new failed" ));
    return NULL;
  }

  /* Initialize the Groove data store */
  if( FD_UNLIKELY( !fd_groove_data_new( data_shmem ) ) ) {
    FD_LOG_WARNING(( "fd_groove_data_new failed" ));
    return NULL;
  }

  return groove;
}

/* fd_groove_join joins a groove in the shmem region pointed to by
   shgroove into the local join region pointed to by ljoin.  volume0
   points to the first byte of the volume region in the caller's address
   space.  volume_max is the maximum number of volumes that can be
   mapped into the caller's address space.  If volume_max is 0, the
   implementation default maximum will be used.  cgroup_hint is a hint
   about which concurrency group the caller will be in.  On success,
   returns ljoin.  On failure, returns NULL (logs details). */

fd_groove_t *
fd_groove_join( void * shmem,
                ulong  meta_map_ele_max,
                void * volume0,
                ulong  volume_max,
                ulong  cgroup_hint ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_groove_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_groove_t *          groove             = FD_SCRATCH_ALLOC_APPEND( l, fd_groove_align(), sizeof(fd_groove_t) );
  void *                 meta_map_ele_shmem = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_groove_meta_t), fd_ulong_sat_mul( meta_map_ele_max, sizeof(fd_groove_meta_t) ) );
  void *                 meta_map           = FD_SCRATCH_ALLOC_APPEND( l, fd_groove_meta_map_align(), fd_groove_meta_map_footprint(
        meta_map_ele_max,
        fd_groove_meta_map_lock_cnt_est( meta_map_ele_max ),
        fd_groove_meta_map_probe_max_est( meta_map_ele_max ) ) );
  void *                data_shmem          = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_groove_data_t), fd_groove_data_footprint() );
  FD_SCRATCH_ALLOC_FINI( l, fd_groove_align() );

  fd_wksp_t * wksp = fd_wksp_containing( groove );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "groove must be part of a workspace" ));
    return NULL;
  }

  /* Check the magic */
  if( FD_UNLIKELY( groove->magic != FD_GROOVE_MAGIC ) ) {
    FD_LOG_WARNING(( "invalid groove magic" ));
    return NULL;
  }

  /* Join the metadata map */ /* meta_map is unaligned */
  if( FD_UNLIKELY( !fd_groove_meta_map_join( groove->meta_map, meta_map, meta_map_ele_shmem ) ) ) {
    FD_LOG_WARNING(( "fd_groove_meta_map_join failed" ));
    return NULL;
  }

  /* Join the data store */
  if( FD_UNLIKELY( !fd_groove_data_join( groove->data, data_shmem, volume0, volume_max, cgroup_hint ) ) ) {
    FD_LOG_WARNING(( "fd_groove_data_join failed" ));
    return NULL;
  }

  return groove;
}

/* fd_groove_leave leaves a groove.  On success, returns join.  On
   failure, returns NULL (logs details). */

void *
fd_groove_leave( fd_groove_t * groove ) {
  if( FD_UNLIKELY( !groove ) ) {
    FD_LOG_WARNING(( "NULL groove" ));
    return NULL;
  }

  /* Check the magic */
  if( FD_UNLIKELY( groove->magic != FD_GROOVE_MAGIC ) ) {
    FD_LOG_WARNING(( "invalid groove magic" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_groove_data_leave( groove->data ) ) ) {
    FD_LOG_WARNING(( "fd_groove_data_leave failed" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_groove_meta_map_leave( groove->meta_map ) ) ) {
    FD_LOG_WARNING(( "fd_groove_meta_map_leave failed" ));
    return NULL;
  }

  return groove;
}

/* Initialize the groove key. */
void
groove_key_init( fd_pubkey_t const * pubkey,
                 fd_groove_key_t *   key ) {
  fd_memcpy( key->c, pubkey, sizeof(fd_pubkey_t) );
}

/* Inserts an account into Groove, updating the account if it already exists. */
void
fd_groove_upsert_account( fd_groove_t *       groove,
                          fd_pubkey_t const * pubkey,
                          uchar *             data,
                          ulong               data_len ) {
  fd_groove_key_t groove_key[1];
  groove_key_init( pubkey, groove_key );

  /* Look up the account in Groove metadata store */
  fd_groove_meta_map_query_t query[1];
  int err = fd_groove_meta_map_prepare( groove->meta_map, groove_key, NULL, query, FD_MAP_FLAG_BLOCKING );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "fd_groove_meta_map_prepare failed: %d", err ));
    return;
  }

  fd_groove_meta_t * meta = fd_groove_meta_map_query_ele(query);
  int used                = fd_groove_meta_bits_used( meta->bits );

  /* If the account does not exist, insert it */
  if( FD_UNLIKELY( !used ) ) {
    /* Allocate a new region for the account */
    int alloc_err;
    void *new_region = fd_groove_data_alloc( groove->data,
                                           FD_GROOVE_DATA_ALLOC_ALIGN_DEFAULT,
                                           data_len,
                                           0, /* tag */
                                           &alloc_err );
    if( FD_UNLIKELY(alloc_err) ) {
      FD_LOG_ERR(( "fd_groove_data_alloc failed: %d", alloc_err ));
      return;
    }

    /* Copy the account data into the new region */
    fd_memcpy( new_region, data, data_len );

    /* Insert an entry into the metadata map */
    /* TODO: better val_max */
    meta->bits = fd_groove_meta_bits( 1, data_len, data_len );
    meta->val_off = (ulong)new_region - (ulong)fd_groove_data_volume0(groove->data);
    fd_memcpy( meta->key.c, pubkey, sizeof(fd_pubkey_t) );
    fd_groove_meta_map_publish( query );

    return;
  }

  /* Account exists - check to see if the account size has been modified */
  ulong   val_size = fd_groove_meta_bits_val_sz(meta->bits);
  uchar * old_data = (uchar *)fd_type_pun(fd_groove_data_volume0(groove->data)) + meta->val_off;
  if ( FD_UNLIKELY(val_size != data_len) ) {
    /* Allocate new region with updated size */
    int alloc_err;
    void *new_region = fd_groove_data_alloc(groove->data,
                                           FD_GROOVE_DATA_ALLOC_ALIGN_DEFAULT,
                                           data_len,
                                           0, /* tag */
                                           &alloc_err);
    if( FD_UNLIKELY(alloc_err) ) {
      FD_LOG_ERR(( "fd_groove_data_alloc failed: %d", alloc_err ));
      fd_groove_meta_map_cancel( query );
      return;
    }

    /* Copy new data into the allocated region */
    fd_memcpy( new_region, data, data_len );

    /* Update metadata to point to new region */
    fd_groove_meta_t *mutable_meta = fd_groove_meta_map_query_ele(query);
    mutable_meta->bits             = fd_groove_meta_bits(1, data_len, data_len);
    mutable_meta->val_off          = (ulong)new_region - (ulong)fd_groove_data_volume0(groove->data);
    fd_groove_meta_map_publish( query );

    /* Free old region */
    if (FD_UNLIKELY( fd_groove_data_free( groove->data, old_data ) != FD_GROOVE_SUCCESS )) {
      FD_LOG_ERR(( "failed to free old data region" ));
      return;
    }

    return;
  }

  /* Account data size is the same, so we can just copy the data into the old region */
  /* We do not need to update the metadata map because the account data size is the same */
  fd_memcpy( old_data, data, data_len );
  fd_groove_meta_map_cancel( query );
}

static void
fd_groove_update_meta_region( fd_groove_t *      groove,
                              fd_groove_meta_t * meta,
                              uchar *            new_region,
                              ulong              data_len ) {
  meta->bits = fd_groove_meta_bits(1, data_len, data_len);
  meta->val_off = (ulong)new_region - (ulong)fd_groove_data_volume0(groove->data);
}

static void
fd_groove_populate_account_region( uchar *                         groove_data_region,
                                   ulong                           slot,
                                   fd_solana_account_hdr_t const * hdr ) {
  /* Copy the account metadata into the new region */
  fd_account_meta_t * meta = fd_type_pun(groove_data_region);
  fd_memset( meta, 0, sizeof(fd_account_meta_t) );
  meta->magic = FD_ACCOUNT_META_MAGIC;
  meta->hlen  = sizeof(fd_account_meta_t);
  meta->dlen  = hdr->meta.data_len;
  meta->slot  = slot;
  fd_memcpy( &meta->hash, &hdr->hash, sizeof(fd_hash_t) );
  fd_memcpy( &meta->info, &hdr->info, sizeof(fd_solana_account_meta_t) );
}

uchar *
fd_groove_upsert_account_from_snapshot( fd_groove_t *                   groove,
                                        fd_pubkey_t const *             pubkey,
                                        ulong                           slot,
                                        fd_solana_account_hdr_t const * hdr,
                                        int *                           out_err ) {
  fd_groove_key_t groove_key[1];
  groove_key_init( pubkey, groove_key );

  /* Look up the account in Groove metadata store */
  fd_groove_meta_map_query_t query[1];
  int err = fd_groove_meta_map_prepare( groove->meta_map, groove_key, NULL, query, FD_MAP_FLAG_BLOCKING );
  if( FD_UNLIKELY( err ) ) {
    if( FD_UNLIKELY( err == FD_MAP_ERR_FULL ) ) {
      FD_LOG_ERR(( "groove metadata map is full. need to increase FD_GROOVE_META_MAP_ELE_MAX" ));
      return NULL;
    } else {
      FD_LOG_ERR(( "fd_groove_meta_map_prepare failed: %d", err ));
      return NULL;
    }
  }

  fd_groove_meta_t * groove_meta = fd_groove_meta_map_query_ele(query);
  int used                       = fd_groove_meta_bits_used( groove_meta->bits );
  ulong val_size                 = sizeof(fd_account_meta_t) + hdr->meta.data_len;

  /* If the account exists, check to see if the version we are inserting is newer or the account data size has changed */
  if( FD_UNLIKELY( used ) ) {
    /* Check to see if the version we are inserting is newer */
    ulong val_off            = groove_meta->val_off;
    uchar * val_data         = (uchar *)fd_groove_data_volume0(groove->data) + val_off;
    fd_account_meta_t * meta = fd_type_pun( val_data );
    if( FD_UNLIKELY( meta->slot > slot ) ) {
      /* The version we are inserting is older, so we don't need to do anything */
      fd_groove_meta_map_cancel( query );
      return NULL;
    }

    /* Check to see if the account data size has changed, if so re-allocate the region in Groove */
    if( FD_UNLIKELY( meta->dlen != hdr->meta.data_len ) ) {
      /* Allocate new region with updated size */
      int alloc_err;
      void *new_region = fd_groove_data_alloc( groove->data,
                                          FD_GROOVE_DATA_ALLOC_ALIGN_DEFAULT,
                                          val_size,
                                          0, /* tag */
                                          &alloc_err );
      if( FD_UNLIKELY(alloc_err || !new_region) ) {
        fd_groove_meta_map_cancel( query );
        FD_LOG_ERR(( "fd_groove_data_alloc failed: %d", alloc_err ));
      }
      fd_groove_update_meta_region( groove, groove_meta, new_region, val_size );

      /* Free the old region */
      if (FD_UNLIKELY( fd_groove_data_free( groove->data, val_data ) != FD_GROOVE_SUCCESS )) {
        fd_groove_meta_map_cancel( query );
        FD_LOG_ERR(( "failed to free old data region" ));
      }

      /* Copy the account data into the new region */
      fd_groove_populate_account_region( new_region, slot, hdr );
      fd_groove_meta_map_publish( query );
      return new_region;
    }
  }

  /* This is a fresh account, so we need to allocate a new region */
  int alloc_err;
  void *new_region = fd_groove_data_alloc( groove->data,
                                          FD_GROOVE_DATA_ALLOC_ALIGN_DEFAULT,
                                          val_size,
                                          0, /* tag */
                                          &alloc_err );
  if( FD_UNLIKELY(alloc_err || !new_region) ) {
    fd_groove_meta_map_cancel( query );
    if( out_err ) {
      *out_err = alloc_err;
    }
    return NULL;
  }
  groove_meta->key = *groove_key;
  fd_groove_update_meta_region( groove, groove_meta, new_region, val_size );

  /* Populate the account region */
  fd_groove_populate_account_region( new_region, slot, hdr );
  fd_groove_meta_map_publish( query );

  return new_region;
}
