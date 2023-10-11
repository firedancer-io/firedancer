#include "fd_funk.h"

fd_funk_partvec_t *
fd_funk_get_partvec( fd_funk_t * funk,
                     fd_wksp_t * wksp /* Assumes wksp == fd_funk_wksp( funk ) */) {
  return (fd_funk_partvec_t *)fd_wksp_laddr_fast( wksp, funk->partvec_gaddr );
}

void
fd_funk_part_init( fd_funk_rec_t * rec ) {
  rec->prev_part_idx = FD_FUNK_REC_IDX_NULL;
  rec->next_part_idx = FD_FUNK_REC_IDX_NULL;
  rec->part = FD_FUNK_PART_NULL;
}

/* Private function */
static int
fd_funk_part_remove( fd_funk_partvec_t * partvec,
                     fd_funk_rec_t *     rec_map,
                     fd_funk_rec_t *     rec,
                     uint                part) {
  if ( FD_UNLIKELY( part >= partvec->num_part ) )
    return FD_FUNK_ERR_INVAL;

  fd_funk_parthead_t * head = &partvec->heads[part];

  ulong prev_idx = rec->prev_part_idx;
  ulong next_idx = rec->next_part_idx;

  int prev_null = fd_funk_rec_idx_is_null( prev_idx );
  int next_null = fd_funk_rec_idx_is_null( next_idx );

  if( prev_null ) head->head_idx                    = next_idx;
  else            rec_map[ prev_idx ].next_part_idx = next_idx;

  if( next_null ) head->tail_idx                    = prev_idx;
  else            rec_map[ next_idx ].prev_part_idx = prev_idx;

  rec->prev_part_idx = FD_FUNK_REC_IDX_NULL;
  rec->next_part_idx = FD_FUNK_REC_IDX_NULL;
  rec->part = FD_FUNK_PART_NULL;
  return FD_FUNK_SUCCESS;
}

/* Private function */
static int
fd_funk_part_add( fd_funk_partvec_t * partvec,
                  fd_funk_rec_t *     rec_map,
                  fd_funk_rec_t *     rec,
                  uint                part) {
  if ( FD_UNLIKELY( part >= partvec->num_part ) )
    return FD_FUNK_ERR_INVAL;

  fd_funk_parthead_t * head = &partvec->heads[part];

  ulong rec_idx = (ulong)(rec - rec_map);
  ulong old_tail_idx = head->tail_idx;
  rec->prev_part_idx = old_tail_idx;
  head->tail_idx = rec_idx;

  rec->next_part_idx = FD_FUNK_REC_IDX_NULL;

  if ( fd_funk_rec_idx_is_null( old_tail_idx ) ) head->head_idx = rec_idx;
  else                                           rec_map[old_tail_idx].next_part_idx = rec_idx;

  rec->part = part;
  return FD_FUNK_SUCCESS;
}

int
fd_funk_part_set_intern( fd_funk_partvec_t * partvec,
                         fd_funk_rec_t *     rec_map,
                         fd_funk_rec_t *     rec,
                         uint                part) {
  if (part == rec->part) return FD_FUNK_SUCCESS;

  int err;
  if (rec->part != FD_FUNK_PART_NULL) {
    err = fd_funk_part_remove( partvec, rec_map, rec, rec->part );
    if ( FD_UNLIKELY( err ) ) return err;
  }

  if (part != FD_FUNK_PART_NULL) {
    err = fd_funk_part_add( partvec, rec_map, rec, part );
    if ( FD_UNLIKELY( err ) ) return err;
  }

  return FD_FUNK_SUCCESS;
}

int
fd_funk_part_set( fd_funk_t *     funk,
                  fd_funk_rec_t * rec,
                  uint            part) {
  fd_wksp_t * wksp = fd_funk_wksp( funk );
  return fd_funk_part_set_intern( fd_funk_get_partvec(funk, wksp),
                                  fd_funk_rec_map(funk, wksp),
                                  rec,
                                  part );
}

void
fd_funk_repartition(fd_funk_t *            funk,
                    uint                   num_part,
                    fd_funk_repartition_cb cb,
                    void *                 cb_arg) {
  fd_wksp_t * wksp = fd_funk_wksp( funk );
  fd_funk_partvec_t * partvec = fd_funk_get_partvec( funk, wksp );
  fd_funk_rec_t * rec_map = fd_funk_rec_map( funk, wksp );
  fd_alloc_t * alloc = fd_funk_alloc( funk, wksp );

  /* Rebuild the header vector */
  fd_alloc_free( alloc, partvec );

  ulong tmp_max;
  partvec = (fd_funk_partvec_t *)fd_alloc_malloc_at_least( alloc, fd_funk_partvec_align(), fd_funk_partvec_footprint(num_part), &tmp_max );
  if( FD_UNLIKELY( !partvec ) ) {
    FD_LOG_ERR(( "partvec alloc failed" ));
    return;
  }
  partvec->num_part = num_part;
  funk->partvec_gaddr = fd_wksp_gaddr_fast( wksp, partvec );

  for ( uint i = 0; i < num_part; ++i )
    partvec->heads[i].head_idx = partvec->heads[i].tail_idx = FD_FUNK_REC_IDX_NULL;

  for( fd_funk_rec_map_iter_t iter = fd_funk_rec_map_iter_init( rec_map );
       !fd_funk_rec_map_iter_done( rec_map, iter );
       iter = fd_funk_rec_map_iter_next( rec_map, iter ) ) {
    fd_funk_rec_t * rec = fd_funk_rec_map_iter_ele( rec_map, iter );
    fd_funk_part_init( rec );
  }

  for( fd_funk_rec_map_iter_t iter = fd_funk_rec_map_iter_init( rec_map );
       !fd_funk_rec_map_iter_done( rec_map, iter );
       iter = fd_funk_rec_map_iter_next( rec_map, iter ) ) {
    fd_funk_rec_t * rec = fd_funk_rec_map_iter_ele( rec_map, iter );
    if ( !(rec->flags & FD_FUNK_REC_FLAG_ERASE) ) {
      uint part = (*cb)(rec, num_part, cb_arg);
      if (part != FD_FUNK_PART_NULL) {
        int err = fd_funk_part_add( partvec, rec_map, rec, part );
        if ( FD_UNLIKELY( err ) ) FD_LOG_WARNING(( "error during repartition: %d", err ));
      }
    }
  }
}

int
fd_funk_part_verify( fd_funk_t * funk ) {
  fd_wksp_t * wksp = fd_funk_wksp( funk );
  fd_funk_partvec_t * partvec = fd_funk_get_partvec( funk, wksp );
  fd_funk_rec_t * rec_map = fd_funk_rec_map( funk, wksp );

  ulong cnt = 0;
  for ( uint i = 0; i < partvec->num_part; ++i ) {
    ulong prev = FD_FUNK_REC_IDX_NULL;
    ulong cur = partvec->heads[i].head_idx;
    while ( !fd_funk_rec_idx_is_null(cur) ) {
      fd_funk_rec_t * rec = rec_map + cur;
      if ( fd_funk_rec_map_private_unbox_tag( rec->map_next ) || (rec->flags & FD_FUNK_REC_FLAG_ERASE) ) {
        FD_LOG_WARNING(( "partition contains deleted record" ));
        return FD_FUNK_ERR_INVAL;
      }
      if ( rec->prev_part_idx != prev ) {
        FD_LOG_WARNING(( "prev_part_idx is wrong" ));
        return FD_FUNK_ERR_INVAL;
      }
      if ( rec->part != i ) {
        FD_LOG_WARNING(( "part is wrong" ));
        return FD_FUNK_ERR_INVAL;
      }
      prev = cur;
      cur = rec->next_part_idx;
      ++cnt;
    }
    if ( partvec->heads[i].tail_idx != prev ) {
      FD_LOG_WARNING(( "tail_idx is wrong" ));
      return FD_FUNK_ERR_INVAL;
    }
  }

  ulong cnt2 = 0;
  for( fd_funk_rec_map_iter_t iter = fd_funk_rec_map_iter_init( rec_map );
       !fd_funk_rec_map_iter_done( rec_map, iter );
       iter = fd_funk_rec_map_iter_next( rec_map, iter ) ) {
    fd_funk_rec_t * rec = fd_funk_rec_map_iter_ele( rec_map, iter );
    if (rec->part != FD_FUNK_PART_NULL)
      ++cnt2;
  }
  if ( cnt != cnt2 ) {
    FD_LOG_WARNING(( "part is wrong for some records" ));
    return FD_FUNK_ERR_INVAL;
  }

  return FD_FUNK_SUCCESS;
}
