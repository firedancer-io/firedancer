#ifndef HEADER_fd_src_funk_fd_funk_part_h
#define HEADER_fd_src_funk_fd_funk_part_h

/* This provides APIs for managing funk record partitions. */

struct fd_funk_parthead {
  ulong  head_idx;      /* Record map index of the first record in parition, FD_FUNK_REC_IDX_NULL if none */
  ulong  tail_idx;      /* "                       last          " */
};

typedef struct fd_funk_parthead fd_funk_parthead_t;

struct fd_funk_partvec {
    uint num_part;               /* Number of partitions */
    fd_funk_parthead_t heads[1]; /* Partition headers indexed by partition number */
};

typedef struct fd_funk_partvec fd_funk_partvec_t;

FD_FN_PURE static inline ulong fd_funk_partvec_align(void) {
  return alignof(fd_funk_partvec_t);
}
FD_FN_PURE static inline ulong
fd_funk_partvec_footprint(uint num_part) {
  return sizeof(fd_funk_partvec_t) + (fd_uint_max(num_part, 1U) - 1U)*sizeof(fd_funk_parthead_t);
}

/* Get the partition vector structure which controls the partitions */
fd_funk_partvec_t *
fd_funk_get_partvec( fd_funk_t * funk,
                     fd_wksp_t * wksp /* Assumes wksp == fd_funk_wksp( funk ) */);

/* Initialize partition fields in a record to default values */
void fd_funk_part_init( fd_funk_rec_t * rec );

/* Set the partition number of a record. Use FD_FUNK_PART_NULL to
   remove the record from its current partition. Otherwise, the
   partition number must be less than the num_part value given in the
   last call to fd_funk_repartition. Returns an error code. */
int fd_funk_part_set_intern( fd_funk_partvec_t * partvec,
                             fd_funk_rec_t *     rec_map,
                             fd_funk_rec_t *     rec,
                             uint                part );

int fd_funk_part_set( fd_funk_t *     funk,
                      fd_funk_rec_t * rec,
                      uint            part );

/* Resize the partition vector and reassign partition numbers to all
   records using a callback function to get the value. num_part must
   be a relatively small integer (i.e. < 1,000,000). The internal data
   structure if a vector of size num_part. */
typedef uint (*fd_funk_repartition_cb)(fd_funk_rec_t * rec, uint num_part, void * cb_arg);

void fd_funk_repartition(fd_funk_t *            funk,
                         uint                   num_part,
                         fd_funk_repartition_cb cb,
                         void *                 cb_arg);

/* Get the first record in the partition. Used for iteration. */
FD_FN_PURE static inline fd_funk_rec_t const *
fd_funk_part_head( fd_funk_partvec_t *   partvec,
                   uint                  part,
                   fd_funk_rec_t const * rec_map ) { /* Assumes == fd_funk_rec_map( funk, fd_funk_wksp( funk ) ) */
  if( part >= partvec->num_part ) return NULL;
  ulong rec_head_idx = partvec->heads[part].head_idx;
  if( fd_funk_rec_idx_is_null( rec_head_idx ) ) return NULL;
  return rec_map + rec_head_idx;
}

/* Get the next record in the partition. Used for iteration. */
FD_FN_PURE static inline fd_funk_rec_t const *
fd_funk_part_next( fd_funk_rec_t const * rec,
                   fd_funk_rec_t const * rec_map ) { /* Assumes == fd_funk_rec_map( funk, fd_funk_wksp( funk ) ) */
  ulong rec_idx = rec->next_part_idx;
  if( fd_funk_rec_idx_is_null( rec_idx ) ) return NULL;
  return rec_map + rec_idx;
}

/* Misc */

/* fd_funk_part_verify verifies the partitions. Returns FD_FUNK_SUCCESS
   if the record map appears intact and FD_FUNK_ERR_INVAL if not (logs
   details).  Meant to be called as part of fd_funk_verify. */

int
fd_funk_part_verify( fd_funk_t * funk );

#endif /* HEADER_fd_src_funk_fd_funk_part_h */
