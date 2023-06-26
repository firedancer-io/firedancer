#include "fd_fseq.h"

/* fd_fseq_shmem_t specifies the layout of a shared memory region
   containing an fseq */

#define FD_FSEQ_MAGIC (0xf17eda2c37f5ec00UL) /* firedancer fseq ver 0 */

struct __attribute__((aligned(FD_FSEQ_ALIGN))) fd_fseq_shmem {
  ulong magic; /* == FD_FSEQ_MAGIC */
  ulong seq0;  /* Initial sequence number */
  ulong seq;   /* Current sequence number */
  /* Padding to FD_FSEQ_APP_ALIGN here */
  /* FD_FSEQ_APP_FOOTPRINT for app region here */
  /* Padding to FD_FSEQ_ALIGN here */
};

typedef struct fd_fseq_shmem fd_fseq_shmem_t;

ulong
fd_fseq_align( void ) {
  return FD_FSEQ_ALIGN;
}

ulong
fd_fseq_footprint( void ) {
  return FD_FSEQ_FOOTPRINT;
}

void *
fd_fseq_new( void * shmem,
             ulong  seq0 ) {

   if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_fseq_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  } 

  fd_fseq_shmem_t * fseq = (fd_fseq_shmem_t *)shmem;

  memset( fseq, 0, FD_FSEQ_FOOTPRINT );

  fseq->seq0 = seq0;
  fseq->seq  = seq0;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( fseq->magic ) = FD_FSEQ_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

ulong *
fd_fseq_join( void * shfseq ) {

  if( FD_UNLIKELY( !shfseq ) ) {
    FD_LOG_WARNING(( "NULL shfseq" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shfseq, fd_fseq_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shfseq" ));
    return NULL;
  }

  fd_fseq_shmem_t * fseq = (fd_fseq_shmem_t *)shfseq;

  if( FD_UNLIKELY( fseq->magic!=FD_FSEQ_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return &fseq->seq;
}

void *
fd_fseq_leave( ulong const * fseq ) {

  if( FD_UNLIKELY( !fseq ) ) {
    FD_LOG_WARNING(( "NULL or bad shfseq" ));
    return NULL;
  }

  return (void *)(fseq-2);
}

void *
fd_fseq_delete( void * shfseq ) {

  if( FD_UNLIKELY( !shfseq ) ) {
    FD_LOG_WARNING(( "NULL shfseq" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shfseq, fd_fseq_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shfseq" ));
    return NULL;
  }

  fd_fseq_shmem_t * fseq = (fd_fseq_shmem_t *)shfseq;

  if( FD_UNLIKELY( fseq->magic!=FD_FSEQ_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( fseq->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return (void *)fseq;
}

