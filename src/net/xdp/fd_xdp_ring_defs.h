#ifndef HEADER_fd_xdp_ring_defs_h
#define HEADER_fd_xdp_ring_defs_h

/* iterate over ring types */
#define FD_RING_ITER_TYPES(X,...)                                                             \
  X( rx, struct xdp_desc, rx_ring_size,         XDP_PGOFF_RX_RING             , __VA_ARGS__ ) \
  X( tx, struct xdp_desc, tx_ring_size,         XDP_PGOFF_TX_RING             , __VA_ARGS__ ) \
  X( fr, ulong,        fill_ring_size,       XDP_UMEM_PGOFF_FILL_RING      , __VA_ARGS__ ) \
  X( cr, ulong,        completion_ring_size, XDP_UMEM_PGOFF_COMPLETION_RING, __VA_ARGS__ )

/* get the size of a ring entry */
#define FD_RING_ENTRY_SIZE(RING) (sizeof(ring_##RING##_t))

/* define a ring */
#define FD_RING_DEF( RING, ENTRY_TP, SZ, OFFSET, ... ) \
  typedef ENTRY_TP fd_ring_entry_##RING##_t;           \
  struct fd_ring_##RING##_desc {                       \
    void *     mem;                                    \
    ENTRY_TP * ring;                                   \
    ulong * flags;                                  \
    ulong     sz;                                     \
    ulong * prod;                                   \
    ulong * cons;                                   \
    ulong   cached_prod;                            \
    ulong   cached_cons;                            \
  };                                                   \
  typedef struct fd_ring_##RING##_desc fd_ring_##RING##_desc_t;

/* define a member */
#define FD_RING_MEMBER( RING, ENTRY_TP, SZ, OFFSET, ... ) \
  fd_ring_##RING##_desc_t ring_##RING;

/* mmap a ring */
/* TODO, mmap was originally called with MAP_POPULATE, but this symbol isn't available with this build */
#define FD_RING_MMAP( RING, TP, SZ, OFFSET, OBJ, ERR, ... )                                               \
  (OBJ).ring_##RING.mem = mmap( NULL, (OBJ).offsets.RING.desc + (OBJ).config.SZ * sizeof(TP),             \
      PROT_READ | PROT_WRITE, MAP_SHARED, (OBJ).xdp_sock, OFFSET );                                       \
  if( (OBJ).ring_##RING.mem != MAP_FAILED ) {                                                             \
    (OBJ).ring_##RING.ring  = (TP*)( (ulong)(OBJ).ring_##RING.mem + (OBJ).offsets.RING.desc );           \
    (OBJ).ring_##RING.flags = (ulong*)( (ulong)(OBJ).ring_##RING.mem + (OBJ).offsets.RING.flags );    \
    (OBJ).ring_##RING.sz    = (OBJ).config.SZ;                                                            \
    (OBJ).ring_##RING.prod  = (ulong*)( (ulong)(OBJ).ring_##RING.mem + (OBJ).offsets.RING.producer ); \
    (OBJ).ring_##RING.cons  = (ulong*)( (ulong)(OBJ).ring_##RING.mem + (OBJ).offsets.RING.consumer ); \
  } else ERR

/* mmap a ring */
#define FD_RING_MMAP_OLD( RING, TP, SZ, OFFSET, OBJ, ... )                                        \
  (RING).mem = mmap( NULL, offsets.RING.desc + SZ * sizeof(TP),                                   \
      PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, OFFSET );                            \
  if( (RING).mem == MAP_FAILED ) {                                                                \
    fprintf( stderr, "unable to mmap %s ring. Error: %d %s\n", #RING, errno, strerror( errno ) ); \
    exit(1);                                                                                      \
  }                                                                                               \
  (RING).ring  = (TP*)( (ulong)(RING).mem + offsets.RING.desc );                                 \
  (RING).flags = (ulong*)( (ulong)(RING).mem + offsets.RING.flags );                          \
  (RING).sz    = SZ;                                                                              \
  (RING).prod  = (ulong*)( (ulong)(RING).mem + offsets.RING.producer );                       \
  (RING).cons  = (ulong*)( (ulong)(RING).mem + offsets.RING.consumer );


#define FD_RING_TYPE(RING) fd_ring_entry_##RING##_t
#define FD_RING_GET_AVAIL(RING) ( *(RING).prod - *(RING).cons )
#define FD_RING_ENQUEUE(RING,VALUE)                \
  do {                                             \
    if( FD_RING_GET_AVAIL(RING) < (RING).sz ) {    \
      ulong prod = *(RING).prod;                  \
      ulong mask = (RING).sz - 1;                 \
      (RING).ring[ prod & mask ] = (VALUE);        \
      __asm__ __volatile__( "" : : : "memory" );   \
      *(RING).prod = prod + 1;                     \
      __asm__ __volatile__( "" : : : "memory" );   \
    }                                              \
  } while(0)

#define FD_RING_TEST_GET_AVAIL(OBJ,RING) ( *(OBJ).ring_##RING.prod - *(OBJ).ring_##RING.cons )

#define FD_RING_TEST_ENQUEUE(OBJ,RING,VALUE)                         \
  do {                                                               \
    if( FD_RING_TEST_GET_AVAIL(OBJ,RING) < (OBJ).ring_##RING.sz ) {  \
      ulong prod = *(OBJ).ring_##RING.prod;                         \
      ulong mask = (OBJ).ring_##RING.sz - 1;                        \
      (OBJ).ring_##RING.ring[ prod & mask ] = (VALUE);               \
      __asm__ __volatile__( "" : : : "memory" );                     \
      *(OBJ).ring_##RING.prod = prod + 1;                            \
      __asm__ __volatile__( "" : : : "memory" );                     \
    }                                                                \
  } while(0)

/* use to avoid warnings of unused types */
#define FD_RING_USE(RING,...) do { FD_RING_TYPE(RING) _; (void)_; } while(0);

#endif // HEADER_fd_xdp_ring_defs_h

