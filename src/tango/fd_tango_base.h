#ifndef HEADER_fd_src_tango_fd_tango_base_h
#define HEADER_fd_src_tango_fd_tango_base_h

/* Tango messaging concepts:

   - Each message comes from a single local origin.  Each origin has a
     13-bit id that uniquely identifies it within a set of message
     producers and consumers for the lifetime of the set.  Origins
     typically include a mixture of network receiving devices, local
     message publishers, etc.  Applications might restrict the set of
     origins / add additional context / structure to origins id as
     need.

   - Messages are partitioned into one or more disjoint fragments.  The
     number of message payload bytes in a message fragment is in
     [0,2^16).  That is, message fragment size is any 16-bit unsigned
     int (thus bounded and variable).  Zero sized fragments are
     legitimate (e.g. one use case for this is heartbeating a stalled
     send of a large multi-fragment message).  Note that this is large
     enough to allow a maximum size UDP payload to be published in a
     single message fragment.  Applications might chose to impose
     additional limitations on message fragmentation.

   - Each fragment has a 64-bit sequence number that is unique over a
     (potentially dynamic) set of communicating message producers and
     consumers for the lifetime of that set.  Note that the use of a
     64-bit sequence number means that sequence number reuse is not an
     issue practically (would take hundreds of years even at highly
     local unrealistic messaging rates from producers to consumers).
     Note also that it is possible to use a smaller sequence number and
     deal with the implications of sequence number reuse via a number of
     standard techniques (epochs, TCP timestamp style, etc ... possibly
     with some minor additional constraints).  This is not done here for
     code simplicity / robustness / flexibility.

   - Message fragment sequence numbers increase sequentially with no
     gaps over the set of all producers for the set's lifetime.  As
     such, if a consumer encounters a gap in fragment sequence numbers,
     it knows it was overrun and has lost a message fragment (but
     typically that consumer does not know the origin of the lost
     fragment and needs to react accordingly).

   - The message fragment sequence numbers increase monotonically but
     not necessarily sequentially as the fragments from messages from
     different origins may be interleaved in fragment sequence number.

   - Each fragment is timestamped accordingly to when its origin first
     started producing it (tsorig) and when it was made first available
     for consumers (tspub).  As these are used mostly for monitoring and
     diagnostic purposes, they are stored in a temporally and/or
     precision compressed representation to free up room for other
     metadata.

  -  tsorig is measured on the origin's wallclock and the tspub is
     measured on the consumer facing publisher's wallclock (these are
     often the same wallclock).  As such, tsorig from the same origin
     will be monotonically increasing and tspub will be monotonically
     increasing across all fragments from all origins.

   - The wallclocks used for the timestamping should be reasonably well
     synchronized in the sense described in util/log.  As such
     timestamps measured by the same wallclocks will be exactly
     spatially comparable and approximately temporally comparable and
     timestamps measured by different wallclocks are both approximately
     spatially and temporally comparable.  Applications might chose to
     use things like preexisting host globally synchronized hardware
     tickcounters (e.g. RDTSC) for these instead of the system wallclock
     to reduce overheads.

   - Message fragments are distributed strictly in order.  There is no
     inherent limit to the number of fragments in a message.
     Applications might impose additional restrictions as appropriate
     for their needs.

   - To facilitate message reassembly, each fragment has a set of
     control bits that specify message boundaries and other conditions
     that might occur during message distribution.

     * SOM ("start-of-message"): This indicates this fragment starts a
       message from the fragment's origin.

     * EOM ("end-of-message"): This indicates this fragment ends a
       message from the fragment's origin.  If a consumer sees all the
       fragment sequence numbers between the sequence number of an SOM
       fragment from an origin to the sequence number of an EOM fragment
       from that origin inclusive, it knows that it has received all
       fragments for that message without loss from that origin.

     * ERR ("error"): This indicates that the _entire_ message to which
       the fragment belongs should be considered as corrupt (e.g. CRC
       checks that happen at the very end of network packet reception
       are the typical reason for this and these inherent cannot be
       checked until the last fragment).

   - To facilitate high performance message distribution, each fragment
     has a 64-bit message signature.  How the signature is used is
     application defined.  A typical use case is to have the first
     fragment of a message signify (in an application dependent way)
     which consumers are definitely known a priori to be uninterested in
     the message (such that those consumer doesn't have to spend any
     bandwidth or compute to reassemble or parse message payloads while
     still preserving common sequencing and ordering of all messages
     between all consumers).

   - For similar reasons, recent message fragments are typically stored
     in two separate caches:  A fragment metadata cache ("mcache", which
     behaves like a hybrid of a ring and a direct mapped cache ... it
     maps recently published fragment sequence numbers to fragment
     metadata) and a fragment payload cache (which is more flexibly
     allocated at "chunk" granularity as per the capabilities and needs
     of the individual origins). */

#include "../util/fd_util.h"

#if FD_HAS_SSE /* also covers FD_HAS_AVX */
#include <x86intrin.h>
#endif

/* FD_CHUNK_{LG_SZ,ALIGN,FOOTPRINT,SZ} describe the granularity of
   message fragment payload allocations.  ALIGN==FOOTPRINT==SZ==2^LG_SZ
   and recommend this to be something like a cache line practically. */

#define FD_CHUNK_LG_SZ     (6)
#define FD_CHUNK_ALIGN     (64UL) /* == 2^FD_CHUNK_LG_SZ, explicit to workaround compiler limitations */
#define FD_CHUNK_FOOTPRINT (64UL) /* " */
#define FD_CHUNK_SZ        (64UL) /* " */

/* FD_CHUNK_{LG_SZ,ALIGN,FOOTPRINT,SZ} describe the coarse layout of
   message fragment structures.
   sizeof(fd_frag_meta_t)==ALIGN==FOOTPRINT==SZ==2^LG_SZ.  Recommend
   this to be something like a positive integer multiple or an integer
   power of two divisor of a cache line size. */

#define FD_FRAG_META_LG_SZ     (5)
#define FD_FRAG_META_ALIGN     (32UL) /* == 2^FD_FRAG_META_LG_SZ, explicit to workaround compiler limitations */
#define FD_FRAG_META_FOOTPRINT (32UL) /* " */
#define FD_FRAG_META_SZ        (32UL) /* " */

/* FD_FRAG_META_ORIG_MAX specifies the maximum number of message origins
   that are supported.  Origins ids are in [0,FD_FRAG_META_ORIG_MAX). */

#define FD_FRAG_META_ORIG_MAX (8192UL)

/* fd_frag_meta_t specifies the message fragment metadata. */

union __attribute__((aligned(FD_FRAG_META_ALIGN))) fd_frag_meta {

  struct {

    /* First aligned SSE word ... these are strictly updated atomically */

    ulong  seq; /* naturally atomic r/w, frag sequence number. */
    ulong  sig; /* naturally atomic r/w, application defined message signature for fast consumer side filtering
                   performance is best if this is updated atomically with seq */

    /* Second aligned SSE word ... these are typically updated
       atomically but there is no guarantee both SSE words are jointly
       updated atomically. */

    uint   chunk;  /* naturally atomic r/w, compressed relative location of first byte of the frag in data region. */
    ushort sz;     /* naturally atomic r/w, Frag size in bytes. */
    ushort ctl;    /* naturally atomic r/w, Message reassembly control bits (origin/clock domain, SOM/EOM/ERR flags) */
    uint   tsorig; /* naturally atomic r/w, Message diagnostic compressed timestamps */
    uint   tspub;  /* naturally atomic r/w, " */

  };


  /* Intel architecture manual 3A section 8.1.1 (April 2022):

       Processors that enumerate support for Intel AVX (by setting the
       feature flag CPUID.01H:ECX.AVX[bit 28]) guarantee that the
       16-byte memory operations performed by the following instructions
       will always be carried out atomically:

       - MOVAPD, MOVAPS, and MOVDQA.
       - VMOVAPD, VMOVAPS, and VMOVDQA when encoded with VEX.128.
       - VMOVAPD, VMOVAPS, VMOVDQA32, and VMOVDQA64 when encoded with
         EVEX.128 and k0 (masking disabled).

       (Note that these instructions require the linear addresses of
       their memory operands to be 16-byte aligned.)

     That is accesses to "sse0" and "sse1" below are atomic when AVX
     support is available given the overall structure alignment,
     appropriate intrinsics and what not.  Accesses to avx are likely
     atomic on many x86 platforms but this is not guaranteed and such
     should not be assumed. */

# if FD_HAS_SSE
  struct {
    __m128i sse0; /* naturally atomic r/w, covers seq and sig */
    __m128i sse1; /* naturally atomic r/w, covers chunk, sz, ctl, tsorig and tspub */
  };
# endif

# if FD_HAS_AVX
  __m256i avx; /* Possibly non-atomic but can hold the metadata in a single register */
# endif

};

typedef union fd_frag_meta fd_frag_meta_t;

FD_PROTOTYPES_BEGIN

/* fd_seq_{lt,le,eq,ne,ge,gt} compare 64-bit sequence numbers with
   proper handling of sequence number wrapping (e.g. if, for example, we
   decide to randomize the initial sequence numbers used by an
   application for security reasons and by chance pick a sequence number
   near 2^64 such that wrapping sequence numbers 0 occurs.  That is,
   sequence number reuse is not an issue practically in a real world
   application but sequence number wrapping is if we want to support
   things like initial sequence number randomization for security.

   fd_seq_{inc,dec} returns the result of incrementing/decrementing
   sequence number a delta times.

   fd_seq_diff returns the how many sequence numbers a is ahead of b.
   Positive/negative values means a is in the future/past of b.  Zero
   indicates a and b are the same.

   In general operations on sequence numbers are strongly encouraged to
   use this macros as such facilitates updating code to accommodate
   things like changing the width of a sequence number. */

FD_FN_CONST static inline int fd_seq_lt( ulong a, ulong b ) { return ((long)(a-b))< 0L; }
FD_FN_CONST static inline int fd_seq_le( ulong a, ulong b ) { return ((long)(a-b))<=0L; }
FD_FN_CONST static inline int fd_seq_eq( ulong a, ulong b ) { return a==b;              }
FD_FN_CONST static inline int fd_seq_ne( ulong a, ulong b ) { return a!=b;              }
FD_FN_CONST static inline int fd_seq_ge( ulong a, ulong b ) { return ((long)(a-b))>=0L; }
FD_FN_CONST static inline int fd_seq_gt( ulong a, ulong b ) { return ((long)(a-b))> 0L; }

FD_FN_CONST static inline ulong fd_seq_inc( ulong a, ulong delta ) { return a+delta; }
FD_FN_CONST static inline ulong fd_seq_dec( ulong a, ulong delta ) { return a-delta; }

FD_FN_CONST static inline long fd_seq_diff( ulong a, ulong b ) { return (long)(a-b); }

/* fd_chunk_to_laddr: returns a pointer in the local address space to
   the first byte of the chunk with the given compressed relative
   address chunk given the pointer in the local address space of the
   chunk whose index is 0 (chunk0).  fd_chunk_to_laddr_const is for
   const-correctness.

   fd_laddr_to_chunk: vica versa. */

FD_FN_CONST static inline void *    /* Will be aligned FD_CHUNK_ALIGN and in [ chunk0, chunk0 + FD_CHUNK_SZ*(UINT_MAX+1) ) */
fd_chunk_to_laddr( void * chunk0,   /* Assumed aligned FD_CHUNK_ALIGN */
                   ulong  chunk ) { /* Assumed in [0,UINT_MAX] */
  return (void *)(((ulong)chunk0) + (chunk << FD_CHUNK_LG_SZ));
}

FD_FN_CONST static inline void const *
fd_chunk_to_laddr_const( void const * chunk0,
                         ulong        chunk ) {
  return (void const *)(((ulong)chunk0) + (chunk << FD_CHUNK_LG_SZ));
}

FD_FN_CONST static inline ulong           /* Will be in [0,UINT_MAX] */
fd_laddr_to_chunk( void const * chunk0,   /* Assumed aligned FD_CHUNK_ALIGN */
                   void const * laddr ) { /* Assumed aligned FD_CHUNK_ALIGN and in [ chunk0, chunk0 + FD_CHUNK_SZ*(UINT_MAX+1) ) */
  return (((ulong)laddr)-((ulong)chunk0)) >> FD_CHUNK_LG_SZ;
}

/* fd_frag_meta_seq_query returns the sequence number pointed to by meta
   as atomically observed at some point of time between when the call
   was made and the call returns.  Assumes meta is valid.  This acts as
   a compiler memory fence. */

static inline ulong
fd_frag_meta_seq_query( fd_frag_meta_t const * meta ) { /* Assumed non-NULL */
  FD_COMPILER_MFENCE();
  ulong seq = FD_VOLATILE_CONST( meta->seq );
  FD_COMPILER_MFENCE();
  return seq;
}

#if FD_HAS_SSE

/* fd_frag_meta_seq_sig_query returns the sequence number and signature
   pointed to by meta in one atomic read, same semantics as
   fd_frag_meta_seq_query. */
static inline __m128i
fd_frag_meta_seq_sig_query( fd_frag_meta_t const * meta ) { /* Assumed non-NULL */
  FD_COMPILER_MFENCE();
  __m128i sse0 = _mm_load_si128( &meta->sse0 );
  FD_COMPILER_MFENCE();
  return sse0;
}

#endif

/* fd_frag_meta_ctl, fd_frag_meta_ctl_{som,eom,err} pack and unpack the
   fd_frag message reassembly control bits. */

FD_FN_CONST static inline ulong  /* In [0,2^16) */
fd_frag_meta_ctl( ulong orig,    /* Assumed in [0,FD_FRAG_META_ORIG_MAX) */
                  int   som,     /* 0 for false, non-zero for true */
                  int   eom,     /* 0 for false, non-zero for true */
                  int   err ) {  /* 0 for false, non-zero for true */
  return ((ulong)!!som) | (((ulong)!!eom)<<1) | (((ulong)!!err)<<2) | (orig<<3);
}

FD_FN_CONST static inline ulong fd_frag_meta_ctl_orig( ulong ctl ) { return        ctl>>3;         }
FD_FN_CONST static inline int   fd_frag_meta_ctl_som ( ulong ctl ) { return (int)( ctl     & 1UL); }
FD_FN_CONST static inline int   fd_frag_meta_ctl_eom ( ulong ctl ) { return (int)((ctl>>1) & 1UL); }
FD_FN_CONST static inline int   fd_frag_meta_ctl_err ( ulong ctl ) { return (int)((ctl>>2) & 1UL); }

#if FD_HAS_SSE

FD_FN_CONST static inline __m128i
fd_frag_meta_sse0( ulong seq,
                   ulong sig ) {
  return _mm_set_epi64x( (long)sig, (long)seq ); /* Backward Intel ... sigh */
}

FD_FN_CONST static inline ulong fd_frag_meta_sse0_seq( __m128i sse0 ) { return (ulong)_mm_extract_epi64( sse0, 0 ); }
FD_FN_CONST static inline ulong fd_frag_meta_sse0_sig( __m128i sse0 ) { return (ulong)_mm_extract_epi64( sse0, 1 ); }

FD_FN_CONST static inline __m128i
fd_frag_meta_sse1( ulong chunk,    /* Assumed 32-bit */
                   ulong sz,       /* Assumed 16 bit */
                   ulong ctl,      /* Assumed 16-bit */
                   ulong tsorig,   /* Assumed 32-bit */
                   ulong tspub ) { /* Assumed 32-bit */
  return _mm_set_epi64x( (long)(tsorig | (tspub<<32)),
                         (long)(chunk | (sz<<32) | (ctl<<48)) ); /* Backward Intel ... sigh */
}

FD_FN_CONST static inline ulong fd_frag_meta_sse1_chunk ( __m128i sse1 ) { return (ulong)(uint  )_mm_extract_epi32( sse1, 0 ); }
FD_FN_CONST static inline ulong fd_frag_meta_sse1_sz    ( __m128i sse1 ) { return (ulong)(ushort)_mm_extract_epi16( sse1, 2 ); }
FD_FN_CONST static inline ulong fd_frag_meta_sse1_ctl   ( __m128i sse1 ) { return (ulong)(ushort)_mm_extract_epi16( sse1, 3 ); }
FD_FN_CONST static inline ulong fd_frag_meta_sse1_tsorig( __m128i sse1 ) { return (ulong)(uint  )_mm_extract_epi32( sse1, 2 ); }
FD_FN_CONST static inline ulong fd_frag_meta_sse1_tspub ( __m128i sse1 ) { return (ulong)(uint  )_mm_extract_epi32( sse1, 3 ); }

#endif
#if FD_HAS_AVX

FD_FN_CONST static inline __m256i
fd_frag_meta_avx( ulong seq,
                  ulong sig,
                  ulong chunk,    /* Assumed 32-bit */
                  ulong sz,       /* Assumed 16 bit */
                  ulong ctl,      /* Assumed 16-bit */
                  ulong tsorig,   /* Assumed 32-bit */
                  ulong tspub ) { /* Assumed 32-bit */
  return _mm256_set_epi64x( (long)(tsorig | (tspub<<32)),
                            (long)(chunk | (sz<<32) | (ctl<<48)),
                            (long)sig,
                            (long)seq ); /* Backward Intel ... sigh */
}

FD_FN_CONST static inline ulong fd_frag_meta_avx_seq   ( __m256i avx ) { return (ulong)        _mm256_extract_epi64( avx,  0 ); }
FD_FN_CONST static inline ulong fd_frag_meta_avx_sig   ( __m256i avx ) { return (ulong)        _mm256_extract_epi64( avx,  1 ); }
FD_FN_CONST static inline ulong fd_frag_meta_avx_chunk ( __m256i avx ) { return (ulong)(uint  )_mm256_extract_epi32( avx,  4 ); }
FD_FN_CONST static inline ulong fd_frag_meta_avx_sz    ( __m256i avx ) { return (ulong)(ushort)_mm256_extract_epi16( avx, 10 ); }
FD_FN_CONST static inline ulong fd_frag_meta_avx_ctl   ( __m256i avx ) { return (ulong)(ushort)_mm256_extract_epi16( avx, 11 ); }
FD_FN_CONST static inline ulong fd_frag_meta_avx_tsorig( __m256i avx ) { return (ulong)(uint  )_mm256_extract_epi32( avx,  6 ); }
FD_FN_CONST static inline ulong fd_frag_meta_avx_tspub ( __m256i avx ) { return (ulong)(uint  )_mm256_extract_epi32( avx,  7 ); }

#endif

/* fd_frag_meta_ts_{comp,decomp}:  Given the longs ts and tsref that
   are reasonably close to each other (|ts-tsref| < 2^31 ... about
   +/-2.1 seconds if ts and tsref are reasonably well synchronized
   fd_log_wallclock measurements), this pair of functions can quickly
   and losslessly compress / decompress ts by a factor of 2 exactly
   using tsref as the compressor / decompressor "state". */

FD_FN_CONST static inline ulong   /* In [0,UINT_MAX] */
fd_frag_meta_ts_comp( long ts ) {
  return (ulong)(uint)ts;
}

FD_FN_CONST static inline long
fd_frag_meta_ts_decomp( ulong tscomp,   /* In [0,UINT_MAX] */
                        long  tsref ) {
  ulong msb = ((ulong)tsref) + fd_ulong_mask_lsb(31) - tscomp;
  return (long)((msb & ~fd_ulong_mask_lsb(32)) | tscomp);
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_tango_fd_tango_base_h */

