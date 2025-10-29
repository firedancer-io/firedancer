#ifndef HEADER_fd_src_flamenco_runtime_tests_fd_sol_compat_h
#define HEADER_fd_src_flamenco_runtime_tests_fd_sol_compat_h

/* fd_sol_compat_abi.h provides a public stable ABI exposed in a shared
   library.  Fuzzing / testing engines (such as solfuzz) can use these
   to invoke Firedancer SVM components.

   General usage is like this:

     sol_compat_init()  -- Allocates an anonymous shared memory workspace
     for each input {
       sol_compat_instr_execute_v1() -- Run a test vector
     }
     sol_compat_fini()  -- Releases all resources back to the kernel

   Note that sol_compat usage relies on global variables, thus does not
   support multiple sessions or multi-threading. */

#include "../../fd_flamenco_base.h"

/* Admin API */

FD_PROTOTYPES_BEGIN

/* sol_compat_init installs a new solfuzz execution context into the
   current process.  Under the hood, acquires some demand-paged memory
   (with transparent huge page hint), and initializes some reusable data
   structures.  Must be called before any other solfuzz APIs. */

void
sol_compat_init( int log_level );

/* sol_compat_fini undoes the global setup done above.  Releases all
   memory allocations and file handles created back to the kernel. */

void
sol_compat_fini( void );

FD_PROTOTYPES_END

/* Features API */

/* sol_compat_features_t is a compressed feature set storage format.
   {harcoded,supported}_features point to a vector of features.
   Each entry contains the first 8 bytes of the feature gate account
   address identifying the feature, interpreted as a little-endian
   64-bit integer. */

struct sol_compat_features {
  ulong   struct_size;  /* used for ABI versioning */
  ulong * hardcoded_features;
  ulong   hardcoded_features_cnt;
  ulong * supported_features;
  ulong   supported_feature_cnt;
};

typedef struct sol_compat_features sol_compat_features_t;

FD_PROTOTYPES_BEGIN

/* sol_compat_get_features_v1 returns the feature set supported by this
   Firedancer SVM build. */

sol_compat_features_t const *
sol_compat_get_features_v1( void );

FD_PROTOTYPES_END

/* Execution API */

FD_PROTOTYPES_BEGIN

/* The 'execute_v1' methods execute a single input against an Firedancer
   SVM component.  in points to a byte array of in_sz bytes containing a
   Protobuf-encoded input message.  out points to a byte array that the
   method will write the Protobuf-encoded output message to.  The caller
   sets *out_sz to the capacity of the out buffer.  On return, *out_sz
   contains the serialized size of the output message (guaranteed to be
   <= capacity). */

int
sol_compat_instr_execute_v1( uchar *       out,
                             ulong *       out_sz,
                             uchar const * in,
                             ulong         in_sz );

int
sol_compat_txn_execute_v1( uchar *       out,
                           ulong *       out_sz,
                           uchar const * in,
                           ulong         in_sz );

int
sol_compat_block_execute_v1( uchar *       out,
                             ulong *       out_sz,
                             uchar const * in,
                             ulong         in_sz );

int
sol_compat_elf_loader_v1( uchar *       out,
                          ulong *       out_sz,
                          uchar const * in,
                          ulong         in_sz );

int
sol_compat_vm_syscall_execute_v1( uchar *       out,
                                  ulong *       out_sz,
                                  uchar const * in,
                                  ulong         in_sz );

int
sol_compat_vm_interp_v1( uchar *       out,
                         ulong *       out_sz,
                         uchar const * in,
                         ulong         in_sz );

int
sol_compat_shred_parse_v1( uchar *       out,
                           ulong *       out_sz,
                           uchar const * in,
                           ulong         in_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_tests_fd_sol_compat_h */
