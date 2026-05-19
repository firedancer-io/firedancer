#ifndef HEADER_fd_src_flamenco_vm_fd_vm_private_h
#define HEADER_fd_src_flamenco_vm_fd_vm_private_h

#include "fd_vm.h"

#include "../runtime/fd_runtime_const.h"
#include "../runtime/fd_runtime.h"
#include "fd_vm_base.h"

/* FD_VM_ALIGN_RUST_{} define the alignments for relevant rust types.
   Alignments are derived with std::mem::align_of::<T>() and are enforced
   by the VM (with the exception of v1 loader).

   In our implementation, when calling FD_VM_MEM_HADDR_ST / FD_VM_MEM_HADDR_LD,
   we need to make sure we're passing the correct alignment based on the Rust
   type in the corresponding mapping in Agave.

   FD_VM_ALIGN_RUST_{} has been generated with this Rust code:
   ```rust
      pub type Epoch = u64;
      pub struct Pubkey(pub [u8; 32]);
      pub struct AccountMeta {
          pub lamports: u64,
          pub rent_epoch: Epoch,
          pub owner: Pubkey,
          pub executable: bool,
      }

      pub struct PodScalar(pub [u8; 32]);

      fn main() {
          println!("u8: {}", std::mem::align_of::<u8>());
          println!("u32: {}", std::mem::align_of::<u32>());
          println!("u64: {}", std::mem::align_of::<u64>());
          println!("u128: {}", std::mem::align_of::<u128>());
          println!("&[u8]: {}", std::mem::align_of::<&[u8]>());
          println!("AccountMeta: {}", std::mem::align_of::<AccountMeta>());
          println!("PodScalar: {}", std::mem::align_of::<PodScalar>());
          println!("Pubkey: {}", std::mem::align_of::<Pubkey>());
      }
    ``` */

#define FD_VM_ALIGN_RUST_U8                       (1UL)
#define FD_VM_ALIGN_RUST_U32                      (4UL)
#define FD_VM_ALIGN_RUST_I32                      (4UL)
#define FD_VM_ALIGN_RUST_U64                      (8UL)
#define FD_VM_ALIGN_RUST_SLICE_U8_REF             (8UL)
#define FD_VM_ALIGN_RUST_POD_U8_ARRAY             (1UL)
#define FD_VM_ALIGN_RUST_PUBKEY                   (1UL)
#define FD_VM_ALIGN_RUST_SYSVAR_CLOCK             (8UL)
#define FD_VM_ALIGN_RUST_SYSVAR_EPOCH_SCHEDULE    (8UL)
#define FD_VM_ALIGN_RUST_SYSVAR_RENT              (8UL)
#define FD_VM_ALIGN_RUST_SYSVAR_LAST_RESTART_SLOT (8UL)
#define FD_VM_ALIGN_RUST_SYSVAR_EPOCH_REWARDS    (16UL)

/* fd_vm_vec_t is the in-memory representation of a vector descriptor.
   Equal in layout to the Rust slice header &[_] and various vector
   types in the C version of the syscall API. */
/* FIXME: WHEN IS VADDR NULL AND/OR SZ 0 OKAY? */
/* FIXME: MOVE FD_VM_RUST_VEC_T FROM SYSCALL/FD_VM_CPI.H HERE TOO? */

#define FD_VM_VEC_ALIGN FD_VM_ALIGN_RUST_SLICE_U8_REF
#define FD_VM_VEC_SIZE  (16UL)

struct __attribute__((packed)) fd_vm_vec {
  ulong addr; /* FIXME: NAME -> VADDR */
  ulong len;  /* FIXME: NAME -> SZ */
};

typedef struct fd_vm_vec fd_vm_vec_t;

FD_STATIC_ASSERT( sizeof(fd_vm_vec_t)==FD_VM_VEC_SIZE, fd_vm_vec size mismatch );

/* SBPF version and features
   https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/program.rs#L28
   Note: SIMDs enable or disable features, e.g. BPF instructions.
   If we have macros with names ENABLE vs DISABLE, we have the advantage that
   the condition is always pretty clear: sbpf_version <= activation_version,
   but the disadvantage of inconsistent names.
   Viceversa, calling everything ENABLE has the risk to invert a <= with a >=
   and create a huge mess.
   We define both, so hopefully it's foolproof. */

/* https://github.com/anza-xyz/sbpf/blob/v0.14.4/src/program.rs#L28-L93 */
/* SIMD-0166 */
#define FD_VM_SBPF_MANUAL_STACK_FRAME_BUMP(v)              ( v == FD_SBPF_V1 || v == FD_SBPF_V2 ) /* https://github.com/anza-xyz/sbpf/blob/v0.14.4/src/program.rs#L32-L34 */
#define FD_VM_SBPF_STACK_FRAME_GAPS(v)                     ( v == FD_SBPF_V0 )                    /* https://github.com/anza-xyz/sbpf/blob/v0.14.4/src/program.rs#L36-L38 */
/* SIMD-0174 */
#define FD_VM_SBPF_ENABLE_PQR(v)                           ( v == FD_SBPF_V2 )                    /* https://github.com/anza-xyz/sbpf/blob/v0.14.4/src/program.rs#L41-L43 */
#define FD_VM_SBPF_EXPLICIT_SIGN_EXTENSION_OF_RESULTS(v)   ( v == FD_SBPF_V2 )                    /* https://github.com/anza-xyz/sbpf/blob/v0.14.4/src/program.rs#L45-L47 */
#define FD_VM_SBPF_SWAP_SUB_REG_IMM_OPERANDS(v)            ( v == FD_SBPF_V2 )                    /* https://github.com/anza-xyz/sbpf/blob/v0.14.4/src/program.rs#L49-L51 */
#define FD_VM_SBPF_DISABLE_NEG(v)                          ( v == FD_SBPF_V2 )                    /* https://github.com/anza-xyz/sbpf/blob/v0.14.4/src/program.rs#L53-L55 */
/* SIMD-0173 */
#define FD_VM_SBPF_CALLX_USES_SRC_REG(v)                   ( v == FD_SBPF_V2 )                    /* https://github.com/anza-xyz/sbpf/blob/v0.14.4/src/program.rs#L58-L60 */
#define FD_VM_SBPF_DISABLE_LDDW(v)                         ( v == FD_SBPF_V2 )                    /* https://github.com/anza-xyz/sbpf/blob/v0.14.4/src/program.rs#L62-L64 */
#define FD_VM_SBPF_DISABLE_LE(v)                           ( v == FD_SBPF_V2 )                    /* https://github.com/anza-xyz/sbpf/blob/v0.14.4/src/program.rs#L66-L68 */
#define FD_VM_SBPF_MOVE_MEMORY_IX_CLASSES(v)               ( v == FD_SBPF_V2 )                    /* https://github.com/anza-xyz/sbpf/blob/v0.14.4/src/program.rs#L70-L72 */
/* SIMD-0178 */
#define FD_VM_SBPF_STATIC_SYSCALLS(v)                      ( v >= FD_SBPF_V3 )                    /* https://github.com/anza-xyz/sbpf/blob/v0.14.4/src/program.rs#L75-L77 */
/* SIMD-0189 */
#define FD_VM_SBPF_ENABLE_STRICTER_ELF_HEADERS(v)          ( v >= FD_SBPF_V3 )                    /* https://github.com/anza-xyz/sbpf/blob/v0.14.4/src/program.rs#L79-L81 */
#define FD_VM_SBPF_ENABLE_LOWER_RODATA_VADDR(v)            ( v >= FD_SBPF_V3 )                    /* https://github.com/anza-xyz/sbpf/blob/v0.14.4/src/program.rs#L83-L85 */
/* SIMD-0377 */
#define FD_VM_SBPF_ENABLE_JMP32(v)                         ( v >= FD_SBPF_V3 )                    /* https://github.com/anza-xyz/sbpf/blob/v0.14.4/src/program.rs#L87-L89 */
#define FD_VM_SBPF_CALLX_USES_DST_REG(v)                   ( v >= FD_SBPF_V3 )                    /* https://github.com/anza-xyz/sbpf/blob/v0.14.4/src/program.rs#L91-L93 */

#define FD_VM_OFFSET_MASK (0xffffffffUL)

/* https://github.com/anza-xyz/agave/blob/v3.0.1/transaction-context/src/lib.rs#L32 */
#define FD_MAX_ACCOUNT_DATA_GROWTH_PER_TRANSACTION ((long)(FD_RUNTIME_ACC_SZ_MAX * 2UL))

FD_PROTOTYPES_BEGIN

/* Error logging handholding assertions */

#ifdef FD_RUNTIME_ERR_HANDHOLDING
/* Asserts that the error and error kind are populated (non-zero) */
#define FD_VM_TEST_ERR_EXISTS( vm )                                       \
    FD_TEST( vm->instr_ctx->txn_out->err.exec_err );                      \
    FD_TEST( vm->instr_ctx->txn_out->err.exec_err_kind )

/* Used prior to a FD_VM_ERR_FOR_LOG_INSTR call to deliberately
   bypass overwrite handholding checks.
   Only use this if you know what you're doing. */
#define FD_VM_PREPARE_ERR_OVERWRITE( vm )                                 \
   vm->instr_ctx->txn_out->err.exec_err = 0;                              \
   vm->instr_ctx->txn_out->err.exec_err_kind = 0

/* Asserts that the error and error kind are not populated (zero) */
#define FD_VM_TEST_ERR_OVERWRITE( vm )                                    \
    FD_TEST( !vm->instr_ctx->txn_out->err.exec_err );                     \
    FD_TEST( !vm->instr_ctx->txn_out->err.exec_err_kind )
#else
#define FD_VM_TEST_ERR_EXISTS( vm ) ( ( void )0 )
#define FD_VM_PREPARE_ERR_OVERWRITE( vm ) ( ( void )0 )
#define FD_VM_TEST_ERR_OVERWRITE( vm ) ( ( void )0 )
#endif

/* Log error within the instr_ctx to match Agave/Rust error. */

#define FD_VM_ERR_FOR_LOG_EBPF( vm, err_ ) (__extension__({                \
    FD_VM_TEST_ERR_OVERWRITE( vm );                                        \
    vm->instr_ctx->txn_out->err.exec_err = err_;                           \
    vm->instr_ctx->txn_out->err.exec_err_kind = FD_EXECUTOR_ERR_KIND_EBPF; \
  }))

#define FD_VM_ERR_FOR_LOG_SYSCALL( vm, err_ ) (__extension__({                \
    FD_VM_TEST_ERR_OVERWRITE( vm );                                           \
    vm->instr_ctx->txn_out->err.exec_err = err_;                              \
    vm->instr_ctx->txn_out->err.exec_err_kind = FD_EXECUTOR_ERR_KIND_SYSCALL; \
  }))

#define FD_VM_ERR_FOR_LOG_INSTR( vm, err_ ) (__extension__({                \
    FD_VM_TEST_ERR_OVERWRITE( vm );                                         \
    vm->instr_ctx->txn_out->err.exec_err = err_;                            \
    vm->instr_ctx->txn_out->err.exec_err_kind = FD_EXECUTOR_ERR_KIND_INSTR; \
  }))

#define FD_VADDR_TO_REGION( _vaddr ) fd_ulong_min( (_vaddr) >> FD_VM_MEM_MAP_REGION_VIRT_ADDR_BITS, FD_VM_HIGH_REGION )

/* fd_vm_instr APIs ***************************************************/

/* FIXME: MIGRATE FD_SBPF_INSTR_T STUFF TO THIS API */

/* fd_vm_instr returns the SBPF instruction word corresponding to the
   given fields. */

FD_FN_CONST static inline ulong
fd_vm_instr( ulong opcode, /* Assumed valid */
             ulong dst,    /* Assumed in [0,FD_VM_REG_CNT) */
             ulong src,    /* Assumed in [0,FD_VM_REG_CNT) */
             short offset,
             uint  imm ) {
  return opcode | (dst<<8) | (src<<12) | (((ulong)(ushort)offset)<<16) | (((ulong)imm)<<32);
}

/* fd_vm_instr_* return the SBPF instruction field for the given word.
   fd_vm_instr_{normal,mem}_* only apply to {normal,mem} opclass
   instructions. */

FD_FN_CONST static inline ulong fd_vm_instr_opcode( ulong instr ) { return   instr      & 255UL;       } /* In [0,256) */
FD_FN_CONST static inline ulong fd_vm_instr_dst   ( ulong instr ) { return ((instr>> 8) &  15UL);      } /* In [0,16)  */
FD_FN_CONST static inline ulong fd_vm_instr_src   ( ulong instr ) { return ((instr>>12) &  15UL);      } /* In [0,16)  */
FD_FN_CONST static inline ulong fd_vm_instr_offset( ulong instr ) { return (ulong)(long)(short)(ushort)(instr>>16); }
FD_FN_CONST static inline uint  fd_vm_instr_imm   ( ulong instr ) { return (uint)(instr>>32);          }

FD_FN_CONST static inline ulong fd_vm_instr_opclass       ( ulong instr ) { return  instr      & 7UL; } /* In [0,8)  */
FD_FN_CONST static inline ulong fd_vm_instr_normal_opsrc  ( ulong instr ) { return (instr>>3) &  1UL; } /* In [0,2)  */
FD_FN_CONST static inline ulong fd_vm_instr_normal_opmode ( ulong instr ) { return (instr>>4) & 15UL; } /* In [0,16) */
FD_FN_CONST static inline ulong fd_vm_instr_mem_opsize    ( ulong instr ) { return (instr>>3) &  3UL; } /* In [0,4)  */
FD_FN_CONST static inline ulong fd_vm_instr_mem_opaddrmode( ulong instr ) { return (instr>>5) &  7UL; } /* In [0,16) */

/* Lazy page zeroing ******************************************************

   fd_vm_lazy_zero_pages checks whether the 2KB page(s) covering
   [offset, offset+sz) within a stack or heap region have been zeroed.
   If any page's bitmap bit is clear, the page is zeroed via fd_memset
   and the bit is set.  On the fast path (page already zeroed), this
   costs a shift, a bit-test, and a predicted-taken branch (~3 cycles).

   Also used after TLB setup to pre-zero the entire cached range so
   that TLB hits don't need per-access bitmap checks. */

static inline void
fd_vm_lazy_zero_pages( ulong * bitmap,
                       uchar * region_base,
                       ulong   offset,
                       ulong   sz ) {
  if( FD_UNLIKELY( !sz ) ) return;
  ulong p_lo = offset >> FD_VM_LAZY_PAGE_LG_SZ;
  ulong p_hi = (offset + sz - 1UL) >> FD_VM_LAZY_PAGE_LG_SZ;
  for( ulong p = p_lo; p <= p_hi; p++ ) {
    ulong w = p >> 6;
    ulong b = 1UL << (p & 63UL);
    if( FD_UNLIKELY( !(bitmap[w] & b) ) ) {
      fd_memset( region_base + (p << FD_VM_LAZY_PAGE_LG_SZ), 0, FD_VM_LAZY_PAGE_SZ );
      bitmap[w] |= b;
    }
  }
}

/* fd_vm_mark_all_pages_initialized sets all bitmap bits for both
   stack and heap, effectively disabling lazy zeroing.  Useful in test
   harnesses that directly populate vm->heap/stack via memcpy. */

static inline void
fd_vm_mark_all_pages_initialized( fd_vm_t * vm ) {
  memset( vm->stack_zero_bitmap, 0xFF, FD_VM_LAZY_BITMAP_WORDS * sizeof(ulong) );
  memset( vm->heap_zero_bitmap,  0xFF, FD_VM_LAZY_BITMAP_WORDS * sizeof(ulong) );
}

/* fd_vm_zero_uninitialized_pages zeros every page whose bitmap bit is
   still clear (never accessed through fd_vm_mem_haddr during execution).
   Call after execution but before reading heap/stack for deterministic
   comparison. */

static inline void
fd_vm_zero_uninitialized_pages( ulong * bitmap,
                                uchar * region_base,
                                ulong   region_sz ) {
  ulong page_cnt = region_sz >> FD_VM_LAZY_PAGE_LG_SZ;
  for( ulong p = 0; p < page_cnt; p++ ) {
    ulong w = p >> 6;
    ulong b = 1UL << (p & 63UL);
    if( FD_UNLIKELY( !(bitmap[w] & b) ) ) {
      fd_memset( region_base + (p << FD_VM_LAZY_PAGE_LG_SZ), 0, FD_VM_LAZY_PAGE_SZ );
    }
  }
}

/* fd_vm_mem API ******************************************************/

/* fd_vm_mem APIs support the fast mapping of virtual address ranges to
   host address ranges.  The SBPF virtual address space consists of
   5 consecutive 4 GiB regions (see fd_vm_base.h for layout).  The
   mapable size of each region is less than 4 GiB (as implied by
   FD_VM_MEM_MAP_REGION_SZ==2^32-1 and that Solana protocol limits are
   much smaller still), so a valid virtual address range cannot span
   multiple regions. */

/* fd_vm_mem_cfg configures the vm's tlb arrays.  Assumes vm is valid
   and vm already has configured the rodata, stack, heap and input
   regions.  Returns vm. */

static inline fd_vm_t *
fd_vm_mem_cfg( fd_vm_t * vm ) {
  if( FD_VM_SBPF_ENABLE_LOWER_RODATA_VADDR( vm->sbpf_version ) ) {
    /* In SBPF V3, rodata is at vaddr 0:
       [rodata@0, empty@0x100000000, stack@0x200000000, heap@0x300000000, input@0x400000000]

       This is so that we don't need to do any relocations - all rodata
       accesses are direct offsets from 0.

       https://github.com/anza-xyz/sbpf/blob/v0.14.4/src/elf.rs#L358-L362
       https://github.com/anza-xyz/agave/blob/v4.0.0-beta.4/syscalls/src/lib.rs#L346 */
    vm->region_haddr[0]                  = (ulong)vm->rodata; vm->region_ld_sz[0]                  = (uint)vm->rodata_sz;   vm->region_st_sz[0]                  = (uint)0UL;
    vm->region_haddr[FD_VM_PROG_REGION]  = 0UL;               vm->region_ld_sz[FD_VM_PROG_REGION]  = (uint)0UL;             vm->region_st_sz[FD_VM_PROG_REGION]  = (uint)0UL;
  } else {
    /* V0-V2: region 0 unused, rodata at region 1 (vaddr 0x100000000) */
    vm->region_haddr[0]                  = 0UL;               vm->region_ld_sz[0]                  = (uint)0UL;             vm->region_st_sz[0]                  = (uint)0UL;
    vm->region_haddr[FD_VM_PROG_REGION]  = (ulong)vm->rodata; vm->region_ld_sz[FD_VM_PROG_REGION]  = (uint)vm->rodata_sz;   vm->region_st_sz[FD_VM_PROG_REGION]  = (uint)0UL;
  }
  vm->region_haddr[FD_VM_STACK_REGION]   = (ulong)vm->stack;  vm->region_ld_sz[FD_VM_STACK_REGION] = (uint)FD_VM_STACK_MAX; vm->region_st_sz[FD_VM_STACK_REGION] = (uint)FD_VM_STACK_MAX;
  vm->region_haddr[FD_VM_HEAP_REGION]    = (ulong)vm->heap;   vm->region_ld_sz[FD_VM_HEAP_REGION]  = (uint)vm->heap_max;    vm->region_st_sz[FD_VM_HEAP_REGION]  = (uint)vm->heap_max;
  vm->region_haddr[5]                    = 0UL;               vm->region_ld_sz[5]                  = (uint)0UL;             vm->region_st_sz[5]                  = (uint)0UL;
  if( vm->direct_mapping || !vm->input_mem_regions_cnt ) {
    /* When direct mapping is enabled, we don't use these fields because
       the load and stores are fragmented. */
    vm->region_haddr[FD_VM_INPUT_REGION] = 0UL;
    vm->region_ld_sz[FD_VM_INPUT_REGION] = 0U;
    vm->region_st_sz[FD_VM_INPUT_REGION] = 0U;
  } else {
    vm->region_haddr[FD_VM_INPUT_REGION] = vm->input_mem_regions[0].haddr;
    vm->region_ld_sz[FD_VM_INPUT_REGION] = vm->input_mem_regions[0].region_sz;
    vm->region_st_sz[FD_VM_INPUT_REGION] = vm->input_mem_regions[0].region_sz;
  }
  return vm;
}

/* Simplified version of Agave's `generate_access_violation()` function
   that simply returns either FD_VM_ERR_EBPF_ACCESS_VIOLATION or
   FD_VM_ERR_EBPF_STACK_ACCESS_VIOLATION. This has no consensus
   effects and is purely for logging purposes for fuzzing. Returns
   FD_VM_ERR_EBPF_STACK_ACCESS_VIOLATION if the provided vaddr is in the
   stack (0x200000000) and FD_VM_ERR_EBPF_ACCESS_VIOLATION otherwise.

   https://github.com/anza-xyz/sbpf/blob/v0.11.1/src/memory_region.rs#L834-L869 */
static FD_FN_PURE inline int
fd_vm_generate_access_violation( ulong vaddr, ulong sbpf_version ) {
  /* rel_offset can be negative because there is an edge case where the
     first "frame" right before the stack region should also throw a
     stack access violation. */
  long rel_offset = fd_long_sat_sub( (long)vaddr, (long)FD_VM_MEM_MAP_STACK_REGION_START );
  long stack_frame = rel_offset / (long)FD_VM_STACK_FRAME_SZ;
  if( !fd_sbpf_manual_stack_frame_bump_enabled( sbpf_version ) &&
      stack_frame>=-1L && stack_frame<=(long)FD_VM_MAX_CALL_DEPTH ) {
    return FD_VM_ERR_EBPF_STACK_ACCESS_VIOLATION;
  }
  return FD_VM_ERR_EBPF_ACCESS_VIOLATION;
}

/* fd_vm_mem_haddr translates the vaddr range [vaddr,vaddr+sz) (in
   infinite precision math) into the non-wrapping haddr range
   [haddr,haddr+sz).  On success, returns haddr and every byte in the
   haddr range is a valid address.  On failure, returns sentinel and
   there was at least one byte in the virtual address range that did not
   have a corresponding byte in the host address range.

   IMPORTANT SAFETY TIP!  When sz==0, the return value currently is
   arbitrary.  This is often fine as there should be no
   actual accesses to a sz==0 region.  However, this also means that
   testing return for sentinel is insufficient to tell if mapping
   failed.  That is, assuming sentinel is a location that could never
   happen on success:

     sz!=0 and ret!=sentinel -> success
     sz!=0 and ret==sentinel -> failure
     sz==0 -> ignore ret, application specific handling

   With ~O(2) extra fast branchless instructions, the below could be
   tweaked in the sz==0 case to return NULL or return a non-NULL
   sentinel value.  What is most optimal practically depends on how
   empty ranges and NULL vaddr handling is defined in the application.

   Requires ~O(10) fast branchless assembly instructions with 2 L1 cache
   hit loads and pretty good ILP.

   fd_vm_mem_haddr_fast is when the vaddr is for use when it is already
   known that the vaddr region has a valid mapping.

   These assumptions don't hold if direct mapping is enabled since input
   region lookups become O(log(n)). */


/* fd_vm_get_input_mem_region_idx returns the index into the input memory
   region array with the largest region offset that is <= the offset that
   is passed in.  This function makes NO guarantees about the input being
   a valid input region offset; the caller is responsible for safely handling
   it. */
static inline ulong
fd_vm_get_input_mem_region_idx( fd_vm_t const * vm, ulong offset ) {
  uint left  = 0U;
  uint right = vm->input_mem_regions_cnt - 1U;
  uint mid   = 0U;

  while( left<right ) {
    mid = (left+right) / 2U;
    if( offset>=vm->input_mem_regions[ mid ].vaddr_offset+vm->input_mem_regions[ mid ].address_space_reserved ) {
      left = mid + 1U;
    } else {
      right = mid;
    }
  }
  return left;
}

/* If the region is an account, handle the resizing logic. This logic
   corresponds to
   solana_transaction_context::TransactionContext::access_violation_handler

   https://github.com/anza-xyz/agave/blob/v3.0.1/transaction-context/src/lib.rs#L510-L581 */
static inline void
fd_vm_handle_input_mem_region_oob( fd_vm_t const * vm,
                                   ulong           offset,
                                   ulong           sz,
                                   ulong           region_idx,
                                   uchar           write ) {
  /* If virtual_address_space_adjustments is not enabled, we don't need to
     do anything */
  if( FD_UNLIKELY( !vm->virtual_address_space_adjustments ) ) {
    return;
  }

  /* If the access is not a write, we don't need to do anything
     https://github.com/anza-xyz/agave/blob/v3.0.1/transaction-context/src/lib.rs#L523-L525 */
  if( FD_UNLIKELY( !write ) ) {
    return;
  }

  fd_vm_input_region_t * region = &vm->input_mem_regions[ region_idx ];
  /* If the region is not writable, we don't need to do anything
     https://github.com/anza-xyz/agave/blob/v3.0.1/transaction-context/src/lib.rs#L526-L529 */
  if( FD_UNLIKELY( !region->is_writable ) ) {
    return;
  }

  /* Calculate the requested length
     https://github.com/anza-xyz/agave/blob/v3.0.1/transaction-context/src/lib.rs#L532-L535 */
  ulong requested_len = fd_ulong_sat_sub( fd_ulong_sat_add( offset, sz ), region->vaddr_offset );
  if( FD_UNLIKELY( requested_len > region->address_space_reserved ) ) {
    return;
  }

  /* Calculate the remaining allowed growth
     https://github.com/anza-xyz/agave/blob/v3.0.1/transaction-context/src/lib.rs#L549-L551 */
  long remaining_growth_signed = fd_long_sat_sub(
    FD_MAX_ACCOUNT_DATA_GROWTH_PER_TRANSACTION,
    vm->instr_ctx->txn_out->details.accounts_resize_delta );
  ulong remaining_allowed_growth = (remaining_growth_signed > 0L)
    ? (ulong)remaining_growth_signed
    : 0UL;

  /* If the requested length is greater than the size of the region,
     resize the region
     https://github.com/anza-xyz/agave/blob/v3.0.1/transaction-context/src/lib.rs#L553-L571 */
  if( FD_UNLIKELY( requested_len > region->region_sz ) ) {
    /* Calculate the new region size
       https://github.com/anza-xyz/agave/blob/v3.0.1/transaction-context/src/lib.rs#L558-L560 */
    ulong new_region_sz = fd_ulong_min(
      fd_ulong_min( region->address_space_reserved, FD_RUNTIME_ACC_SZ_MAX ),
      fd_ulong_sat_add( region->region_sz, remaining_allowed_growth ) );

    /* Resize the account and the region
       https://github.com/anza-xyz/agave/blob/v3.0.1/transaction-context/src/lib.rs#L569-L570 */
    if( FD_UNLIKELY( new_region_sz > region->region_sz ) ) {
      /* Safe because new_region_sz > region->region_sz */
      long growth = (long)(new_region_sz - region->region_sz);
      vm->instr_ctx->txn_out->details.accounts_resize_delta = fd_long_sat_add(
        vm->instr_ctx->txn_out->details.accounts_resize_delta, growth );

      fd_account_meta_resize( vm->acc_region_metas[ region->acc_region_meta_idx ].meta, new_region_sz );
      region->region_sz = (uint)new_region_sz;
    }
  }
}

/* fd_vm_find_input_mem_region returns the translated haddr for a given
   offset into the input region.  If an offset/sz is invalid or if an
   illegal write is performed, the sentinel value is returned. If the offset
   provided is too large, it will choose the upper-most region as the
   region_idx. However, it will get caught for being too large of an access
   in the multi-region checks. */
static inline ulong
fd_vm_find_input_mem_region( fd_vm_t const * vm,
                             ulong           offset,
                             ulong           sz,
                             uchar           write,
                             ulong           sentinel ) {
  if( FD_UNLIKELY( vm->input_mem_regions_cnt==0 ) ) {
    return sentinel; /* Access is too large */
  }

  /* Binary search to find the correct memory region.  If direct mapping is not
     enabled, then there is only 1 memory region which spans the input region. */
  ulong region_idx = fd_vm_get_input_mem_region_idx( vm, offset );
  if( FD_UNLIKELY( region_idx>=vm->input_mem_regions_cnt ) ) {
    return sentinel; /* Region not found */
  }

  ulong bytes_in_region = fd_ulong_sat_sub( vm->input_mem_regions[ region_idx ].region_sz,
                                            fd_ulong_sat_sub( offset, vm->input_mem_regions[ region_idx ].vaddr_offset ) );

  /* If the access is out of bounds, invoke the callback to handle the out of bounds access.
     This potentially resizes the region if necessary. */
  if( FD_UNLIKELY( sz>bytes_in_region ) ) {
    fd_vm_handle_input_mem_region_oob( vm, offset, sz, region_idx, write );
  }

  /* After potentially resizing, re-check the bounds */
  bytes_in_region = fd_ulong_sat_sub( vm->input_mem_regions[ region_idx ].region_sz,
                                      fd_ulong_sat_sub( offset, vm->input_mem_regions[ region_idx ].vaddr_offset ) );
  /* If the access is still out of bounds, return the sentinel */
  if( FD_UNLIKELY( sz>bytes_in_region ) ) {
    return sentinel;
  }

  if( FD_UNLIKELY( write && vm->input_mem_regions[ region_idx ].is_writable==0U ) ) {
    return sentinel; /* Illegal write */
  }

  ulong start_region_idx = region_idx;

  ulong adjusted_haddr = vm->input_mem_regions[ start_region_idx ].haddr + offset - vm->input_mem_regions[ start_region_idx ].vaddr_offset;
  return adjusted_haddr;
}


static inline ulong
fd_vm_mem_haddr( fd_vm_t const * vm,
                 ulong           vaddr,
                 ulong           sz,
                 ulong const *   vm_region_haddr, /* indexed [0,6) */
                 uint  const *   vm_region_sz,    /* indexed [0,6) */
                 uchar           write,           /* 1 if the access is a write, 0 if it is a read */
                 ulong           sentinel ) {
  ulong region = FD_VADDR_TO_REGION( vaddr );
  ulong offset = vaddr & FD_VM_OFFSET_MASK;

  /* Some configurations of the vm have unmapped gaps between each
     stack frame. If this is the case, we need to check that the access
     is not in a gap region. */
  int stack_frame_gaps_enabled = vm->stack_push_frame_count > 1;
  if( FD_UNLIKELY( region==FD_VM_STACK_REGION && stack_frame_gaps_enabled ) ) {
    /* If an access starts in a gap region, that is an access violation */
    if( FD_UNLIKELY( !!(vaddr & 0x1000) ) ) {
      return sentinel;
    }

    /* To account for the fact that we have gaps in the virtual address space but not in the
       physical address space, we need to subtract from the offset the size of all the virtual
       gap frames underneath it.

       https://github.com/solana-labs/rbpf/blob/b503a1867a9cfa13f93b4d99679a17fe219831de/src/memory_region.rs#L147-L149 */
    ulong gap_mask = 0xFFFFFFFFFFFFF000;
    offset = ( ( offset & gap_mask ) >> 1 ) | ( offset & ~gap_mask );
  }

  ulong region_sz = (ulong)vm_region_sz[ region ];
  ulong sz_max    = region_sz - fd_ulong_min( offset, region_sz );

  /* If the region is an account, handle the resizing logic. This logic corresponds to
     solana_transaction_context::TransactionContext::access_violation_handler

     https://github.com/anza-xyz/agave/blob/v3.0.1/transaction-context/src/lib.rs#L510-L581 */
  if( region==FD_VM_INPUT_REGION ) {
    return fd_vm_find_input_mem_region( vm, offset, sz, write, sentinel );
  }

  ulong haddr = fd_ulong_if( sz<=sz_max, vm_region_haddr[ region ] + offset, sentinel );

  if( FD_LIKELY( haddr != sentinel ) &&
      FD_UNLIKELY( region == FD_VM_STACK_REGION || region == FD_VM_HEAP_REGION ) ) {
    fd_vm_t * vm_mut = (fd_vm_t *)vm;
    ulong * bitmap = (region == FD_VM_STACK_REGION) ? vm_mut->stack_zero_bitmap : vm_mut->heap_zero_bitmap;
    uchar * base   = (region == FD_VM_STACK_REGION) ? vm_mut->stack : vm_mut->heap;
    fd_vm_lazy_zero_pages( bitmap, base, offset, sz );
  }

# ifdef FD_VM_INTERP_MEM_TRACING_ENABLED
  if ( FD_LIKELY( haddr != sentinel ) ) {
    fd_vm_trace_event_mem( vm->trace, write, vaddr, sz, haddr );
  }
# endif
  return haddr;
}

/* fd_vm_mem_haddr_tlb_miss handles the TLB miss path: translates the
   address via fd_vm_mem_haddr and populates the TLB cache on success.
   Deliberately not inlined so that the hot (hit) path stays tiny.

   The TLB stores bounds in vaddr space (region bits included) so the
   hit check is just two comparisons with no region extraction. */

static __attribute__((noinline)) ulong
fd_vm_mem_haddr_tlb_miss( fd_vm_t const * vm,
                          ulong           vaddr,
                          ulong           sz,
                          ulong const *   vm_region_haddr,
                          uint  const *   vm_region_sz,
                          uchar           write,
                          ulong           sentinel,
                          ulong *         p_tlb_haddr_base,
                          ulong *         p_tlb_vaddr_lo,
                          ulong *         p_tlb_vaddr_hi,
                          int             stack_gaps_enabled ) {
  ulong region = FD_VADDR_TO_REGION( vaddr );
  ulong offset = vaddr & FD_VM_OFFSET_MASK;
  ulong region_bits = region << FD_VM_MEM_MAP_REGION_VIRT_ADDR_BITS;

  /* For input regions, do an integrated translate+TLB-populate using a
     single binary search, avoiding the double lookup that would result
     from calling fd_vm_mem_haddr (which searches) then searching again
     to find the region bounds for the TLB entry. */
  if( FD_UNLIKELY( region == FD_VM_INPUT_REGION ) ) {
    if( FD_UNLIKELY( vm->input_mem_regions_cnt==0 ) ) return sentinel;

    ulong idx = fd_vm_get_input_mem_region_idx( vm, offset );
    if( FD_UNLIKELY( idx>=vm->input_mem_regions_cnt ) ) return sentinel;

    fd_vm_input_region_t const * ir = &vm->input_mem_regions[ idx ];

    ulong bytes_in_region = fd_ulong_sat_sub( ir->region_sz,
                              fd_ulong_sat_sub( offset, ir->vaddr_offset ) );
    if( FD_UNLIKELY( sz>bytes_in_region ) ) {
      fd_vm_handle_input_mem_region_oob( vm, offset, sz, idx, write );
      ir = &vm->input_mem_regions[ idx ];
      bytes_in_region = fd_ulong_sat_sub( ir->region_sz,
                          fd_ulong_sat_sub( offset, ir->vaddr_offset ) );
      if( FD_UNLIKELY( sz>bytes_in_region ) ) return sentinel;
    }

    if( FD_UNLIKELY( write && ir->is_writable==0U ) ) return sentinel;

    ulong haddr = ir->haddr + offset - ir->vaddr_offset;
    *p_tlb_vaddr_lo   = region_bits | ir->vaddr_offset;
    *p_tlb_vaddr_hi   = region_bits | (ir->vaddr_offset + ir->region_sz);
    /* haddr_base = ir->haddr - ir->vaddr_offset.  Subtraction may wrap
       under ulong arithmetic when haddr < vaddr_offset; the hit path
       computes haddr_base + (vaddr & FD_VM_OFFSET_MASK), and that
       second add wraps in the opposite direction so the result is the
       correct host address.  See audit §1.2. */
    *p_tlb_haddr_base = ir->haddr   - ir->vaddr_offset;
    return haddr;
  }

  /* Non-input regions (stack/heap/program/...): inline the translation
     and TLB-populate.  This is equivalent to calling fd_vm_mem_haddr()
     followed by the TLB-populate logic, but avoids re-extracting
     region/offset/stack_frame_gaps_enabled and the now-dead
     `if (region==INPUT)` branch inside fd_vm_mem_haddr.  Tracing
     bypasses this miss path entirely (see fd_vm_interp_core.c), so we
     don't need a fd_vm_trace_event_mem call here. */
  ulong adj_offset = offset;
  if( FD_UNLIKELY( region == FD_VM_STACK_REGION && stack_gaps_enabled ) ) {
    /* If an access starts in a gap region, that is an access violation. */
    if( FD_UNLIKELY( !!(vaddr & 0x1000) ) ) return sentinel;

    /* Subtract the size of all virtual gap frames underneath us; see
       fd_vm_mem_haddr() for the canonical version of this mapping. */
    ulong gap_mask = 0xFFFFFFFFFFFFF000UL;
    adj_offset = ( ( offset & gap_mask ) >> 1 ) | ( offset & ~gap_mask );
  }

  ulong region_sz = (ulong)vm_region_sz[ region ];
  ulong sz_max    = region_sz - fd_ulong_min( adj_offset, region_sz );
  if( FD_UNLIKELY( sz > sz_max ) ) return sentinel;

  ulong haddr = vm_region_haddr[ region ] + adj_offset;

  /* haddr_base = haddr - offset uses the *unadjusted* offset because
     the hit path adds back (vaddr & FD_VM_OFFSET_MASK) which is the
     unadjusted offset.  For stack-with-gaps the cached window is
     restricted to a single 4KB frame below, where adj_offset - offset
     is constant, so this still resolves correctly under ulong wrap. */
  *p_tlb_haddr_base = haddr - offset;

  if( FD_UNLIKELY( region == FD_VM_STACK_REGION && stack_gaps_enabled ) ) {
    /* Restrict the cached window to a single non-gap 4KB frame so the
       (adj_offset - offset) bias stays constant for all hits. */
    ulong frame_base = offset & ~0x1FFFUL;
    *p_tlb_vaddr_lo = region_bits | frame_base;
    *p_tlb_vaddr_hi = region_bits | (frame_base + 0x1000UL);
    /* Pre-zero the entire physical 4KB frame so subsequent TLB hits
       within this window don't need to consult the lazy-zero bitmap. */
    fd_vm_t * vm_mut = (fd_vm_t *)vm;
    fd_vm_lazy_zero_pages( vm_mut->stack_zero_bitmap, vm_mut->stack, frame_base >> 1, 0x1000UL );
  } else if( FD_UNLIKELY( region == FD_VM_STACK_REGION || region == FD_VM_HEAP_REGION ) ) {
    ulong page_base = offset & ~(FD_VM_LAZY_PAGE_SZ - 1UL);
    *p_tlb_vaddr_lo = region_bits | page_base;
    *p_tlb_vaddr_hi = region_bits | (page_base + FD_VM_LAZY_PAGE_SZ);
    /* Pre-zero the cached page (and any spillover into the next page
       that the current access touches; lazy_zero_pages is idempotent
       and page-granular). */
    fd_vm_t * vm_mut = (fd_vm_t *)vm;
    ulong * bitmap = (region == FD_VM_STACK_REGION) ? vm_mut->stack_zero_bitmap : vm_mut->heap_zero_bitmap;
    uchar * base   = (region == FD_VM_STACK_REGION) ? vm_mut->stack : vm_mut->heap;
    fd_vm_lazy_zero_pages( bitmap, base, page_base, ( adj_offset + sz ) - page_base );
  } else {
    *p_tlb_vaddr_lo = region_bits;
    *p_tlb_vaddr_hi = region_bits | region_sz;
  }

  return haddr;
}

/* fd_vm_mem_haddr_with_tlb is a TLB-accelerated wrapper around
   fd_vm_mem_haddr.  It caches the most recent successful translation
   in a single-slot "soft TLB" using vaddr-space bounds (3 ulongs:
   haddr_base, vaddr_lo, vaddr_hi).  On hit, translation costs ~8
   x86 instructions (always inlined): two range comparisons on vaddr
   plus an add for the host address.  On miss, calls
   fd_vm_mem_haddr_tlb_miss (not inlined) to resolve and populate.

   The hit-path sum `haddr_base + (vaddr & FD_VM_OFFSET_MASK)` may
   wrap under ulong arithmetic; this is intentional and correct because
   `haddr_base` was populated as `haddr - offset` (with the same
   wrap), so the two wraps cancel.  See audit §1.2.

   The TLB must be invalidated (set vaddr_hi=0) after any event that
   could change memory mappings (syscalls, CPI).

   Callers must use separate TLB instances for loads vs stores, since
   region_ld_sz and region_st_sz can differ. */

static inline __attribute__((always_inline)) ulong
fd_vm_mem_haddr_with_tlb( fd_vm_t const * vm,
                          ulong           vaddr,
                          ulong           sz,
                          ulong const *   vm_region_haddr,
                          uint  const *   vm_region_sz,
                          uchar           write,
                          ulong           sentinel,
                          ulong *         p_tlb_haddr_base,
                          ulong *         p_tlb_vaddr_lo,
                          ulong *         p_tlb_vaddr_hi,
                          int             stack_gaps_enabled ) {
  ulong vaddr_end = vaddr + sz;
  if( FD_LIKELY( vaddr >= *p_tlb_vaddr_lo
              && vaddr_end <= *p_tlb_vaddr_hi
              && vaddr_end >= vaddr ) ) {
    return *p_tlb_haddr_base + (vaddr & FD_VM_OFFSET_MASK);
  }

  return fd_vm_mem_haddr_tlb_miss( vm, vaddr, sz, vm_region_haddr, vm_region_sz,
                                   write, sentinel, p_tlb_haddr_base,
                                   p_tlb_vaddr_lo, p_tlb_vaddr_hi, stack_gaps_enabled );
}

/* fd_vm_mem_haddr_with_tlb_1 is a specialized variant of
   fd_vm_mem_haddr_with_tlb for single-byte accesses (sz=1).
   The TLB hit check simplifies to vaddr < vaddr_hi (since
   vaddr+1 <= hi iff vaddr < hi). */

static inline __attribute__((always_inline)) ulong
fd_vm_mem_haddr_with_tlb_1( fd_vm_t const * vm,
                            ulong           vaddr,
                            ulong const *   vm_region_haddr,
                            uint  const *   vm_region_sz,
                            uchar           write,
                            ulong           sentinel,
                            ulong *         p_tlb_haddr_base,
                            ulong *         p_tlb_vaddr_lo,
                            ulong *         p_tlb_vaddr_hi,
                            int             stack_gaps_enabled ) {
  if( FD_LIKELY( vaddr >= *p_tlb_vaddr_lo
              && vaddr <  *p_tlb_vaddr_hi ) ) {
    return *p_tlb_haddr_base + (vaddr & FD_VM_OFFSET_MASK);
  }

  return fd_vm_mem_haddr_tlb_miss( vm, vaddr, 1UL, vm_region_haddr, vm_region_sz,
                                   write, sentinel, p_tlb_haddr_base,
                                   p_tlb_vaddr_lo, p_tlb_vaddr_hi, stack_gaps_enabled );
}

static inline ulong
fd_vm_mem_haddr_fast( fd_vm_t const * vm,
                      ulong           vaddr,
                      ulong   const * vm_region_haddr ) { /* indexed [0,6) */
  ulong region   = FD_VADDR_TO_REGION( vaddr );
  ulong offset   = vaddr & FD_VM_OFFSET_MASK;
  if( FD_UNLIKELY( region==FD_VM_INPUT_REGION ) ) {
    return fd_vm_find_input_mem_region( vm, offset, 1UL, 0, 0UL );
  }
  return vm_region_haddr[ region ] + offset;
}

FD_FN_PURE static inline ulong fd_vm_mem_ld_1( ulong haddr ) {
  return (ulong)*(uchar const *)haddr;
}

FD_FN_PURE static inline ulong fd_vm_mem_ld_2( ulong haddr ) {
  ushort t;
  memcpy( &t, (void const *)haddr, sizeof(ushort) );
  return (ulong)t;
}

FD_FN_PURE static inline ulong fd_vm_mem_ld_4( ulong haddr ) {
  uint t;
  memcpy( &t, (void const *)haddr, sizeof(uint) );
  return (ulong)t;
}

FD_FN_PURE static inline ulong fd_vm_mem_ld_8( ulong haddr ) {
  ulong t;
  memcpy( &t, (void const *)haddr, sizeof(ulong) );
  return t;
}

static inline void fd_vm_mem_st_1( ulong haddr, uchar val ) {
  *(uchar *)haddr = val;
}

static inline void fd_vm_mem_st_2( ulong  haddr,
                                   ushort val ) {
  memcpy( (void *)haddr, &val, sizeof(ushort) );
}

static inline void fd_vm_mem_st_4( ulong haddr,
                                   uint  val ) {
  memcpy( (void *)haddr, &val, sizeof(uint) );
}

static inline void fd_vm_mem_st_8( ulong haddr,
                                   ulong val ) {
  memcpy( (void *)haddr, &val, sizeof(ulong) );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_vm_fd_vm_private_h */
