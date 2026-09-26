#include "fd_transpile_live.h"
#include "fd_transpile_runtime.h"
#include "../fd_vm_private.h"
#include "../../../ballet/murmur3/fd_murmur3.h"
#include "../../../ballet/sbpf/fd_sbpf_opcodes.h"
#include "../../runtime/fd_runtime.h"
#include "../../runtime/fd_system_ids.h"
#include "../../runtime/sysvar/fd_sysvar_cache.h"
#include "../../log_collector/fd_log_collector.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* maps_perms looks up the /proc/self/maps entry containing addr and
   copies its permission string (e.g. "r-xp") to perms.  Returns 0 on
   success or -1 if addr is not mapped. */

static int
maps_perms( ulong addr,
            char  perms[5] ) {
  FILE * f = fopen( "/proc/self/maps", "r" );
  FD_TEST( f );
  char line[ 512 ];
  int  found = -1;
  while( fgets( line, sizeof(line), f ) ) {
    ulong lo, hi;
    char  p[5];
    if( sscanf( line, "%lx-%lx %4s", &lo, &hi, p )!=3 ) continue;
    if( addr>=lo && addr<hi ) {
      memcpy( perms, p, 5UL );
      found = 0;
      break;
    }
  }
  fclose( f );
  return found;
}

static void
check_mapping( ulong        addr,
               ulong        sz,
               char const * expected ) {
  for( ulong off=0UL; off<sz; off+=FD_SHMEM_NORMAL_PAGE_SZ ) {
    char perms[5];
    FD_TEST( !maps_perms( addr+off, perms ) );
    if( FD_UNLIKELY( strcmp( perms, expected ) ) ) {
      FD_LOG_ERR(( "mapping %#lx has perms %s, expected %s", addr+off, perms, expected ));
    }
  }
}

/* Test program (sBPF v0):
     0: call sol_memset_         (r3=0 => no-op, sets r0=0)
     1: mov64 r2, 1
     2: lsh64 r2, 32
     3: add64 r2, 8*8            (r2 = vaddr of pc 8)
     4: callx r2
     5: add64 r0, 1
     6: exit
     7: exit
     8: mov64 r0, 41
     9: exit
   Returns 42.  Exercises a syscall veneer and the callx tables. */

#define TEST_TEXT_CNT 10UL

static void
test_program( fd_sbpf_program_t * prog,
              ulong *             text,
              void *              calldests_mem ) {
  ulong callx_dst = 8UL;
  uint  memset_id = fd_murmur3_32( "sol_memset_", 11UL, 0U );
  text[0] = fd_vm_instr( FD_SBPF_OP_CALL_IMM,  0, 0, 0, memset_id );
  text[1] = fd_vm_instr( FD_SBPF_OP_MOV64_IMM, 2, 0, 0, 1U );
  text[2] = fd_vm_instr( FD_SBPF_OP_LSH64_IMM, 2, 0, 0, 32U );
  text[3] = fd_vm_instr( FD_SBPF_OP_ADD64_IMM, 2, 0, 0, (uint)( callx_dst*8UL ) );
  text[4] = fd_vm_instr( FD_SBPF_OP_CALL_REG,  0, 0, 0, 2U );
  text[5] = fd_vm_instr( FD_SBPF_OP_ADD64_IMM, 0, 0, 0, 1U );
  text[6] = fd_vm_instr( FD_SBPF_OP_EXIT,      0, 0, 0, 0U );
  text[7] = fd_vm_instr( FD_SBPF_OP_EXIT,      0, 0, 0, 0U );
  text[8] = fd_vm_instr( FD_SBPF_OP_MOV64_IMM, 0, 0, 0, 41U );
  text[9] = fd_vm_instr( FD_SBPF_OP_EXIT,      0, 0, 0, 0U );

  fd_sbpf_calldests_t * calldests = fd_sbpf_calldests_join( fd_sbpf_calldests_new( calldests_mem, TEST_TEXT_CNT ) );
  FD_TEST( calldests );
  fd_sbpf_calldests_insert( calldests, 0UL       );
  fd_sbpf_calldests_insert( calldests, callx_dst );

  memset( prog, 0, sizeof(fd_sbpf_program_t) );
  prog->info.text_cnt     = (uint)TEST_TEXT_CNT;
  prog->info.text_sz      = TEST_TEXT_CNT*8UL;
  prog->info.sbpf_version = FD_SBPF_V0;
  prog->rodata            = text;
  prog->rodata_sz         = TEST_TEXT_CNT*8UL;
  prog->text              = text;
  prog->entry_pc          = 0UL;
  prog->calldests         = calldests;
}

static int
test_exec( fd_sbpf_program_t const *    prog,
           fd_sbpf_syscalls_t *         syscalls,
           fd_vm_transpiled_exec_func_t fn,
           long *                       cu ) {
  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );

  static fd_vm_t _vm[1];
  fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );
  FD_TEST( vm );
  FD_TEST( fd_vm_init( vm, NULL, FD_VM_HEAP_DEFAULT, FD_VM_COMPUTE_UNIT_LIMIT,
                       prog->rodata, prog->rodata_sz, prog->text, prog->info.text_cnt, 0UL, prog->info.text_sz,
                       prog->entry_pc, prog->calldests, prog->info.sbpf_version, syscalls, NULL, sha,
                       NULL, 0UL, NULL, 0, 0, 0, 0, 0, 0UL ) );

  int err = fn ? fn( vm ) : fd_vm_exec( vm );
  FD_TEST( vm->reg[0]==42UL );
  *cu = vm->cu;

  fd_vm_delete( fd_vm_leave( vm ) );
  fd_sha256_delete( fd_sha256_leave( sha ) );
  return err;
}

/* Frame pointer chain test

   Every sBPF function invocation has a psABI style x86 frame (see
   fd_transpile_x86.dasc).  A syscall handler walks the rbp chain and
   records how many frames lie between it and the root frame's caller.

   Program (sBPF v0), a recursion of depth FRAME_TEST_DEPTH that calls
   the probe syscall at the bottom:
     0: mov64 r1, FRAME_TEST_DEPTH
     1: call 3
     2: exit
     3: jeq r1, 0, +3        -> 7
     4: sub64 r1, 1
     5: call 3
     6: exit
     7: call frame_probe
     8: exit
   Entry frame + FRAME_TEST_DEPTH+1 frames of pc 3 are live at the
   probe. */

#define FRAME_TEST_DEPTH    (5UL)
#define FRAME_TEST_TEXT_CNT (9UL)

static int   frame_probe_armed;  /* only walk when called from transpiled code */
static ulong frame_probe_root;   /* frame address of test_frames */
static ulong frame_probe_cnt;    /* frames walked between probe and test_frames */
static ulong frame_probe_reg[ FD_VM_STACK_FRAME_MAX+2UL ];

static int
frame_probe( void * _vm,
             ulong  r1,
             ulong  r2,
             ulong  r3,
             ulong  r4,
             ulong  r5 ) {
  (void)_vm; (void)r1; (void)r2; (void)r3; (void)r4; (void)r5;
  if( !frame_probe_armed ) return 0;
  ulong cnt = 0UL;
  ulong bp  = (ulong)__builtin_frame_address( 0 );
  /* Walk until rbp equals test_frames' frame address.  Each hop must
     go up the stack. */
  while( bp!=frame_probe_root ) {
    FD_TEST( cnt<FD_VM_STACK_FRAME_MAX+2UL );
    ulong next = FD_VOLATILE_CONST( *(ulong *)bp );
    if( FD_UNLIKELY( next<=bp || next>frame_probe_root ) ) {
      FD_LOG_ERR(( "broken frame chain at hop %lu: rbp %#lx -> %#lx (root %#lx)", cnt, bp, next, frame_probe_root ));
    }
    frame_probe_reg[ cnt++ ] = FD_VOLATILE_CONST( *(ulong *)(bp+8UL) ); /* return address */
    bp = next;
  }
  frame_probe_cnt = cnt;
  return 0;
}

static ulong frame_test_text[ FRAME_TEST_TEXT_CNT ];

static void
frame_test_program( fd_sbpf_program_t * prog,
                    void *              calldests_mem ) {
  ulong * text = frame_test_text;
  text[0] = fd_vm_instr( FD_SBPF_OP_MOV64_IMM, 1, 0, 0, (uint)FRAME_TEST_DEPTH );
  text[1] = fd_vm_instr( FD_SBPF_OP_CALL_IMM,  0, 0, 0, fd_pchash( 3U ) );
  text[2] = fd_vm_instr( FD_SBPF_OP_EXIT,      0, 0, 0, 0U );
  text[3] = fd_vm_instr( FD_SBPF_OP_JEQ_IMM,   1, 0, 3, 0U );
  text[4] = fd_vm_instr( FD_SBPF_OP_SUB64_IMM, 1, 0, 0, 1U );
  text[5] = fd_vm_instr( FD_SBPF_OP_CALL_IMM,  0, 0, 0, fd_pchash( 3U ) );
  text[6] = fd_vm_instr( FD_SBPF_OP_EXIT,      0, 0, 0, 0U );
  text[7] = fd_vm_instr( FD_SBPF_OP_CALL_IMM,  0, 0, 0, fd_murmur3_32( "frame_probe", 11UL, 0U ) );
  text[8] = fd_vm_instr( FD_SBPF_OP_EXIT,      0, 0, 0, 0U );

  fd_sbpf_calldests_t * calldests = fd_sbpf_calldests_join( fd_sbpf_calldests_new( calldests_mem, FRAME_TEST_TEXT_CNT ) );
  FD_TEST( calldests );
  fd_sbpf_calldests_insert( calldests, 0UL );
  fd_sbpf_calldests_insert( calldests, 3UL );

  memset( prog, 0, sizeof(fd_sbpf_program_t) );
  prog->info.text_cnt     = (uint)FRAME_TEST_TEXT_CNT;
  prog->info.text_sz      = FRAME_TEST_TEXT_CNT*8UL;
  prog->info.sbpf_version = FD_SBPF_V0;
  prog->rodata            = text;
  prog->rodata_sz         = FRAME_TEST_TEXT_CNT*8UL;
  prog->text              = text;
  prog->entry_pc          = 0UL;
  prog->calldests         = calldests;
}

static void __attribute__((noinline))
test_frames( void ) {
  static fd_sbpf_program_t prog[1];
  void * calldests_mem = aligned_alloc( fd_sbpf_calldests_align(), fd_sbpf_calldests_footprint( FRAME_TEST_TEXT_CNT ) );
  FD_TEST( calldests_mem );
  frame_test_program( prog, calldests_mem );

  static fd_sbpf_syscalls_t _syscalls[ FD_SBPF_SYSCALLS_SLOT_CNT ];
  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_join( fd_sbpf_syscalls_new( _syscalls ) );
  FD_TEST( syscalls );
  FD_TEST( !fd_vm_syscall_register( syscalls, "frame_probe", frame_probe ) );

  fd_transpiled_live_t * live = fd_transpiled_live_create( prog, syscalls );
  FD_TEST( live );

  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );
  static fd_vm_t _vm[1];
  fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );
  FD_TEST( vm );
  FD_TEST( fd_vm_init( vm, NULL, FD_VM_HEAP_DEFAULT, FD_VM_COMPUTE_UNIT_LIMIT,
                       prog->rodata, prog->rodata_sz, prog->text, prog->info.text_cnt, 0UL, prog->info.text_sz,
                       prog->entry_pc, prog->calldests, prog->info.sbpf_version, syscalls, NULL, sha,
                       NULL, 0UL, NULL, 0, 0, 0, 0, 0, 0UL ) );

  /* Interpreter reference: the syscall is reached at the expected
     sBPF depth */
  FD_TEST( fd_vm_exec( vm )==FD_VM_SUCCESS );

  FD_TEST( fd_vm_init( vm, NULL, FD_VM_HEAP_DEFAULT, FD_VM_COMPUTE_UNIT_LIMIT,
                       prog->rodata, prog->rodata_sz, prog->text, prog->info.text_cnt, 0UL, prog->info.text_sz,
                       prog->entry_pc, prog->calldests, prog->info.sbpf_version, syscalls, NULL, sha,
                       NULL, 0UL, NULL, 0, 0, 0, 0, 0, 0UL ) );

  frame_probe_cnt   = 0UL;
  frame_probe_root  = (ulong)__builtin_frame_address( 0 );
  frame_probe_armed = 1;
  fd_vm_transpiled_exec_func_t fn = (fd_vm_transpiled_exec_func_t)live->text_haddr;
  FD_TEST( fn( vm )==FD_VM_SUCCESS );
  frame_probe_armed = 0;

  /* Chain: frame_probe, [syscall thunk has no frame], sBPF pc 3
     x(DEPTH+1), sBPF pc 0, root, test_frames.  The probe's own frame
     and the root frame are each counted as one hop. */
  ulong expect = 1UL /* frame_probe */ + (FRAME_TEST_DEPTH+1UL) + 1UL /* pc 0 */ + 1UL /* root */;
  if( FD_UNLIKELY( frame_probe_cnt!=expect ) ) {
    FD_LOG_ERR(( "frame chain has %lu hops, expected %lu", frame_probe_cnt, expect ));
  }
  /* Return addresses of sBPF frames point into the transpiled text */
  ulong text_lo = live->text_haddr;
  ulong text_hi = live->text_haddr + live->text_map_sz;
  for( ulong i=1UL; i<expect-1UL; i++ ) {
    if( FD_UNLIKELY( frame_probe_reg[ i ]<text_lo || frame_probe_reg[ i ]>=text_hi ) ) {
      FD_LOG_ERR(( "hop %lu return address %#lx outside transpiled text [%#lx,%#lx)", i, frame_probe_reg[ i ], text_lo, text_hi ));
    }
  }
  /* Root frame returns to test_frames */
  ulong self_lo = (ulong)test_frames;
  FD_TEST( frame_probe_reg[ expect-1UL ]>self_lo && frame_probe_reg[ expect-1UL ]<self_lo+4096UL );

  /* Fault unwinding from deep inside the frame chain restores the root
     frame: exhaust the call depth (DEPTH > FD_VM_STACK_FRAME_MAX) */
  frame_test_text[0] = fd_vm_instr( FD_SBPF_OP_MOV64_IMM, 1, 0, 0, (uint)(FD_VM_STACK_FRAME_MAX+8UL) );
  fd_transpiled_live_destroy( live );
  live = fd_transpiled_live_create( prog, syscalls );
  FD_TEST( live );
  fn = (fd_vm_transpiled_exec_func_t)live->text_haddr;
  FD_TEST( fd_vm_init( vm, NULL, FD_VM_HEAP_DEFAULT, FD_VM_COMPUTE_UNIT_LIMIT,
                       prog->rodata, prog->rodata_sz, prog->text, prog->info.text_cnt, 0UL, prog->info.text_sz,
                       prog->entry_pc, prog->calldests, prog->info.sbpf_version, syscalls, NULL, sha,
                       NULL, 0UL, NULL, 0, 0, 0, 0, 0, 0UL ) );
  int err_interp = fd_vm_exec( vm );
  long cu_interp = vm->cu;
  FD_TEST( fd_vm_init( vm, NULL, FD_VM_HEAP_DEFAULT, FD_VM_COMPUTE_UNIT_LIMIT,
                       prog->rodata, prog->rodata_sz, prog->text, prog->info.text_cnt, 0UL, prog->info.text_sz,
                       prog->entry_pc, prog->calldests, prog->info.sbpf_version, syscalls, NULL, sha,
                       NULL, 0UL, NULL, 0, 0, 0, 0, 0, 0UL ) );
  ulong bp_before = (ulong)__builtin_frame_address( 0 );
  int err_live = fn( vm );
  FD_TEST( (ulong)__builtin_frame_address( 0 )==bp_before );
  if( FD_UNLIKELY( err_interp!=err_live || cu_interp!=vm->cu ) ) {
    FD_LOG_ERR(( "depth fault mismatch: interp err %d cu %ld, live err %d cu %ld", err_interp, cu_interp, err_live, vm->cu ));
  }
  FD_LOG_NOTICE(( "depth fault: err %d cu %ld", err_live, vm->cu ));

  fd_vm_delete( fd_vm_leave( vm ) );
  fd_sha256_delete( fd_sha256_leave( sha ) );
  fd_transpiled_live_destroy( live );
  fd_sbpf_syscalls_delete( fd_sbpf_syscalls_leave( syscalls ) );
  free( calldests_mem );
  FD_LOG_NOTICE(( "frame chain ok (%lu hops)", frame_probe_cnt ));
}

/* Frame-relative fast path test

   Loads and stores through r10 within the current frame bypass address
   translation and use vm->transpiled.frame_haddr.  The program stores
   at the extreme legal offsets (-FD_VM_STACK_FRAME_SZ and -width) of
   each frame along a call chain of depth 2, verifies callee frames
   read as zero before being written, and verifies caller slots survive
   the call.  r0 accumulates mismatches and is 42 iff none occurred.
   The same program runs under the interpreter and transpiled code for
   sBPF v0 (gapped stack) and v3 (dense stack); results must match. */

#define SLOT_TEST_TEXT_CNT (52UL)
#define SLOT_TEST_F1       (18UL)
#define SLOT_TEST_F2       (42UL)

static ulong slot_test_text[ SLOT_TEST_TEXT_CNT ];

static void
slot_test_program( fd_sbpf_program_t * prog,
                   void *              calldests_mem,
                   ulong               sbpf_version ) {
  ulong * text = slot_test_text;
  short   lo   = (short)-(long)FD_VM_STACK_FRAME_SZ;
# define CALL(pc,target) ( FD_VM_SBPF_STATIC_SYSCALLS( sbpf_version ) ? \
    fd_vm_instr( FD_SBPF_OP_CALL_IMM, 0, 1, 0, (uint)(int)((long)(target)-(long)(pc)-1L) ) : \
    fd_vm_instr( FD_SBPF_OP_CALL_IMM, 0, 0, 0, fd_pchash( (uint)(target) ) ) )
  /* entry */
  text[ 0] = fd_vm_instr( FD_SBPF_OP_MOV64_IMM, 1, 0,  0, 0x11U );
  text[ 1] = fd_vm_instr( FD_SBPF_OP_STXDW,    10, 1, lo, 0U );
  text[ 2] = fd_vm_instr( FD_SBPF_OP_STXB,     10, 1, -1, 0U );
  text[ 3] = fd_vm_instr( FD_SBPF_OP_MOV64_IMM, 2, 0,  0, 0x22U );
  text[ 4] = fd_vm_instr( FD_SBPF_OP_STXDW,    10, 2, -16, 0U );
  text[ 5] = CALL( 5UL, SLOT_TEST_F1 );
  text[ 6] = fd_vm_instr( FD_SBPF_OP_LDXDW,     3, 10, lo, 0U );
  text[ 7] = fd_vm_instr( FD_SBPF_OP_LDXB,      4, 10, -1, 0U );
  text[ 8] = fd_vm_instr( FD_SBPF_OP_LDXDW,     5, 10, -16, 0U );
  text[ 9] = fd_vm_instr( FD_SBPF_OP_XOR64_IMM, 3, 0,  0, 0x11U );
  text[10] = fd_vm_instr( FD_SBPF_OP_XOR64_IMM, 4, 0,  0, 0x11U );
  text[11] = fd_vm_instr( FD_SBPF_OP_XOR64_IMM, 5, 0,  0, 0x22U );
  text[12] = fd_vm_instr( FD_SBPF_OP_OR64_REG,  0, 3,  0, 0U );
  text[13] = fd_vm_instr( FD_SBPF_OP_OR64_REG,  0, 4,  0, 0U );
  text[14] = fd_vm_instr( FD_SBPF_OP_OR64_REG,  0, 5,  0, 0U );
  text[15] = fd_vm_instr( FD_SBPF_OP_JNE_IMM,   0, 0,  1, 0U );
  text[16] = fd_vm_instr( FD_SBPF_OP_MOV64_IMM, 0, 0,  0, 42U );
  text[17] = fd_vm_instr( FD_SBPF_OP_EXIT,      0, 0,  0, 0U );
  /* f1: zero-check own frame, write it, spill the check to [r10-24],
     call f2, verify own frame survived */
  text[18] = fd_vm_instr( FD_SBPF_OP_LDXDW,     1, 10, lo, 0U );
  text[19] = fd_vm_instr( FD_SBPF_OP_LDXB,      2, 10, -1, 0U );
  text[20] = fd_vm_instr( FD_SBPF_OP_LDXDW,     3, 10, -16, 0U );
  text[21] = fd_vm_instr( FD_SBPF_OP_OR64_REG,  1, 2,  0, 0U );
  text[22] = fd_vm_instr( FD_SBPF_OP_OR64_REG,  1, 3,  0, 0U );
  text[23] = fd_vm_instr( FD_SBPF_OP_MOV64_IMM, 2, 0,  0, 0x33U );
  text[24] = fd_vm_instr( FD_SBPF_OP_STXDW,    10, 2, lo, 0U );
  text[25] = fd_vm_instr( FD_SBPF_OP_STXB,     10, 2, -1, 0U );
  text[26] = fd_vm_instr( FD_SBPF_OP_MOV64_IMM, 2, 0,  0, 0x44U );
  text[27] = fd_vm_instr( FD_SBPF_OP_STXDW,    10, 2, -16, 0U );
  text[28] = fd_vm_instr( FD_SBPF_OP_STXDW,    10, 1, -24, 0U );
  text[29] = CALL( 29UL, SLOT_TEST_F2 );
  text[30] = fd_vm_instr( FD_SBPF_OP_LDXDW,     1, 10, -24, 0U );
  text[31] = fd_vm_instr( FD_SBPF_OP_OR64_REG,  0, 1,  0, 0U );
  text[32] = fd_vm_instr( FD_SBPF_OP_LDXDW,     3, 10, lo, 0U );
  text[33] = fd_vm_instr( FD_SBPF_OP_LDXB,      4, 10, -1, 0U );
  text[34] = fd_vm_instr( FD_SBPF_OP_LDXDW,     5, 10, -16, 0U );
  text[35] = fd_vm_instr( FD_SBPF_OP_XOR64_IMM, 3, 0,  0, 0x33U );
  text[36] = fd_vm_instr( FD_SBPF_OP_XOR64_IMM, 4, 0,  0, 0x33U );
  text[37] = fd_vm_instr( FD_SBPF_OP_XOR64_IMM, 5, 0,  0, 0x44U );
  text[38] = fd_vm_instr( FD_SBPF_OP_OR64_REG,  0, 3,  0, 0U );
  text[39] = fd_vm_instr( FD_SBPF_OP_OR64_REG,  0, 4,  0, 0U );
  text[40] = fd_vm_instr( FD_SBPF_OP_OR64_REG,  0, 5,  0, 0U );
  text[41] = fd_vm_instr( FD_SBPF_OP_EXIT,      0, 0,  0, 0U );
  /* f2: return zero-check of own frame in r0, then write it */
  text[42] = fd_vm_instr( FD_SBPF_OP_LDXDW,     0, 10, lo, 0U );
  text[43] = fd_vm_instr( FD_SBPF_OP_LDXB,      1, 10, -1, 0U );
  text[44] = fd_vm_instr( FD_SBPF_OP_LDXDW,     2, 10, -16, 0U );
  text[45] = fd_vm_instr( FD_SBPF_OP_OR64_REG,  0, 1,  0, 0U );
  text[46] = fd_vm_instr( FD_SBPF_OP_OR64_REG,  0, 2,  0, 0U );
  text[47] = fd_vm_instr( FD_SBPF_OP_MOV64_IMM, 1, 0,  0, 0x55U );
  text[48] = fd_vm_instr( FD_SBPF_OP_STXDW,    10, 1, lo, 0U );
  text[49] = fd_vm_instr( FD_SBPF_OP_STXB,     10, 1, -1, 0U );
  text[50] = fd_vm_instr( FD_SBPF_OP_STXDW,    10, 1, -16, 0U );
  text[51] = fd_vm_instr( FD_SBPF_OP_EXIT,      0, 0,  0, 0U );
# undef CALL

  fd_sbpf_calldests_t * calldests = fd_sbpf_calldests_join( fd_sbpf_calldests_new( calldests_mem, SLOT_TEST_TEXT_CNT ) );
  FD_TEST( calldests );
  fd_sbpf_calldests_insert( calldests, 0UL          );
  fd_sbpf_calldests_insert( calldests, SLOT_TEST_F1 );
  fd_sbpf_calldests_insert( calldests, SLOT_TEST_F2 );

  memset( prog, 0, sizeof(fd_sbpf_program_t) );
  prog->info.text_cnt     = (uint)SLOT_TEST_TEXT_CNT;
  prog->info.text_sz      = SLOT_TEST_TEXT_CNT*8UL;
  prog->info.sbpf_version = sbpf_version;
  prog->rodata            = text;
  prog->rodata_sz         = SLOT_TEST_TEXT_CNT*8UL;
  prog->text              = text;
  prog->entry_pc          = 0UL;
  prog->calldests         = FD_VM_SBPF_STATIC_SYSCALLS( sbpf_version ) ? NULL : calldests;
}

static void
slot_test_run( fd_sbpf_program_t const *    prog,
               fd_sbpf_syscalls_t *         syscalls,
               fd_vm_transpiled_exec_func_t fn,
               fd_vm_t *                    vm ) {
  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );
  FD_TEST( fd_vm_join( fd_vm_new( vm ) ) );
  FD_TEST( fd_vm_init( vm, NULL, FD_VM_HEAP_DEFAULT, FD_VM_COMPUTE_UNIT_LIMIT,
                       prog->rodata, prog->rodata_sz, prog->text, prog->info.text_cnt, 0UL, prog->info.text_sz,
                       prog->entry_pc, prog->calldests, prog->info.sbpf_version, syscalls, NULL, sha,
                       NULL, 0UL, NULL, 0, 0, 0, 0, 0, 0UL ) );
  FD_TEST( ( fn ? fn( vm ) : fd_vm_exec( vm ) )==FD_VM_SUCCESS );
  FD_TEST( vm->reg[0]==42UL );
  fd_sha256_delete( fd_sha256_leave( sha ) );
}

static void
test_frame_slots( fd_sbpf_syscalls_t * syscalls,
                  ulong                sbpf_version ) {
  static fd_sbpf_program_t prog[1];
  void * calldests_mem = aligned_alloc( fd_sbpf_calldests_align(), fd_sbpf_calldests_footprint( SLOT_TEST_TEXT_CNT ) );
  FD_TEST( calldests_mem );
  slot_test_program( prog, calldests_mem, sbpf_version );

  fd_transpiled_live_t * live = fd_transpiled_live_create( prog, syscalls );
  FD_TEST( live );

  static fd_vm_t vm_interp[1];
  static fd_vm_t vm_live[1];
  slot_test_run( prog, syscalls, NULL, vm_interp );
  slot_test_run( prog, syscalls, (fd_vm_transpiled_exec_func_t)live->text_haddr, vm_live );

  FD_TEST( vm_interp->cu         ==vm_live->cu          );
  FD_TEST( vm_interp->frame_cnt  ==vm_live->frame_cnt   );
  FD_TEST( vm_interp->stack_clean==vm_live->stack_clean );
  FD_TEST( vm_interp->stack_clean>=3UL*FD_VM_STACK_FRAME_SZ );
  FD_TEST( !memcmp( vm_interp->reg,   vm_live->reg,   FD_VM_REG_CNT*sizeof(ulong) ) );
  FD_TEST( !memcmp( vm_interp->stack, vm_live->stack, vm_live->stack_clean ) );

  /* Host stack frames are dense for both layouts */
  uchar const * f0 = vm_live->stack;
  uchar const * f1 = f0 + FD_VM_STACK_FRAME_SZ;
  uchar const * f2 = f1 + FD_VM_STACK_FRAME_SZ;
  FD_TEST( FD_LOAD( ulong, f0 )==0x11UL && f0[ FD_VM_STACK_FRAME_SZ-1UL ]==0x11 && FD_LOAD( ulong, f0+FD_VM_STACK_FRAME_SZ-16UL )==0x22UL );
  FD_TEST( FD_LOAD( ulong, f1 )==0x33UL && f1[ FD_VM_STACK_FRAME_SZ-1UL ]==0x33 && FD_LOAD( ulong, f1+FD_VM_STACK_FRAME_SZ-16UL )==0x44UL );
  FD_TEST( FD_LOAD( ulong, f2 )==0x55UL && f2[ FD_VM_STACK_FRAME_SZ-1UL ]==0x55 && FD_LOAD( ulong, f2+FD_VM_STACK_FRAME_SZ-16UL )==0x55UL );
  FD_TEST( FD_LOAD( ulong, f1+FD_VM_STACK_FRAME_SZ-24UL )==0UL );

  fd_vm_delete( fd_vm_leave( vm_live   ) );
  fd_vm_delete( fd_vm_leave( vm_interp ) );
  fd_transpiled_live_destroy( live );
  free( calldests_mem );
  FD_LOG_NOTICE(( "frame slots ok (sbpf v%lu)", sbpf_version ));
}

/* sBPF program fixtures from the repo.  Each is loaded, executed by
   fd_vm_exec and by transpiled code, and the results compared. */

#define FIX(id,path) FD_IMPORT_BINARY( id, "src/ballet/sbpf/fixtures/" path )
FIX( fixture_hello,       "hello_solana_program.so" );
FIX( fixture_clock,       "clock_sysvar_program.so" );
FIX( fixture_spl_p_token, "spl_p_token.so"          );
#undef FIX

static struct {
  char const *  name;
  uchar const * bin;
  ulong const * bin_sz;
} const fixtures[] = {
  { "hello_solana_program", fixture_hello,       &fixture_hello_sz       },
  { "clock_sysvar_program", fixture_clock,       &fixture_clock_sz       },
  { "spl_p_token",          fixture_spl_p_token, &fixture_spl_p_token_sz },
  {0}
};

/* Minimal runtime environment for syscalls: log collector, clock
   sysvar, instruction stack depth, and error reporting. */

typedef struct {
  fd_runtime_t *      runtime;
  fd_txn_out_t *      txn_out;
  fd_bank_t *         bank;
  fd_sysvar_cache_t * sysvar_cache;
  fd_log_collector_t  log[1];
  fd_instr_info_t     instr[1];
  fd_exec_instr_ctx_t instr_ctx[1];
} test_env_t;

static void
test_env_init( test_env_t * env ) {
  env->runtime      = calloc( 1UL, sizeof(fd_runtime_t) );
  env->txn_out      = calloc( 1UL, sizeof(fd_txn_out_t) );
  env->bank         = calloc( 1UL, sizeof(fd_bank_t)    );
  FD_TEST( env->runtime && env->txn_out && env->bank );
  static fd_sysvar_cache_t cache_mem[1];
  env->sysvar_cache = fd_sysvar_cache_join( fd_sysvar_cache_new( cache_mem ) );
  FD_TEST( env->sysvar_cache );

  fd_sol_sysvar_clock_t clock = {
    .slot                  = 1234UL,
    .epoch_start_timestamp = 1700000000L,
    .epoch                 = 5UL,
    .leader_schedule_epoch = 6UL,
    .unix_timestamp        = 1700000400L
  };
  fd_sysvar_cache_restore_one( env->sysvar_cache, &fd_sysvar_clock_id, 1UL, (uchar const *)&clock, sizeof(clock) );

  fd_features_disable_all( &env->bank->f.features );
  env->runtime->log.log_collector = env->log;
  env->runtime->instr.stack_sz    = 1;
  env->txn_out->accounts.cnt      = 1; /* program id: zero pubkey */

  memset( env->instr, 0, sizeof(fd_instr_info_t) );
  env->instr->stack_height = 1;

  memset( env->instr_ctx, 0, sizeof(fd_exec_instr_ctx_t) );
  env->instr_ctx->instr        = env->instr;
  env->instr_ctx->runtime      = env->runtime;
  env->instr_ctx->txn_out      = env->txn_out;
  env->instr_ctx->bank         = env->bank;
  env->instr_ctx->sysvar_cache = env->sysvar_cache;
  strcpy( env->instr_ctx->program_id_base58, "11111111111111111111111111111111" );
}

static void
test_env_fini( test_env_t * env ) {
  fd_sysvar_cache_delete( fd_sysvar_cache_leave( env->sysvar_cache ) );
  free( env->bank );
  free( env->txn_out );
  free( env->runtime );
}

typedef struct {
  int   err;
  ulong bail_cnt;
  ulong r0;
  long  cu;
  ulong log_sz;
  uchar log[ FD_LOG_COLLECTOR_MAX + FD_LOG_COLLECTOR_EXTRA ];
} test_result_t;

static void
fixture_exec( test_env_t *                 env,
              fd_sbpf_program_t const *    prog,
              fd_sbpf_syscalls_t *         syscalls,
              fd_vm_transpiled_exec_func_t fn,
              test_result_t *              out ) {
  fd_log_collector_init( env->log, 1 );
  memset( &env->txn_out->err, 0, sizeof(env->txn_out->err) );
  memset( &env->txn_out->details.return_data, 0, sizeof(env->txn_out->details.return_data) );

  /* Serialized input: no accounts, empty instruction data, zero
     program id */
  static uchar input[ 64 ] __attribute__((aligned(16)));
  memset( input, 0, sizeof(input) );
  fd_vm_input_region_t region = {
    .haddr                  = (ulong)input,
    .region_sz              = (uint)sizeof(input),
    .address_space_reserved = sizeof(input),
    .is_writable            = 1
  };

  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );
  static fd_vm_t _vm[1];
  fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );
  FD_TEST( vm );
  FD_TEST( fd_vm_init( vm, env->instr_ctx, FD_VM_HEAP_DEFAULT, FD_VM_COMPUTE_UNIT_LIMIT,
                       prog->rodata, prog->rodata_sz, prog->text, prog->info.text_cnt, prog->info.text_off, prog->info.text_sz,
                       prog->entry_pc, prog->calldests, prog->info.sbpf_version, syscalls, NULL, sha,
                       &region, 1UL, NULL, 0, 0, 0, 0, 0, 0UL ) );
  FD_TEST( fd_vm_validate( vm )==FD_VM_SUCCESS );

  out->bail_cnt = 0UL;
  if( fn ) {
    out->err = fn( vm );
    if( out->err==FD_VM_ERR_EBPF_BAIL ) {
      out->bail_cnt++;
      out->err = fd_vm_exec( vm );
    }
  } else {
    out->err = fd_vm_exec( vm );
  }
  out->r0     = vm->reg[0];
  out->cu     = vm->cu;
  out->log_sz = env->log->buf_sz;
  memcpy( out->log, env->log->buf, out->log_sz );

  fd_vm_delete( fd_vm_leave( vm ) );
  fd_sha256_delete( fd_sha256_leave( sha ) );
}

static void
test_fixtures( fd_sbpf_syscalls_t * syscalls ) {
  test_env_t env[1];
  test_env_init( env );
  static test_result_t res_interp[1];
  static test_result_t res_live  [1];

  fd_sbpf_loader_config_t config = {
    .elf_deploy_checks = 0,
    .sbpf_min_version  = FD_SBPF_V0,
    .sbpf_max_version  = FD_SBPF_V3
  };

  for( ulong i=0UL; fixtures[i].name; i++ ) {
    uchar const * bin    = fixtures[i].bin;
    ulong         bin_sz = *fixtures[i].bin_sz;

    fd_sbpf_elf_info_t info;
    FD_TEST( !fd_sbpf_elf_peek( &info, bin, bin_sz, &config ) );
    void * rodata   = aligned_alloc( FD_SBPF_PROG_RODATA_ALIGN, fd_ulong_align_up( fd_ulong_max( info.bin_sz, 1UL ), FD_SBPF_PROG_RODATA_ALIGN ) );
    void * prog_mem = aligned_alloc( fd_sbpf_program_align(), fd_sbpf_program_footprint( &info ) );
    void * scratch  = malloc( bin_sz );
    FD_TEST( rodata && prog_mem && scratch );
    fd_sbpf_program_t * prog = fd_sbpf_program_new( prog_mem, &info, rodata );
    FD_TEST( prog );
    FD_TEST( !fd_sbpf_program_load( prog, bin, bin_sz, syscalls, &config, scratch, bin_sz ) );

    fd_transpiled_live_t * live = fd_transpiled_live_create( prog, syscalls );
    FD_TEST( live );

    fixture_exec( env, prog, syscalls, NULL, res_interp );
    fixture_exec( env, prog, syscalls, (fd_vm_transpiled_exec_func_t)live->text_haddr, res_live );

    if( FD_UNLIKELY( res_interp->err!=res_live->err ||
                     res_interp->r0 !=res_live->r0  ||
                     res_interp->cu !=res_live->cu  ||
                     res_interp->log_sz!=res_live->log_sz ||
                     memcmp( res_interp->log, res_live->log, res_interp->log_sz ) ) ) {
      FD_LOG_ERR(( "%s: mismatch (interp err %d r0 %#lx cu %ld log_sz %lu) (live err %d r0 %#lx cu %ld log_sz %lu)",
                   fixtures[i].name,
                   res_interp->err, res_interp->r0, res_interp->cu, res_interp->log_sz,
                   res_live->err,   res_live->r0,   res_live->cu,   res_live->log_sz ));
    }
    FD_LOG_NOTICE(( "%s: ok (err %d r0 %#lx cu %ld log_sz %lu bail %lu)",
                    fixtures[i].name, res_live->err, res_live->r0, res_live->cu, res_live->log_sz, res_live->bail_cnt ));

    fd_transpiled_live_destroy( live );
    free( scratch );
    free( prog_mem );
    free( rodata );
  }

  test_env_fini( env );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  static ulong text[ TEST_TEXT_CNT ];
  static fd_sbpf_program_t prog[1];
  void * calldests_mem = aligned_alloc( fd_sbpf_calldests_align(), fd_sbpf_calldests_footprint( TEST_TEXT_CNT ) );
  FD_TEST( calldests_mem );
  test_program( prog, text, calldests_mem );

  static fd_sbpf_syscalls_t _syscalls[ FD_SBPF_SYSCALLS_SLOT_CNT ];
  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_join( fd_sbpf_syscalls_new( _syscalls ) );
  FD_TEST( syscalls );
  FD_TEST( !fd_vm_syscall_register_all( syscalls, 0 ) );

  FD_TEST( !fd_transpiled_live_create( NULL, syscalls ) );
  FD_TEST( !fd_transpiled_live_create( prog, NULL ) );
  fd_transpiled_live_destroy( NULL );

  fd_transpiled_live_t * live = fd_transpiled_live_create( prog, syscalls );
  FD_TEST( live );

  /* Layout and permissions */

  ulong text_lo   = live->text_haddr;
  ulong rodata_lo = live->rodata_haddr;
  FD_TEST( fd_ulong_is_aligned( text_lo,            FD_SHMEM_NORMAL_PAGE_SZ ) );
  FD_TEST( fd_ulong_is_aligned( rodata_lo,          FD_SHMEM_NORMAL_PAGE_SZ ) );
  FD_TEST( fd_ulong_is_aligned( live->text_map_sz,   FD_SHMEM_NORMAL_PAGE_SZ ) );
  FD_TEST( fd_ulong_is_aligned( live->rodata_map_sz, FD_SHMEM_NORMAL_PAGE_SZ ) );
  FD_TEST( (ulong)live==rodata_lo );
  FD_TEST( text_lo+live->text_map_sz<=rodata_lo || rodata_lo+live->rodata_map_sz<=text_lo );
  long gap = (long)text_lo - (long)rodata_lo;
  FD_TEST( gap<(long)INT_MAX && gap>(long)INT_MIN );
  check_mapping( text_lo,   live->text_map_sz,   "r-xp" );
  check_mapping( rodata_lo, live->rodata_map_sz, "r--p" );

  /* Execution matches the interpreter */

  long cu_interp, cu_live;
  FD_TEST( test_exec( prog, syscalls, NULL, &cu_interp )==FD_VM_SUCCESS );
  FD_TEST( test_exec( prog, syscalls, (fd_vm_transpiled_exec_func_t)live->text_haddr, &cu_live )==FD_VM_SUCCESS );
  if( FD_UNLIKELY( cu_interp!=cu_live ) ) FD_LOG_ERR(( "cu mismatch: interp %ld, live %ld", cu_interp, cu_live ));

  /* Placement is randomized */

  ulong gap_cnt = 0UL;
  for( ulong i=0UL; i<8UL; i++ ) {
    fd_transpiled_live_t * live2 = fd_transpiled_live_create( prog, syscalls );
    FD_TEST( live2 );
    if( (long)live2->text_haddr - (long)live2->rodata_haddr != gap ) gap_cnt++;
    fd_transpiled_live_destroy( live2 );
  }
  FD_TEST( gap_cnt>0UL );

  fd_transpiled_live_destroy( live );
  char perms[5];
  FD_TEST( maps_perms( text_lo,   perms ) );
  FD_TEST( maps_perms( rodata_lo, perms ) );

  test_fixtures( syscalls );
  test_frames();
  test_frame_slots( syscalls, FD_SBPF_V0 );
  test_frame_slots( syscalls, FD_SBPF_V3 );

  fd_sbpf_syscalls_delete( fd_sbpf_syscalls_leave( syscalls ) );
  free( calldests_mem );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
