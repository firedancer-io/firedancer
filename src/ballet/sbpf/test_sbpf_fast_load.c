/* test_sbpf_fast_load: unit tests for the lenient (v0-v2) no-scratch fast
   load path.  For real lenient program fixtures, validates:

     (1) a fast-eligible program (not legacy lenient) loads via the no-scratch
         fast path (load_buf_sz buffer, scratch==NULL); and
     (2) that load is byte-for-byte equivalent to the scratch fallback load
         (rodata bytes, rodata_sz, entry_pc, text layout, calldests); and
     (3) a program with a tail relocation is classified legacy lenient; and
     (4) the scratch fallback loads a program whose tail relocation lands
         inside the file.

   The fast path is the runtime program-cache path (reject_broken_elfs=0). */

#include "fd_sbpf_loader.h"
#include "../../util/fd_util.h"

#include <stdlib.h>
#include <string.h>

/* Same syscall hash set as test_sbpf_loader.c.  reject_broken_elfs is 0
   (runtime), so syscall resolution is not enforced at load; using the same
   set for both the fast and slow loads keeps them comparable regardless. */
static uint const _syscalls[] = {
  0xb6fc1a11, 0x686093bb, 0x207559bd, 0x5c2a3178, 0x52ba5096,
  0x7ef088ca, 0x9377323c, 0x48504a38, 0x11f49d86, 0xd7793abb,
  0x17e40350, 0x174c5122, 0xaa2607ca, 0xdd1c41a6, 0xd56b5fe9,
  0x23a29a61, 0x3b97b73c, 0xbf7188f6, 0x717cc4a3, 0x434371f8,
  0x5fdcde31, 0x3770fb22, 0xa22b9c85, 0xd7449092, 0x83f00e8f,
  0xa226d3eb, 0x5d2245e4, 0x7317b434, 0xadb8efc8, 0x85532d94,
  0U
};

/* fix_ prefix: an unprefixed fixture named after a libc symbol (clock)
   collides with it at link time. */

#define FIX(id,path) FD_IMPORT_BINARY( fix_##id, "src/ballet/sbpf/fixtures/" path )
FIX( hello,    "hello_solana_program.so"        );
FIX( hello_v2, "hello_solana_program_sbpf_v2.so" );
FIX( dup_ep,   "duplicate_entrypoint_entry.elf"  );
FIX( clock,    "clock_sysvar_program.so"         );
/* A lenient program with a relocation that targets the ELF tail (outside the
   read-only image): not fast-path eligible.  Its tail relocation points past
   the end of the file, so the scratch fallback rejects it. */
FIX( tail_reloc, "vm_program_tail_reloc.so" );
#undef FIX

/* A loaded program plus the buffers backing it. */
typedef struct {
  fd_sbpf_program_t * prog;
  void *              rodata;
  void *              prog_buf;
  void *              scratch;  /* NULL on the fast path */
  void *              sys_buf;
} loaded_t;

static int
do_load( uchar const *              bin,
         ulong                      bin_sz,
         fd_sbpf_elf_info_t const * info,
         int                        fast,
         loaded_t *                 out ) {
  ulong rodata_sz = fast ? info->load_buf_sz : info->bin_sz;

  out->rodata   = malloc( fd_ulong_max( rodata_sz, 1UL ) );
  out->prog_buf = aligned_alloc( fd_sbpf_program_align(), fd_sbpf_program_footprint( info ) );
  out->sys_buf  = aligned_alloc( fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() );
  out->scratch  = fast ? NULL : malloc( fd_ulong_max( bin_sz, 1UL ) );
  FD_TEST( out->rodata && out->prog_buf && out->sys_buf );

  fd_sbpf_program_t *  prog = fd_sbpf_program_new( out->prog_buf, info, out->rodata );
  FD_TEST( prog );
  fd_sbpf_syscalls_t * sys  = fd_sbpf_syscalls_new( out->sys_buf );
  for( uint const * x=_syscalls; *x; x++ ) fd_sbpf_syscalls_insert( sys, (ulong)*x );

  fd_sbpf_loader_config_t config = { 0 };
  config.elf_deploy_checks = 0; /* runtime path */
  config.sbpf_min_version  = FD_SBPF_V0;
  config.sbpf_max_version  = FD_SBPF_V3;

  int err = fd_sbpf_program_load( prog, bin, bin_sz, sys, &config,
                                  out->scratch, fast ? 0UL : bin_sz );
  out->prog = prog;
  return err;
}

static void
free_loaded( loaded_t * l ) {
  fd_sbpf_program_delete( l->prog );
  free( l->rodata ); free( l->prog_buf ); free( l->sys_buf );
  if( l->scratch ) free( l->scratch );
}

static void
test_fast_equiv( char const * name, uchar const * bin, ulong bin_sz ) {
  fd_sbpf_loader_config_t config = { 0 };
  config.sbpf_min_version = FD_SBPF_V0;
  config.sbpf_max_version = FD_SBPF_V3;

  fd_sbpf_elf_info_t info;
  FD_TEST( fd_sbpf_elf_peek( &info, bin, bin_sz, &config )==0 );

  /* These fixtures are lenient (v0-v2) programs. */
  FD_TEST( !fd_sbpf_enable_stricter_elf_headers_enabled( info.sbpf_version ) );

  /* (1) peek marked it fast-eligible (not legacy lenient), and the no-scratch
     fast load succeeds. */
  FD_TEST( !fd_sbpf_loader_is_legacy_lenient( &info ) );
  FD_TEST( info.load_buf_sz<=info.bin_sz );

  loaded_t fast, slow;
  FD_TEST( 0==do_load( bin, bin_sz, &info, 1, &fast ) ); /* fast: scratch==NULL  */
  FD_TEST( 0==do_load( bin, bin_sz, &info, 0, &slow ) ); /* slow: scratch buffer */

  /* (2) fast == slow, byte-for-byte and metadata-for-metadata. */
  FD_TEST( fast.prog->rodata_sz     == slow.prog->rodata_sz     );
  FD_TEST( fast.prog->entry_pc      == slow.prog->entry_pc      );
  FD_TEST( fast.prog->info.text_off == slow.prog->info.text_off );
  FD_TEST( fast.prog->info.text_cnt == slow.prog->info.text_cnt );
  FD_TEST( 0==memcmp( fast.rodata, slow.rodata, fast.prog->rodata_sz ) );

  if( fast.prog->calldests && slow.prog->calldests ) {
    for( ulong pc=0UL; pc<fast.prog->info.text_cnt; pc++ ) {
      FD_TEST( !!fd_sbpf_calldests_test( fast.prog->calldests, pc ) ==
               !!fd_sbpf_calldests_test( slow.prog->calldests, pc ) );
    }
  } else {
    FD_TEST( fast.prog->calldests==slow.prog->calldests ); /* both NULL */
  }

  FD_LOG_NOTICE(( "%-34s fast==slow OK (rodata_sz=%lu bin_sz=%lu saved=%lu)",
                  name, fast.prog->rodata_sz, bin_sz, bin_sz-fast.prog->rodata_sz ));

  free_loaded( &fast );
  free_loaded( &slow );
}

/* A program with a relocation that touches the ELF tail is classified legacy
   lenient (load_buf_sz==bin_sz) and handed to the scratch fallback, which
   rejects this fixture because the relocation points past the end of the
   file. */
static void
test_legacy_tail_reloc( char const * name, uchar const * bin, ulong bin_sz ) {
  fd_sbpf_loader_config_t config = { 0 };
  config.sbpf_min_version = FD_SBPF_V0;
  config.sbpf_max_version = FD_SBPF_V3;

  fd_sbpf_elf_info_t info;
  FD_TEST( fd_sbpf_elf_peek( &info, bin, bin_sz, &config )==0 );
  FD_TEST( !fd_sbpf_enable_stricter_elf_headers_enabled( info.sbpf_version ) );

  /* Classified legacy lenient -> scratch fallback (load_buf_sz==bin_sz). */
  FD_TEST(  fd_sbpf_loader_is_legacy_lenient( &info ) );
  FD_TEST(  info.load_buf_sz==info.bin_sz );

  /* The fallback (scratch) load reports this program's load result. */
  loaded_t slow;
  int err = do_load( bin, bin_sz, &info, 0 /* slow / fallback */, &slow );
  FD_TEST( err!=0 );
  free_loaded( &slow );

  FD_LOG_NOTICE(( "%-34s legacy-lenient fallback (load err=%d) OK", name, err ));
}

/* Move the first relocation of a fast-eligible program into the ELF tail,
   just past the read-only image.  The program becomes legacy lenient and
   the scratch fallback loads it, dropping the relocated tail bytes. */
static void
test_legacy_tail_reloc_loads( char const * name, uchar const * bin, ulong bin_sz ) {
  fd_sbpf_loader_config_t config = { 0 };
  config.sbpf_min_version = FD_SBPF_V0;
  config.sbpf_max_version = FD_SBPF_V3;

  fd_sbpf_elf_info_t info;
  FD_TEST( fd_sbpf_elf_peek( &info, bin, bin_sz, &config )==0 );
  FD_TEST( !fd_sbpf_loader_is_legacy_lenient( &info ) );
  FD_TEST( info.load_buf_sz+sizeof(ulong)<=bin_sz );

  uchar * copy = malloc( bin_sz );
  FD_TEST( copy );
  memcpy( copy, bin, bin_sz );
  fd_elf64_rel * rel = (fd_elf64_rel *)( copy+info.dt_rel_off );
  rel->r_offset = info.load_buf_sz;
  rel->r_info   = FD_ELF_R_BPF_64_RELATIVE;

  fd_sbpf_elf_info_t tail_info;
  FD_TEST( fd_sbpf_elf_peek( &tail_info, copy, bin_sz, &config )==0 );
  FD_TEST( fd_sbpf_loader_is_legacy_lenient( &tail_info ) );

  loaded_t slow;
  FD_TEST( 0==do_load( copy, bin_sz, &tail_info, 0 /* slow / fallback */, &slow ) );
  FD_TEST( slow.prog->rodata_sz==info.load_buf_sz );
  free_loaded( &slow );
  free( copy );

  FD_LOG_NOTICE(( "%-34s legacy-lenient fallback load OK", name ));
}

/* hello with pad_cnt SHT_NOBITS headers inserted after .text, so the
   read-only slices sit at high section indices (up to e_shnum==USHORT_MAX).
   Loads must match the unpadded program byte for byte. */
static void
test_ro_high_shidx( ulong pad_cnt ) {
  uchar const * src    = fix_hello;
  ulong         src_sz = fix_hello_sz;
  ulong  shoff  = FD_LOAD( ulong,  src+40 );
  ulong  shnum  = FD_LOAD( ushort, src+60 );
  ulong  strndx = FD_LOAD( ushort, src+62 );
  FD_TEST( shoff+shnum*sizeof(fd_elf64_shdr)==src_sz && strndx>1UL && shnum+pad_cnt<=USHORT_MAX );

  ulong   bin_sz = src_sz + pad_cnt*sizeof(fd_elf64_shdr);
  uchar * bin    = malloc( bin_sz );
  FD_TEST( bin );
  fd_memcpy( bin, src, shoff+2UL*sizeof(fd_elf64_shdr) ); /* through .text */
  fd_elf64_shdr pad = { .sh_type=FD_ELF_SHT_NOBITS };
  for( ulong i=0UL; i<pad_cnt; i++ ) fd_memcpy( bin+shoff+(2UL+i)*sizeof(fd_elf64_shdr), &pad, sizeof(pad) );
  fd_memcpy( bin+shoff+(2UL+pad_cnt)*sizeof(fd_elf64_shdr), src+shoff+2UL*sizeof(fd_elf64_shdr), (shnum-2UL)*sizeof(fd_elf64_shdr) );
  FD_STORE( ushort, bin+60, (ushort)(shnum+pad_cnt)  );
  FD_STORE( ushort, bin+62, (ushort)(strndx+pad_cnt) );

  fd_sbpf_loader_config_t config = { 0 };
  config.sbpf_min_version = FD_SBPF_V0;
  config.sbpf_max_version = FD_SBPF_V3;
  fd_sbpf_elf_info_t info, ref_info;
  FD_TEST( fd_sbpf_elf_peek( &info,     bin, bin_sz, &config )==0 );
  FD_TEST( fd_sbpf_elf_peek( &ref_info, src, src_sz, &config )==0 );
  FD_TEST( info.load_buf_sz==ref_info.load_buf_sz );

  loaded_t ref, fast, slow;
  FD_TEST( 0==do_load( src, src_sz, &ref_info, 1, &ref  ) );
  FD_TEST( 0==do_load( bin, bin_sz, &info,     1, &fast ) );
  FD_TEST( 0==do_load( bin, bin_sz, &info,     0, &slow ) );
  FD_TEST( fast.prog->rodata_sz==ref.prog->rodata_sz && slow.prog->rodata_sz==ref.prog->rodata_sz );
  FD_TEST( 0==memcmp( fast.rodata, ref.rodata, ref.prog->rodata_sz ) );
  FD_TEST( 0==memcmp( slow.rodata, ref.rodata, ref.prog->rodata_sz ) );
  free_loaded( &ref ); free_loaded( &fast ); free_loaded( &slow );
  free( bin );
  FD_LOG_NOTICE(( "ro slices at shidx>=%lu (e_shnum=%lu) OK", 2UL+pad_cnt, shnum+pad_cnt ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_fast_equiv( "hello_solana_program",         fix_hello,    fix_hello_sz    );
  test_fast_equiv( "hello_solana_program_sbpf_v2", fix_hello_v2, fix_hello_v2_sz );
  test_fast_equiv( "duplicate_entrypoint_entry",   fix_dup_ep,   fix_dup_ep_sz   );
  test_fast_equiv( "clock_sysvar_program",         fix_clock,    fix_clock_sz    );

  test_legacy_tail_reloc( "vm_program_tail_reloc", fix_tail_reloc, fix_tail_reloc_sz );
  test_legacy_tail_reloc_loads( "hello_solana_program", fix_hello, fix_hello_sz );

  test_ro_high_shidx( 70UL );
  test_ro_high_shidx( USHORT_MAX-9UL );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
