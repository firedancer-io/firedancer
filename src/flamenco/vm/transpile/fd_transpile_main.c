#include "fd_transpile_obj.h"
#include "../fd_vm.h"
#include "../../../ballet/base58/fd_base58.h"
#include "../../../ballet/blake3/fd_blake3.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static int
transpile_file( char const * input_path ) {
  int     result       = 1;
  FILE *  input        = NULL;
  FILE *  output       = NULL;
  void *  bin          = NULL;
  void *  rodata       = NULL;
  void *  prog_mem     = NULL;
  void *  syscalls_mem = NULL;
  void *  scratch      = NULL;
  void *  vm_mem       = NULL;
  uchar * obj          = NULL;
  fd_transpiler_t * t  = NULL;
  char *  output_path  = NULL;

  /* The input is named <base58(prog_id)>.so.  The output object goes
     next to it, named as fd_transpiler_export_archive expects. */

  char const * slash    = strrchr( input_path, '/' );
  char const * base     = slash ? slash+1 : input_path;
  ulong        dir_len  = (ulong)( base-input_path );
  ulong        base_len = strlen( base );
  uchar        prog_id[ 32 ];
  char         prog_id_b58[ FD_BASE58_ENCODED_32_SZ ];
  if( base_len<=3UL || base_len-3UL>=sizeof(prog_id_b58) || strcmp( base+base_len-3UL, ".so" ) ) {
    FD_LOG_WARNING(( "Expected an input filename of the form <base58 program id>.so, got %s", input_path ));
    goto done;
  }
  fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( prog_id_b58 ), base, base_len-3UL ) );
  if( !fd_base58_decode_32( prog_id_b58, prog_id ) ) {
    FD_LOG_WARNING(( "Expected an input filename of the form <base58 program id>.so, got %s", input_path ));
    goto done;
  }
  output_path = malloc( dir_len+64UL );
  if( !output_path ) goto done;
  memcpy( output_path, input_path, dir_len );
  if( !fd_cstr_printf_check( output_path+dir_len, 64UL, NULL, "fd_transpiled_%s.o", prog_id_b58 ) ) goto done;

  input = fopen( input_path, "rb" );
  if( !input || fseek( input, 0L, SEEK_END ) ) {
    FD_LOG_WARNING(( "Failed to open or seek %s", input_path ));
    goto done;
  }
  long file_sz = ftell( input );
  if( file_sz<=0L || fseek( input, 0L, SEEK_SET ) ) {
    FD_LOG_WARNING(( "Failed to size %s", input_path ));
    goto done;
  }
  ulong bin_sz = (ulong)file_sz;
  bin = malloc( bin_sz );
  if( !bin ) goto done;
  if( fread( bin, 1UL, bin_sz, input )!=bin_sz ) {
    FD_LOG_WARNING(( "Failed to read %s", input_path ));
    goto done;
  }
  if( fclose( input ) ) {
    input = NULL;
    FD_LOG_WARNING(( "Failed to close %s", input_path ));
    goto done;
  }
  input = NULL;

  fd_sbpf_loader_config_t config = { 0 };
  config.elf_deploy_checks = 1;
  config.sbpf_min_version = FD_SBPF_V0;
  config.sbpf_max_version = FD_SBPF_V3;
  fd_sbpf_elf_info_t info;
  if( fd_sbpf_elf_peek( &info, bin, bin_sz, &config ) ) {
    FD_LOG_WARNING(( "Invalid sBPF ELF: %s", input_path ));
    goto done;
  }

  rodata       = malloc( fd_ulong_max( info.load_buf_sz, bin_sz ) );
  prog_mem     = aligned_alloc( fd_sbpf_program_align(), fd_sbpf_program_footprint( &info ) );
  syscalls_mem = aligned_alloc( fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() );
  scratch      = malloc( bin_sz );
  if( !rodata || !prog_mem || !syscalls_mem || !scratch ) goto done;

  fd_sbpf_program_t * prog = fd_sbpf_program_new( prog_mem, &info, rodata );
  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new( syscalls_mem );
  if( !prog || !syscalls || fd_vm_syscall_register_all( syscalls, 0 ) ) {
    FD_LOG_WARNING(( "Failed to initialize sBPF loader" ));
    goto done;
  }
  if( fd_sbpf_program_load( prog, bin, bin_sz, syscalls, &config, scratch, bin_sz ) ) {
    FD_LOG_WARNING(( "Failed to load sBPF program: %s", input_path ));
    goto done;
  }

  vm_mem = aligned_alloc( fd_vm_align(), fd_vm_footprint() );
  if( !vm_mem ) goto done;
  fd_vm_t * vm = fd_vm_join( fd_vm_new( vm_mem ) );
  if( !vm ) goto done;
  vm->rodata       = prog->rodata;
  vm->rodata_sz    = prog->rodata_sz;
  vm->text         = prog->text;
  vm->text_cnt     = prog->info.text_cnt;
  vm->text_sz      = prog->info.text_sz;
  vm->sbpf_version = prog->info.sbpf_version;
  int vfy_err = fd_vm_validate( vm );
  if( vfy_err ) {
    FD_LOG_WARNING(( "sBPF verification failed for %s (%d-%s)", input_path, vfy_err, fd_vm_strerror( vfy_err ) ));
    goto done;
  }

  t = aligned_alloc( 64UL, sizeof(fd_transpiler_t) );
  if( !t ) goto done;

  int trans_err = fd_vm_transpile_prog( t, prog, syscalls );
  if( trans_err ) {
    FD_LOG_WARNING(( "fd_vm_transpile_prog failed" ));
    goto done;
  }

  memcpy( t->meta.prog_id, prog_id, 32UL );
  fd_blake3_hash( bin, bin_sz, t->meta.elf_hash );

  ulong obj_sz = 65536UL + t->code_sz + t->rodata_sz + ( t->reloc_cnt + t->rodata_reloc_cnt ) * 64UL;
  obj = malloc( obj_sz );
  if( !obj ) goto done;

  ulong elf_sz = fd_transpiler_export_obj( t, syscalls, obj, obj_sz );
  if( !elf_sz ) {
    FD_LOG_WARNING(( "fd_transpiler_export_obj failed" ));
    goto done;
  }

  output = fopen( output_path, "wb" );
  if( !output ) {
    FD_LOG_WARNING(( "Failed to open %s for writing", output_path ));
    goto done;
  }
  ulong written = fwrite( obj, 1UL, elf_sz, output );
  int close_err = fclose( output );
  if( written!=elf_sz || close_err ) {
    output = NULL;
    FD_LOG_WARNING(( "Failed to write %s", output_path ));
    goto done;
  }
  output = NULL;
  result = 0;
  FD_LOG_NOTICE(( "Wrote %s", output_path ));

done:
  if( input  ) fclose( input );
  if( output ) fclose( output );
  free( output_path );
  free( t );
  free( obj );
  free( vm_mem );
  free( scratch );
  free( syscalls_mem );
  free( prog_mem );
  free( rodata );
  free( bin );
  return result;
}

int
main( int    argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  int result = 0;
  for( int idx=1; idx<argc; idx++ ) {
    struct stat st;
    if( !stat( argv[idx], &st ) && S_ISDIR( st.st_mode ) ) {
      if( fd_transpiler_export_archive( argv[idx] ) ) {
        result = 1;
      }
    } else {
      if( transpile_file( argv[idx] ) ) {
        result = 1;
      }
    }
  }
  fd_halt();
  return result;
}
