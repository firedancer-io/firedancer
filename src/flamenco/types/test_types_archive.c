#include "fd_types.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#define SLOT_BANK_BIN "dump/slot_bank.bin"
#define EPOCH_BANK_BIN "dump/epoch_bank.bin"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

#define SCRATCH_MAX (1<<28UL)
#define SCRATCH_DEPTH (16UL)
  void * smem = aligned_alloc( fd_scratch_smem_align(), fd_scratch_smem_footprint( SCRATCH_MAX ) );
  void * fmem = aligned_alloc(  fd_scratch_fmem_align(), fd_scratch_fmem_footprint( SCRATCH_DEPTH ) );
  FD_TEST( ( !!smem ) & ( !!fmem ) );
  fd_scratch_attach( smem, fmem, SCRATCH_MAX, SCRATCH_DEPTH );

  {
    struct stat statbuf;
    if( stat(SLOT_BANK_BIN, &statbuf) ) {
      if( errno == ENOENT )
        FD_LOG_ERR(( SLOT_BANK_BIN " is missing try running 'gsutil cp gs://firedancer-ci-resources/slot_bank.bin dump/'" ));
      else
        FD_LOG_ERR(( SLOT_BANK_BIN ": %s", strerror(errno) ));
      return 1;
    }
    FILE* fd = fopen(SLOT_BANK_BIN, "r");
    if( fd == NULL ) {
      FD_LOG_ERR(( SLOT_BANK_BIN ": %s", strerror(errno) ));
      return 1;
    }
    uchar * buf = malloc((size_t)statbuf.st_size);
    if( fread(buf, 1, (size_t)statbuf.st_size, fd) != (size_t)statbuf.st_size ) {
      FD_LOG_ERR(( SLOT_BANK_BIN ": %s", strerror(errno) ));
      return 1;
    }
    fclose(fd);

    FD_LOG_NOTICE(( "read %lu bytes from " SLOT_BANK_BIN, (ulong)statbuf.st_size ));

    fd_slot_bank_t slot_bank;

    fd_bincode_decode_ctx_t ctx;
    ctx.data = buf;
    ctx.dataend = buf + statbuf.st_size;
    ctx.valloc  = fd_libc_alloc_virtual();
    if( fd_slot_bank_decode(&slot_bank, &ctx )!=FD_BINCODE_SUCCESS ||
        ctx.data != ctx.dataend ) {
      FD_LOG_ERR(( "fd_slot_bank_decode failed" ));
      return 1;
    }

    FD_LOG_NOTICE(( "decoded slot_bank" ));

    fd_bincode_encode_ctx_t ctx2;
    uchar * buf2 = malloc((size_t)statbuf.st_size * 2);
    ctx2.data = buf2;
    ctx2.dataend = buf2 + statbuf.st_size*2;
    if( fd_slot_bank_encode_archival(&slot_bank, &ctx2 )!=FD_BINCODE_SUCCESS) {
      FD_LOG_ERR(( "fd_slot_bank_encode_archival failed" ));
      return 1;
    }

    ulong arch_sz = (ulong)((uchar*)ctx2.data - buf2);
    FD_LOG_NOTICE(( "encoded slot_bank into %lu bytes", arch_sz ));

    fd_slot_bank_t slot_bank2;

    fd_bincode_decode_ctx_t ctx3;
    ctx3.data = buf2;
    ctx3.dataend = buf2 + arch_sz;
    ctx3.valloc  = fd_libc_alloc_virtual();
    if( fd_slot_bank_decode_archival(&slot_bank2, &ctx3 )!=FD_BINCODE_SUCCESS ||
        ctx3.data != ctx3.dataend ) {
      FD_LOG_ERR(( "fd_slot_bank_decode_archival failed" ));
      return 1;
    }

    FD_LOG_NOTICE(( "decoded slot_bank" ));

    fd_bincode_encode_ctx_t ctx4;
    uchar * buf4 = malloc((size_t)statbuf.st_size);
    ctx4.data = buf4;
    ctx4.dataend = buf4 + statbuf.st_size;
    if( fd_slot_bank_encode(&slot_bank2, &ctx4 )!=FD_BINCODE_SUCCESS) {
      FD_LOG_ERR(( "fd_slot_bank_encode failed" ));
      return 1;
    }

    ulong final_sz = (ulong)((uchar*)ctx4.data - buf4);
    FD_LOG_NOTICE(( "encoded slot_bank into %lu bytes", final_sz ));

    if( final_sz != (ulong)statbuf.st_size ||
        memcmp(buf, buf4, final_sz) != 0 ) {
      FD_LOG_ERR(( "data mismatch" ));
      return 1;
    }

    fd_bincode_destroy_ctx_t ctx5;
    ctx5.valloc  = fd_libc_alloc_virtual();
    fd_slot_bank_destroy(&slot_bank, &ctx5);
    fd_slot_bank_destroy(&slot_bank2, &ctx5);
    free(buf);
    free(buf2);
    free(buf4);
  }

  {
    struct stat statbuf;
    if( stat(EPOCH_BANK_BIN, &statbuf) ) {
      if( errno == ENOENT )
        FD_LOG_ERR(( SLOT_BANK_BIN " is missing try running 'gsutil cp gs://firedancer-ci-resources/epoch_bank.bin dump/'" ));
      else
        FD_LOG_ERR(( SLOT_BANK_BIN ": %s", strerror(errno) ));
      return 1;
    }
    FILE* fd = fopen(EPOCH_BANK_BIN, "r");
    if( fd == NULL ) {
      FD_LOG_ERR(( EPOCH_BANK_BIN ": %s", strerror(errno) ));
      return 1;
    }
    uchar * buf = malloc((size_t)statbuf.st_size);
    if( fread(buf, 1, (size_t)statbuf.st_size, fd) != (size_t)statbuf.st_size ) {
      FD_LOG_ERR(( EPOCH_BANK_BIN ": %s", strerror(errno) ));
      return 1;
    }
    fclose(fd);

    FD_LOG_NOTICE(( "read %lu bytes from " EPOCH_BANK_BIN, (ulong)statbuf.st_size ));

    fd_epoch_bank_t epoch_bank;

    fd_bincode_decode_ctx_t ctx;
    ctx.data = buf;
    ctx.dataend = buf + statbuf.st_size;
    ctx.valloc  = fd_libc_alloc_virtual();
    if( fd_epoch_bank_decode(&epoch_bank, &ctx )!=FD_BINCODE_SUCCESS ||
        ctx.data != ctx.dataend ) {
      FD_LOG_ERR(( "fd_epoch_bank_decode failed" ));
      return 1;
    }

    FD_LOG_NOTICE(( "decoded epoch_bank" ));

    fd_bincode_encode_ctx_t ctx2;
    uchar * buf2 = malloc((size_t)statbuf.st_size * 2);
    ctx2.data = buf2;
    ctx2.dataend = buf2 + statbuf.st_size*2;
    if( fd_epoch_bank_encode_archival(&epoch_bank, &ctx2 )!=FD_BINCODE_SUCCESS) {
      FD_LOG_ERR(( "fd_epoch_bank_encode_archival failed" ));
      return 1;
    }

    ulong arch_sz = (ulong)((uchar*)ctx2.data - buf2);
    FD_LOG_NOTICE(( "encoded epoch_bank into %lu bytes", arch_sz ));

    fd_epoch_bank_t epoch_bank2;

    fd_bincode_decode_ctx_t ctx3;
    ctx3.data = buf2;
    ctx3.dataend = buf2 + arch_sz;
    ctx3.valloc  = fd_libc_alloc_virtual();
    if( fd_epoch_bank_decode_archival(&epoch_bank2, &ctx3 )!=FD_BINCODE_SUCCESS ||
        ctx3.data != ctx3.dataend ) {
      FD_LOG_ERR(( "fd_epoch_bank_decode_archival failed" ));
      return 1;
    }

    FD_LOG_NOTICE(( "decoded epoch_bank" ));

    fd_bincode_encode_ctx_t ctx4;
    uchar * buf4 = malloc((size_t)statbuf.st_size);
    ctx4.data = buf4;
    ctx4.dataend = buf4 + statbuf.st_size;
    if( fd_epoch_bank_encode(&epoch_bank2, &ctx4 )!=FD_BINCODE_SUCCESS) {
      FD_LOG_ERR(( "fd_epoch_bank_encode failed" ));
      return 1;
    }

    ulong final_sz = (ulong)((uchar*)ctx4.data - buf4);
    FD_LOG_NOTICE(( "encoded epoch_bank into %lu bytes", final_sz ));

    if( final_sz != (ulong)statbuf.st_size ||
        memcmp(buf, buf4, final_sz) != 0 ) {
      FD_LOG_ERR(( "data mismatch" ));
      return 1;
    }

    fd_bincode_destroy_ctx_t ctx5;
    ctx5.valloc  = fd_libc_alloc_virtual();
    fd_epoch_bank_destroy(&epoch_bank, &ctx5);
    fd_epoch_bank_destroy(&epoch_bank2, &ctx5);
    free(buf);
    free(buf2);
    free(buf4);
  }

  free(smem);
  free(fmem);

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
