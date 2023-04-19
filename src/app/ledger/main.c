#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <alloca.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <zstd.h>      // presumes zstd library is installed
#include "../../util/fd_util.h"
#include "tar.h"
#include "../../ballet/runtime/fd_banks_solana.h"
#include "../../ballet/runtime/fd_hashes.h"
#include "../../funk/fd_funk.h"
#include "../../ballet/runtime/fd_types.h"
#include "../../ballet/runtime/fd_runtime.h"

static void usage(const char* progname) {
  fprintf(stderr, "USAGE: %s\n", progname);
  fprintf(stderr, " --cmd ingest --snapshotfile <file>               ingest snapshot file\n");
}

struct SnapshotParser {
  struct TarReadStream tarreader_;
  char* tmpstart_;
  char* tmpcur_;
  char* tmpend_;
    
  fd_global_ctx_t* global_;
  
  struct fd_deserializable_versioned_bank* bank_;
  struct fd_solana_accounts_db_fields* accounts_;
};

void SnapshotParser_init(struct SnapshotParser* self, fd_global_ctx_t* global) {
  TarReadStream_init(&self->tarreader_);
  size_t tmpsize = 1<<30;
  self->tmpstart_ = self->tmpcur_ = (char*)malloc(tmpsize);
  self->tmpend_ = self->tmpstart_ + tmpsize;

  self->global_ = global;
  
  self->bank_ = NULL;
  self->accounts_ = NULL;
}

void SnapshotParser_destroy(struct SnapshotParser* self) {
  TarReadStream_destroy(&self->tarreader_);
  free(self->tmpstart_);
}

void SnapshotParser_parsefd_solana_accounts(struct SnapshotParser* self, const void* data, size_t datalen) {
  (void)self;
  
  while (datalen) {
    fd_solana_account_hdr_t hdr;
    size_t roundedlen = (sizeof(hdr)+7UL)&~7UL;
    if (roundedlen > datalen)
      return;
    memcpy(&hdr, data, sizeof(hdr));
    data = (const char*)data + roundedlen;
    datalen -= roundedlen;

    // fd_account_meta_t metadata;
    // int read_result = fd_acc_mgr_get_metadata( state->global->acc_mgr, state->global->funk_txn, (fd_pubkey_t *) &hdr.meta.pubkey, &metadata );

    roundedlen = (hdr.meta.data_len+7UL)&~7UL;
    if (roundedlen > datalen)
      return;
    data = (const char*)data + roundedlen;
    datalen -= roundedlen;
  }
}

void SnapshotParser_parseSnapshots(struct SnapshotParser* self, const void* data, size_t datalen) {
  const void * dataend = (const char*)data + datalen;
  fd_global_ctx_t* global = self->global_;
    
  self->bank_ = (struct fd_deserializable_versioned_bank*)
    global->allocf(global->allocf_arg, FD_DESERIALIZABLE_VERSIONED_BANK_ALIGN, FD_DESERIALIZABLE_VERSIONED_BANK_FOOTPRINT);
  fd_deserializable_versioned_bank_decode(self->bank_, &data, dataend, global->allocf, global->allocf_arg);

  self->accounts_ = (struct fd_solana_accounts_db_fields*)
    global->allocf(global->allocf_arg, FD_SOLANA_ACCOUNTS_DB_FIELDS_ALIGN, FD_SOLANA_ACCOUNTS_DB_FIELDS_FOOTPRINT);
  fd_solana_accounts_db_fields_decode(self->accounts_, &data, dataend, global->allocf, global->allocf_arg);
}

void SnapshotParser_tarEntry(void* arg, const char* name, const void* data, size_t datalen) {
  if (datalen == 0)
    return;
  if (strncmp(name, "accounts/", sizeof("accounts/")-1) == 0)
    SnapshotParser_parsefd_solana_accounts((struct SnapshotParser*)arg, data, datalen);
  if (strncmp(name, "snapshots/", sizeof("snapshots/")-1) == 0 &&
      strcmp(name, "snapshots/status_cache") != 0)
    SnapshotParser_parseSnapshots((struct SnapshotParser*)arg, data, datalen);
}

// Return non-zero on end of tarball
int SnapshotParser_moreData(void* arg, const void* data, size_t datalen) {
  struct SnapshotParser* self = (struct SnapshotParser*)arg;
  return TarReadStream_moreData(&self->tarreader_, data, datalen, SnapshotParser_tarEntry, self);
}

typedef int (*decompressCallback)(void* arg, const void* data, size_t datalen);
static void decompressFile(const char* fname, decompressCallback cb, void* arg) {
  int const fin = open(fname, O_RDONLY);
  if (fin == -1) {
    FD_LOG_ERR(( "unable to read file %s: %s", fname, strerror(errno) ));
  }
  size_t const buffInSize = ZSTD_DStreamInSize();
  void*  buffIn = alloca(buffInSize);
  size_t const buffOutSize = ZSTD_DStreamOutSize();  /* Guarantee to successfully flush at least one complete compressed block in all circumstances. */
  void* buffOut = alloca(buffOutSize);

  ZSTD_DCtx* const dctx = ZSTD_createDCtx();
  if (dctx == NULL) {
    FD_LOG_ERR(( "ZSTD_createDCtx() failed!"));
  }

  /* This loop assumes that the input file is one or more concatenated zstd
   * streams. This example won't work if there is trailing non-zstd data at
   * the end, but streaming decompression in general handles this case.
   * ZSTD_decompressStream() returns 0 exactly when the frame is completed,
   * and doesn't consume input after the frame.
   */
  ssize_t readRet;
  size_t lastRet = 0;
  while ( (readRet = read(fin, buffIn, buffInSize)) ) {
    if (readRet == -1) {
      FD_LOG_ERR(( "unable to read file %s: %s", fname, strerror(errno) ));
    }
    ZSTD_inBuffer input = { buffIn, (unsigned)readRet, 0 };
    /* Given a valid frame, zstd won't consume the last byte of the frame
     * until it has flushed all of the decompressed data of the frame.
     * Therefore, instead of checking if the return code is 0, we can
     * decompress just check if input.pos < input.size.
     */
    while (input.pos < input.size) {
      ZSTD_outBuffer output = { buffOut, buffOutSize, 0 };
      /* The return code is zero if the frame is complete, but there may
       * be multiple frames concatenated together. Zstd will automatically
       * reset the context when a frame is complete. Still, calling
       * ZSTD_DCtx_reset() can be useful to reset the context to a clean
       * state, for instance if the last decompression call returned an
       * error.
       */
      size_t const ret = ZSTD_decompressStream(dctx, &output , &input);
      if ((*cb)(arg, buffOut, output.pos)) {
        lastRet = 0;
        break;
      }
      lastRet = ret;
    }
  }


  if (lastRet != 0) {
    /* The last return value from ZSTD_decompressStream did not end on a
     * frame, but we reached the end of the file! We assume this is an
     * error, and the input was truncated.
     */
    FD_LOG_ERR(( "EOF before end of stream: %zu", lastRet ));
  }

  ZSTD_freeDCtx(dctx);
  close(fin);
}

int main(int argc, char** argv) {
  fd_boot( &argc, &argv );

  const char* cmd = fd_env_strip_cmdline_cstr(&argc, &argv, "--cmd", NULL, NULL);
  if (cmd == NULL) {
    usage(argv[0]);
    return 1;
  }

  fd_wksp_t* wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, 15, 2, "wksp", 0UL );

  void * alloc_shmem = fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), 1 );
  void * allocf_arg = fd_alloc_join( fd_alloc_new ( alloc_shmem, 1 ), 0UL );

  void * global_raw = fd_alloc_malloc(allocf_arg, FD_GLOBAL_CTX_ALIGN, FD_GLOBAL_CTX_FOOTPRINT);
  fd_global_ctx_t * global = fd_global_ctx_join(fd_global_ctx_new(global_raw));
  global->wksp = wksp;
  global->allocf = (fd_alloc_fun_t)fd_alloc_malloc;
  global->freef = (fd_free_fun_t)fd_alloc_free;
  global->allocf_arg = allocf_arg;
  global->alloc = allocf_arg;

  void* fd_acc_mgr_raw = global->allocf(global->allocf_arg, FD_ACC_MGR_ALIGN, FD_ACC_MGR_FOOTPRINT);
  global->acc_mgr = fd_acc_mgr_join(fd_acc_mgr_new(fd_acc_mgr_raw, global, FD_ACC_MGR_FOOTPRINT));

  if (strcmp(cmd, "ingest") == 0) {
    const char* snapshotfile = fd_env_strip_cmdline_cstr(&argc, &argv, "--snapshotfile", NULL, NULL);
    if (snapshotfile == NULL) {
      usage(argv[0]);
      return 1;
    }
    const char* funkfile = fd_env_strip_cmdline_cstr(&argc, &argv, "--funkfile", NULL, "funkdb");

    unlink(funkfile);
    ulong index_max = 100000000; // Maximum size (count) of master index
    ulong xactions_max = 10;     // Maximum size (count) of transaction index
    ulong cache_max = 10000;     // Maximum number of cache entries
    fd_funk_t* funk = fd_funk_new(funkfile, wksp, 2, index_max, xactions_max, cache_max);
    global->funk = funk;

    struct SnapshotParser parser;
    SnapshotParser_init(&parser, global);
    decompressFile(snapshotfile, SnapshotParser_moreData, &parser);
    SnapshotParser_destroy(&parser);

    fd_funk_delete(funk);
  }

  fd_acc_mgr_delete( fd_acc_mgr_leave( global->acc_mgr ) );
  global->freef(global->allocf_arg, fd_acc_mgr_raw);

  fd_global_ctx_delete( fd_global_ctx_leave( global ) );
  global->freef(global->allocf_arg, global_raw);
  
  fd_alloc_delete( fd_alloc_leave( allocf_arg ) );
  fd_wksp_free_laddr( alloc_shmem );
  
  fd_wksp_delete_anonymous( wksp );

  fd_log_flush();
  fd_halt();
  return 0;
}
