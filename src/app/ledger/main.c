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
#include <bzlib.h>     // presumes bz2 library is installed
#include "../../util/fd_util.h"
#include "../../util/archive/fd_tar.h"
#include "../../ballet/runtime/fd_banks_solana.h"
#include "../../ballet/runtime/fd_hashes.h"
#include "../../funk/fd_funk.h"
#include "../../ballet/runtime/fd_types.h"
#include "../../ballet/runtime/fd_runtime.h"

static void usage(const char* progname) {
  fprintf(stderr, "USAGE: %s\n", progname);
  fprintf(stderr, " --cmd ingest --snapshotfile <file>               ingest snapshot file\n");
  fprintf(stderr, " --wksp <name>                                    workspace name\n");
  fprintf(stderr, " --indexmax <count>                               size of funky account map\n");
  fprintf(stderr, " --txnmax <count>                                 size of funky transaction map\n");
}

struct SnapshotParser {
  struct fd_tar_stream                      tarreader_;
  char*                                     tmpstart_;
  char*                                     tmpcur_;
  char*                                     tmpend_;

  fd_global_ctx_t*                          global_;

  fd_solana_manifest_t                     *manifest_;
};

void SnapshotParser_init(struct SnapshotParser* self, fd_global_ctx_t* global) {
  fd_tar_stream_init(&self->tarreader_, global->allocf, global->allocf_arg, global->freef);
  size_t tmpsize = 1<<30;
  self->tmpstart_ = self->tmpcur_ = (char*)malloc(tmpsize);
  self->tmpend_ = self->tmpstart_ + tmpsize;

  self->global_ = global;

  self->manifest_ = NULL;
}

void SnapshotParser_destroy(struct SnapshotParser* self) {
  fd_tar_stream_delete(&self->tarreader_);
  free(self->tmpstart_);
}

void SnapshotParser_parsefd_solana_accounts(struct SnapshotParser* self, const char* name, const void* data, size_t datalen) {
  ulong id, slot;
  if (sscanf(name, "accounts/%lu.%lu", &slot, &id) != 2)
    return;

  fd_slot_account_pair_t_mapnode_t key1;
  key1.elem.slot = slot;
  fd_slot_account_pair_t_mapnode_t* node1 = fd_slot_account_pair_t_map_find(
    self->manifest_->accounts_db.storages_pool, self->manifest_->accounts_db.storages_root, &key1);
  if (node1 == NULL)
    return;

  fd_serializable_account_storage_entry_t_mapnode_t key2;
  key2.elem.id = id;
  fd_serializable_account_storage_entry_t_mapnode_t* node2 = fd_serializable_account_storage_entry_t_map_find(
    node1->elem.accounts_pool, node1->elem.accounts_root, &key2);
  if (node2 == NULL)
    return;

  if (node2->elem.accounts_current_len < datalen)
    datalen = node2->elem.accounts_current_len;

  while (datalen) {
    size_t roundedlen = (sizeof(fd_solana_account_hdr_t)+7UL)&~7UL;
    if (roundedlen > datalen)
      return;
    fd_solana_account_hdr_t* hdr = (fd_solana_account_hdr_t*)data;

    do {
      fd_account_meta_t metadata;
      int               read_result = fd_acc_mgr_get_metadata( self->global_->acc_mgr, self->global_->funk_txn, (fd_pubkey_t*) &hdr->meta.pubkey, &metadata );
      if ( FD_UNLIKELY( read_result == FD_ACC_MGR_SUCCESS ) ) {
        if (metadata.slot > slot)
          break;
      }
      if (fd_acc_mgr_write_append_vec_account( self->global_->acc_mgr, self->global_->funk_txn, slot, hdr) != FD_ACC_MGR_SUCCESS)
        FD_LOG_ERR(("writing failed account"));
    } while (0);

    roundedlen = (sizeof(fd_solana_account_hdr_t)+hdr->meta.data_len+7UL)&~7UL;
    if (roundedlen > datalen)
      return;
    data = (const char*)data + roundedlen;
    datalen -= roundedlen;
  }
}

void SnapshotParser_parseSnapshots(struct SnapshotParser* self, const void* data, size_t datalen) {
  const void *     dataend = (const char*)data + datalen;
  fd_global_ctx_t* global = self->global_;

  self->manifest_ = (fd_solana_manifest_t*)
                    global->allocf(global->allocf_arg, FD_SOLANA_MANIFEST_ALIGN, FD_SOLANA_MANIFEST_FOOTPRINT);
  fd_solana_manifest_decode(self->manifest_, &data, dataend, global->allocf, global->allocf_arg);
//  FD_LOG_WARNING(( "manifest account entries", self->manifest_.accounts_db.));
}

void SnapshotParser_tarEntry(void* arg, const char* name, const void* data, size_t datalen) {
  if (datalen == 0)
    return;
  if (strncmp(name, "accounts/", sizeof("accounts/")-1) == 0)
    SnapshotParser_parsefd_solana_accounts((struct SnapshotParser*)arg, name, data, datalen);
  if (strncmp(name, "snapshots/", sizeof("snapshots/")-1) == 0 &&
      strcmp(name, "snapshots/status_cache") != 0)
    SnapshotParser_parseSnapshots((struct SnapshotParser*)arg, data, datalen);
}

// Return non-zero on end of tarball
int SnapshotParser_moreData(void* arg, const void* data, size_t datalen) {
  struct SnapshotParser* self = (struct SnapshotParser*)arg;
  return fd_tar_stream_moreData(&self->tarreader_, data, datalen, SnapshotParser_tarEntry, self);
}

typedef int (*decompressCallback)(void* arg, const void* data, size_t datalen);
static void decompressZSTD(const char* fname, decompressCallback cb, void* arg) {
  int const fin = open(fname, O_RDONLY);
  if (fin == -1) {
    FD_LOG_ERR(( "unable to read file %s: %s", fname, strerror(errno) ));
  }
  size_t const buffInSize = ZSTD_DStreamInSize();
  void*        buffIn = alloca(buffInSize);
  size_t const buffOutSize = ZSTD_DStreamOutSize();  /* Guarantee to successfully flush at least one complete compressed block in all circumstances. */
  void*        buffOut = alloca(buffOutSize);

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
      size_t const ret = ZSTD_decompressStream(dctx, &output, &input);
      if (ZSTD_isError(ret)) {
        FD_LOG_ERR(( "bz2 decompression failed: %s", ZSTD_getErrorName( ret ) ));
        goto done;
      }
      if ((*cb)(arg, buffOut, output.pos))
        goto done;
    }
  }

  done:
  ZSTD_freeDCtx(dctx);
  close(fin);
}

static void decompressBZ2(const char* fname, decompressCallback cb, void* arg) {
  int const fin = open(fname, O_RDONLY);
  if (fin == -1) {
    FD_LOG_ERR(( "unable to read file %s: %s", fname, strerror(errno) ));
  }
  
  bz_stream bStream;
  bStream.next_in = NULL;
  bStream.avail_in = 0;
  bStream.bzalloc = NULL;
  bStream.bzfree = NULL;
  bStream.opaque = NULL;
  int bReturn = BZ2_bzDecompressInit(&bStream, 0, 0);
  if (bReturn != BZ_OK)
    FD_LOG_ERR(( "Error occurred during BZIP initialization.  BZIP error code: %d", bReturn ));

  size_t const buffInMax = 128<<10;
  void*        buffIn = alloca(buffInMax);
  size_t       buffInSize = 0;
  size_t const buffOutMax = 512<<10;
  void*        buffOut = alloca(buffOutMax);

  for (;;) {
    ssize_t r = read(fin, (char*)buffIn + buffInSize, buffInMax - buffInSize);
    if (r < 0) {
      FD_LOG_ERR(( "unable to read file %s: %s", fname, strerror(errno) ));
      break;
    }
    buffInSize += (size_t)r;

    bStream.next_in = buffIn;
    bStream.avail_in = (uint)buffInSize;
    bStream.next_out = buffOut;
    bStream.avail_out = (uint)buffOutMax;

    bReturn = BZ2_bzDecompress(&bStream);
    if (bReturn != BZ_OK && bReturn != BZ_STREAM_END) {
      FD_LOG_ERR(( "Error occurred during BZIP decompression.  BZIP error code: %d", bReturn ));
      break;
    }
    if ((*cb)(arg, buffOut, buffOutMax - bStream.avail_out))
      break;
    if (bReturn == BZ_STREAM_END && r == 0)
      break;

    if (bStream.avail_in)
      memmove(buffIn, (char*)buffIn + buffInSize - bStream.avail_in, bStream.avail_in);
    buffInSize = bStream.avail_in;
  }

  BZ2_bzDecompressEnd(&bStream);
  close(fin);
}

int main(int argc, char** argv) {
  fd_boot( &argc, &argv );

  const char* cmd = fd_env_strip_cmdline_cstr(&argc, &argv, "--cmd", NULL, NULL);
  const char* wkspname = fd_env_strip_cmdline_cstr(&argc, &argv, "--wksp", NULL, NULL);
  if (cmd == NULL || wkspname == NULL) {
    usage(argv[0]);
    return 1;
  }

  fd_wksp_t* wksp = fd_wksp_attach(wkspname);
  if (wksp == NULL)
    FD_LOG_ERR(( "failed to attach to workspace %s", wkspname ));

  if (strcmp(cmd, "ingest") == 0) {
    const char* snapshotfile = fd_env_strip_cmdline_cstr(&argc, &argv, "--snapshotfile", NULL, NULL);
    if (snapshotfile == NULL) {
      usage(argv[0]);
      return 1;
    }
    ulong index_max = fd_env_strip_cmdline_ulong(&argc, &argv, "--indexmax", NULL, 350000000);
    ulong xactions_max = fd_env_strip_cmdline_ulong(&argc, &argv, "--txnmax", NULL, 100);

    void* shmem = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint(), 1 );
    if (shmem == NULL)
      FD_LOG_ERR(( "failed to allocate a funky" ));
    char hostname[64];
    gethostname(hostname, sizeof(hostname));
    ulong hashseed = fd_hash(0, hostname, strnlen(hostname, sizeof(hostname)));
    fd_funk_t* funk = fd_funk_join(fd_funk_new(shmem, 1, hashseed, xactions_max, index_max));
    if (funk == NULL) {
      fd_wksp_free_laddr(shmem);
      FD_LOG_ERR(( "failed to allocate a funky" ));
    }

    FD_LOG_WARNING(( "funky at global address 0x%016lx", fd_wksp_gaddr_fast( wksp, shmem ) ));

    char global_mem[FD_GLOBAL_CTX_FOOTPRINT] __attribute__((aligned(FD_GLOBAL_CTX_ALIGN)));
    memset(global_mem, 0, sizeof(global_mem));
    fd_global_ctx_t * global = fd_global_ctx_join( fd_global_ctx_new( global_mem ) );
  
    global->wksp = wksp;
    global->funk = funk;
    global->allocf = (fd_alloc_fun_t)fd_alloc_malloc;
    global->freef = (fd_free_fun_t)fd_alloc_free;
    global->allocf_arg = fd_wksp_laddr_fast( wksp, funk->alloc_gaddr );

    char acc_mgr_mem[FD_ACC_MGR_FOOTPRINT] __attribute__((aligned(FD_ACC_MGR_ALIGN)));
    memset(acc_mgr_mem, 0, sizeof(acc_mgr_mem));
    global->acc_mgr = fd_acc_mgr_join( fd_acc_mgr_new( acc_mgr_mem, global, FD_ACC_MGR_FOOTPRINT ) );

    struct SnapshotParser parser;
    SnapshotParser_init(&parser, global);
    if (strcmp(snapshotfile + strlen(snapshotfile) - 4, ".zst") == 0)
      decompressZSTD(snapshotfile, SnapshotParser_moreData, &parser);
    else if (strcmp(snapshotfile + strlen(snapshotfile) - 4, ".bz2") == 0)
      decompressBZ2(snapshotfile, SnapshotParser_moreData, &parser);
    else
      FD_LOG_ERR(( "unknown snapshot compression suffix" ));
    SnapshotParser_destroy(&parser);

    fd_global_ctx_delete( fd_global_ctx_leave( global ) );
  }

  fd_log_flush();
  fd_halt();
  return 0;
}
