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
#include "../../ballet/base58/fd_base58.h"

static void usage(const char* progname) {
  fprintf(stderr, "USAGE: %s\n", progname);
  fprintf(stderr, " --cmd ingest --snapshotfile <file>               ingest snapshot file\n");
  fprintf(stderr, " --wksp <name>                                    workspace name\n");
  fprintf(stderr, " --gaddr <address>                                join funky at the address instead of making a new one\n");
  fprintf(stderr, " --indexmax <count>                               size of funky account map\n");
  fprintf(stderr, " --txnmax <count>                                 size of funky transaction map\n");
  fprintf(stderr, " --verifyhash <base58hash>                        verify that the accounts hash matches the given one\n");
}

struct SnapshotParser {
  struct fd_tar_stream  tarreader_;
  char*                 tmpstart_;
  char*                 tmpcur_;
  char*                 tmpend_;

  fd_global_ctx_t*      global_;

  fd_solana_manifest_t* manifest_;
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
  if (self->manifest_) {
    fd_global_ctx_t* global = self->global_;
    fd_solana_manifest_destroy(self->manifest_, global->freef, global->allocf_arg);
    global->freef(global->allocf_arg, self->manifest_);
    self->manifest_ = NULL;
  }
  
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

  const char* wkspname = fd_env_strip_cmdline_cstr(&argc, &argv, "--wksp", NULL, NULL);

  if (wkspname == NULL) {
    usage(argv[0]);
    return 1;
  }
  fd_wksp_t* wksp = fd_wksp_attach(wkspname);
  if (wksp == NULL)
    FD_LOG_ERR(( "failed to attach to workspace %s", wkspname ));

  fd_funk_t* funk;
  
  const char* gaddr = fd_env_strip_cmdline_cstr(&argc, &argv, "--gaddr", NULL, NULL);
  if (gaddr == NULL) {
    ulong index_max = fd_env_strip_cmdline_ulong(&argc, &argv, "--indexmax", NULL, 350000000);
    ulong xactions_max = fd_env_strip_cmdline_ulong(&argc, &argv, "--txnmax", NULL, 100);
    
    void* shmem = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint(), 1 );
    if (shmem == NULL)
      FD_LOG_ERR(( "failed to allocate a funky" ));
    char hostname[64];
    gethostname(hostname, sizeof(hostname));
    ulong hashseed = fd_hash(0, hostname, strnlen(hostname, sizeof(hostname)));
    funk = fd_funk_join(fd_funk_new(shmem, 1, hashseed, xactions_max, index_max));
    if (funk == NULL) {
      fd_wksp_free_laddr(shmem);
      FD_LOG_ERR(( "failed to allocate a funky" ));
    }
    
    FD_LOG_NOTICE(( "funky at global address 0x%016lx", fd_wksp_gaddr_fast( wksp, shmem ) ));

  } else {
    void* shmem;
    if (gaddr[0] == '0' && gaddr[1] == 'x')
      shmem = fd_wksp_laddr_fast( wksp, (ulong)strtol(gaddr+2, NULL, 16) );
    else
      shmem = fd_wksp_laddr_fast( wksp, (ulong)strtol(gaddr, NULL, 10) );
    funk = fd_funk_join(shmem);
    if (funk == NULL)
      FD_LOG_ERR(( "failed to join a funky" ));
  }

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
  
  const char* cmd = fd_env_strip_cmdline_cstr(&argc, &argv, "--cmd", NULL, NULL);
  if (cmd == NULL) {
    // Do nothing
    
  } else if (strcmp(cmd, "ingest") == 0) {
    const char* snapshotfile = fd_env_strip_cmdline_cstr(&argc, &argv, "--snapshotfile", NULL, NULL);
    if (snapshotfile == NULL) {
      usage(argv[0]);
      return 1;
    }
    struct SnapshotParser parser;
    SnapshotParser_init(&parser, global);
    if (strcmp(snapshotfile + strlen(snapshotfile) - 4, ".zst") == 0)
      decompressZSTD(snapshotfile, SnapshotParser_moreData, &parser);
    else if (strcmp(snapshotfile + strlen(snapshotfile) - 4, ".bz2") == 0)
      decompressBZ2(snapshotfile, SnapshotParser_moreData, &parser);
    else
      FD_LOG_ERR(( "unknown snapshot compression suffix" ));
    SnapshotParser_destroy(&parser);
  }

  const char* verifyhash = fd_env_strip_cmdline_cstr(&argc, &argv, "--verifyhash", NULL, NULL);
  if (verifyhash) {
    fd_funk_rec_t * rec_map  = fd_funk_rec_map( funk, wksp );
    ulong num_iter_accounts = fd_funk_rec_map_key_cnt( rec_map );

    FD_LOG_NOTICE(( "verifying hash for %lu accounts", num_iter_accounts ));
  
    ulong zero_accounts = 0;
    ulong num_pairs = 0;
    fd_pubkey_hash_pair_t * pairs = (fd_pubkey_hash_pair_t *) malloc(num_iter_accounts*sizeof(fd_pubkey_hash_pair_t));
    for( fd_funk_rec_map_iter_t iter = fd_funk_rec_map_iter_init( rec_map );
         !fd_funk_rec_map_iter_done( rec_map, iter );
         iter = fd_funk_rec_map_iter_next( rec_map, iter ) ) {
      fd_funk_rec_t * rec = fd_funk_rec_map_iter_ele( rec_map, iter );

      if (num_pairs % 10000000 == 0) {
        FD_LOG_NOTICE(( "read %lu so far", num_pairs ));
      }

      fd_account_meta_t * metadata = (fd_account_meta_t *) fd_funk_val_const( rec, wksp );
      if ((metadata->magic != FD_ACCOUNT_META_MAGIC) || (metadata->hlen != sizeof(fd_account_meta_t))) {
        FD_LOG_ERR(("invalid magic on metadata"));
      }
    
      if ((metadata->info.lamports == 0) | ((metadata->info.executable & ~1) != 0)) {
        zero_accounts++;
        continue;
      }
    
    
      fd_memcpy(pairs[num_pairs].pubkey.key, rec->pair.key, 32);
      fd_memcpy(pairs[num_pairs].hash.hash, metadata->hash, 32);
      num_pairs++;
    }
    FD_LOG_NOTICE(("num_iter_accounts: %ld  zero_accounts: %lu", num_iter_accounts, zero_accounts));
    
    fd_hash_t accounts_hash;
    fd_hash_account_deltas(global, pairs, num_pairs, &accounts_hash);

    free(pairs);
    
    char accounts_hash_58[FD_BASE58_ENCODED_32_SZ];
    fd_base58_encode_32((uchar const *)accounts_hash.hash, NULL, accounts_hash_58);

    FD_LOG_NOTICE(("hash result %s", accounts_hash_58));
    if (strcmp(verifyhash, accounts_hash_58) == 0)
      FD_LOG_NOTICE(("hash verified!"));
    else
      FD_LOG_ERR(("hash does not match!"));
  }
  
  fd_global_ctx_delete( fd_global_ctx_leave( global ) );
  fd_funk_leave( funk );

  fd_log_flush();
  fd_halt();
  return 0;
}
