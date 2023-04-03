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

static void usage(const char* progname) {
  fprintf(stderr, "USAGE: %s\n", progname);
  fprintf(stderr, " --cmd unpack --snapshotfile <file>               unpack snapshot file\n");
  fprintf(stderr, " --cmd upload --ledger <dir> --funk_db <db>       \n");
}

struct SnapshotParser {
  struct TarReadStream tarreader_;
  char* tmpstart_;
  char* tmpcur_;
  char* tmpend_;
};

void SnapshotParser_init(struct SnapshotParser* self) {
  TarReadStream_init(&self->tarreader_);
  size_t tmpsize = 1<<30;
  self->tmpstart_ = self->tmpcur_ = (char*)malloc(tmpsize);
  self->tmpend_ = self->tmpstart_ + tmpsize;
}

void SnapshotParser_destroy(struct SnapshotParser* self) {
  TarReadStream_destroy(&self->tarreader_);
  free(self->tmpstart_);
}

void SnapshotParser_parsefd_solana_accounts(struct SnapshotParser* self, const void* data, size_t datalen) {
  (void)self;
  
  while (datalen) {
    size_t roundedlen;
    
#define EAT_SLICE(_target_, _len_)         \
    roundedlen = (_len_+7UL)&~7UL;         \
    if (roundedlen > datalen) return;      \
    memcpy(_target_, data, _len_);         \
    data = (const char*)data + roundedlen; \
    datalen -= roundedlen;

    struct fd_solana_account_stored_meta meta;
    EAT_SLICE(&meta, sizeof(meta));
    struct fd_solana_account_meta account_meta;
    EAT_SLICE(&account_meta, sizeof(account_meta));
    struct fd_solana_account_fd_hash hash;
    EAT_SLICE(&hash, sizeof(hash));

    // Skip data for now
    roundedlen = (meta.data_len+7UL)&~7UL;
    if (roundedlen > datalen) return;
    data = (const char*)data + roundedlen;
    datalen -= roundedlen;

#undef EAT_SLICE
  }
}

static
char* SnapshotParser_allocTemp(FD_FN_UNUSED void* arg, unsigned long align, unsigned long len) {
  char * ptr = malloc(fd_ulong_align_up(sizeof(char *) + len, align));
  char * ret = (char *) fd_ulong_align_up( (ulong) (ptr + sizeof(char *)), align );
  *((char **)(ret - sizeof(char *))) = ptr;
  return ret;
}

void SnapshotParser_parseSnapshots(struct SnapshotParser* self, const void* data, size_t datalen) {
  struct fd_deserializable_versioned_bank* bank = (struct fd_deserializable_versioned_bank*)
    SnapshotParser_allocTemp(self, FD_DESERIALIZABLE_VERSIONED_BANK_ALIGN, FD_DESERIALIZABLE_VERSIONED_BANK_FOOTPRINT);
  fd_deserializable_versioned_bank_decode(bank, &data, &datalen, SnapshotParser_allocTemp, self);

  struct fd_solana_accounts_db_fields* accounts = (struct fd_solana_accounts_db_fields*)
    SnapshotParser_allocTemp(self, FD_SOLANA_ACCOUNTS_DB_FIELDS_ALIGN, FD_SOLANA_ACCOUNTS_DB_FIELDS_FOOTPRINT);
  fd_solana_accounts_db_fields_decode(accounts, &data, &datalen, SnapshotParser_allocTemp, self);
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

void uploadLedger(FD_FN_UNUSED const char *ledger, FD_FN_UNUSED const char *db) {
  
}

int main(int argc, char** argv) {
  const char* cmd = fd_env_strip_cmdline_cstr(&argc, &argv, "--cmd", NULL, NULL);

  if (strcmp(cmd, "unpack") == 0) {
    const char* snapshotfile = fd_env_strip_cmdline_cstr(&argc, &argv, "--snapshotfile", NULL, NULL);
    if (snapshotfile == NULL) {
      usage(argv[0]);
      return 1;
    }

    struct SnapshotParser parser;
    SnapshotParser_init(&parser);
    decompressFile(snapshotfile, SnapshotParser_moreData, &parser);
    SnapshotParser_destroy(&parser);
  }

  if (strcmp(cmd, "upload") == 0) {
      const char* ledger = fd_env_strip_cmdline_cstr(&argc, &argv, "--ledger", NULL, NULL);
      const char* db = fd_env_strip_cmdline_cstr(&argc, &argv, "--funk-db", NULL, NULL);

      uploadLedger(ledger, db);
  }
  
  return 0;
}
