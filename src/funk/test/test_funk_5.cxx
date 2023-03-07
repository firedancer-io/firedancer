#include <stdlib.h>
#include "../../util/fd_util.h"
extern "C" {
#include "../fd_funk.h"
}
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>
#include <string_view>
#include <unordered_map>
#include <vector>

// A simple, fast, but not super great random number generator
class randgen {
  private:
    ulong _s1 = 0;
    ulong _s2 = 0;
    ulong _s3 = 0;

    void mix() {
      _s1 = (_s1+135075924757140979UL)*625099173779010167UL;
      _s2 = (_s2+578819778140026727UL)*115476946196358727UL;
      _s3 = (_s3+237010196533530919UL)*274199408033833319UL;
      _s1 ^= _s2>>31U;
      _s2 ^= _s3>>31U;
      _s3 ^= _s1>>31U;
    }
    
  public:
    randgen() {
      gettimeofday((struct timeval*)&_s1, NULL);
    }
    ~randgen() { }

    void genbytes(char* data, unsigned len) {
      mix();
      while (len >= sizeof(ulong)) {
        memcpy(data, &_s1, sizeof(ulong));
        data += sizeof(ulong);
        len -= (unsigned)sizeof(ulong);
        mix();
      }
      memcpy(data, &_s1, len);
    }

    ulong genulong() {
      mix();
      return _s1;
    }
};

struct recordkey {
    fd_funk_recordid _id;
    recordkey() { }
    recordkey(const fd_funk_recordid* x) { memcpy(&_id, x, sizeof(_id)); }
    recordkey(const recordkey& x) { memcpy(&_id, &x._id, sizeof(_id)); }
    recordkey(recordkey&& x) { memcpy(&_id, &x._id, sizeof(_id)); }
    bool operator== (const recordkey& x) const {
      return memcmp(&_id, &x._id, sizeof(_id)) == 0;
    }
    recordkey& operator= (const recordkey& x) { memcpy(&_id, &x._id, sizeof(_id)); return *this; }
    recordkey& operator= (recordkey&& x) { memcpy(&_id, &x._id, sizeof(_id)); return *this; }
    operator const fd_funk_recordid* () const { return &_id; }
};

struct xactionkey {
    fd_funk_xactionid _id;
    xactionkey() { }
    xactionkey(const xactionkey& x) { memcpy(&_id, &x._id, sizeof(_id)); }
    xactionkey(xactionkey&& x) { memcpy(&_id, &x._id, sizeof(_id)); }
    xactionkey(const fd_funk_xactionid* id) { memcpy(&_id, id, sizeof(_id)); }
    bool operator== (const xactionkey& x) const {
      return memcmp(&_id, &x._id, sizeof(_id)) == 0;
    }
    operator const fd_funk_xactionid* () const { return &_id; }
    xactionkey& operator= (const xactionkey& x) { memcpy(&_id, &x._id, sizeof(_id)); return *this; }
};

class databuf {
  private:
    std::vector<ulong> _buf;

    void updatechecksum(const ulong* data, ulong datalen) {
      auto oldsize = _buf.size();
      if (datalen > oldsize) {
        _buf.resize(datalen);
        auto* bd = _buf.data();
        for (ulong i = oldsize; i < datalen; ++i)
          bd[i] = 0;
      }
      auto* bd = _buf.data();
      for (ulong i = 0; i < datalen; ++i)
        bd[i] ^= data[i];
    }

  public:
    databuf() { }
    databuf(databuf&& x) : _buf(std::move(x._buf)) { }
    ~databuf() { }
    
    databuf& operator= (databuf&& x) { _buf = std::move(x._buf); return *this; }

    void write(const void* data, ulong datalen, databuf& checksum) {
      assert((datalen&(sizeof(ulong)-1)) == 0);
      datalen /= sizeof(ulong);
      auto oldsize = _buf.size();
      checksum.updatechecksum(_buf.data(), fd_ulong_min(datalen, oldsize));
      if (datalen > oldsize)
        _buf.resize(datalen);
      auto* bd = _buf.data();
      for (ulong i = 0; i < datalen; ++i)
        bd[i] = ((const ulong*)data)[i];
      checksum.updatechecksum(bd, datalen);
    }

    void write(const void* data, ulong datalen) {
      assert((datalen&(sizeof(ulong)-1)) == 0);
      datalen /= sizeof(ulong);
      auto oldsize = _buf.size();
      if (datalen > oldsize)
        _buf.resize(datalen);
      auto* bd = _buf.data();
      for (ulong i = 0; i < datalen; ++i)
        bd[i] = ((const ulong*)data)[i];
    }

    void writezeros(ulong datalen) {
      assert((datalen&(sizeof(ulong)-1)) == 0);
      datalen /= sizeof(ulong);
      auto oldsize = _buf.size();
      if (datalen > oldsize)
        _buf.resize(datalen);
      auto* bd = _buf.data();
      for (ulong i = 0; i < datalen; ++i)
        bd[i] = 0;
    }

    void checksum(databuf& checksum) {
      checksum.updatechecksum(_buf.data(), _buf.size());
    }

    const char* data() const { return (const char*)_buf.data(); }
    size_t size() const { return _buf.size()*sizeof(ulong); }

    bool equals(const void* data, ulong datalen) const {
      return (datalen == _buf.size()*sizeof(ulong) &&
              memcmp(_buf.data(), data, datalen) == 0);
    }

    bool operator== (const databuf& x) const {
      return (_buf.size() == x._buf.size() &&
              memcmp(_buf.data(), x._buf.data(), _buf.size()*sizeof(ulong)) == 0);
    }
};

static const char* BACKFILE = "/tmp/funktest";

void grinder(int argc, char** argv, bool firsttime) {
  fd_boot( &argc, &argv );

  if (firsttime)
    unlink(BACKFILE);
  
  fd_wksp_t* wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, 1UL, fd_log_cpu_id(), "wksp", 0UL );

  ulong index_max = 1000;    // Maximum size (count) of master index
  ulong xactions_max = 100;  // Maximum size (count) of transaction index
  ulong cache_max = 100;     // Maximum number of cache entries
  auto* funk = fd_funk_new(BACKFILE, wksp, 1, index_max, xactions_max, cache_max);

  fd_funk_validate(funk);

  xactionkey rootxid(fd_funk_root(funk));

  databuf checksum;
  static const ulong MAXLEN = 8000;
  checksum.writezeros(MAXLEN);
  recordkey checksumkey;
  memset(&checksumkey._id, 'x', sizeof(checksumkey));
  if (firsttime)
    fd_funk_write(funk, rootxid, checksumkey, checksum.data(), 0, checksum.size());

  std::vector<std::pair<recordkey,databuf>> golden;

  // Load existing data
  {
    struct fd_funk_index_iter* iter = (struct fd_funk_index_iter*)
      fd_alloca(fd_funk_iter_align, fd_funk_iter_footprint);
    fd_funk_iter_init(funk, iter);
    struct fd_funk_recordid const* id;
    while ((id = fd_funk_iter_next(funk, iter)) != NULL) {
      const void* data;
      long len = fd_funk_read(funk, rootxid, id, &data, 0, INT32_MAX);
      if (len == -1)
        FD_LOG_ERR(("read failed"));
      recordkey key(id);
      if (key == checksumkey)
        checksum.write(data, len);
      else {
        golden.push_back({});
        auto& p = golden.back();
        p.first = key;
        p.second.write(data, len, checksum);
      }
    }
    FD_LOG_WARNING(("recovered %lu records", golden.size()));
  }

  auto validateall = [&](){
    fd_funk_validate(funk);
    if (fd_funk_num_xactions(funk) != 0)
      FD_LOG_ERR(("wrong transaction count"));
    if (fd_funk_num_records(funk) != golden.size()+1)
      FD_LOG_ERR(("wrong record count"));
    databuf checksum2;
    checksum2.writezeros(MAXLEN);
    for (auto& [key,db] : golden) {
      const void* res;
      auto reslen = fd_funk_read(funk, rootxid, key, &res, 0, INT32_MAX);
      if (!db.equals(res, reslen))
        FD_LOG_ERR(("read returned wrong result"));
      checksum2.checksum(db);
    }
    {
      const void* res;
      auto reslen = fd_funk_read(funk, rootxid, checksumkey, &res, 0, INT32_MAX);
      if (!checksum.equals(res, reslen))
        FD_LOG_ERR(("read returned wrong result"));
    }
    if (!(checksum == checksum2))
      FD_LOG_ERR(("checksum is wrong"));
  };
  validateall();

  char* scratch = (char*)malloc(FD_FUNK_MAX_ENTRY_SIZE);

  randgen rg;
  ulong xcnt = 0;
  for (;;) {
    xactionkey xid;
    rg.genbytes((char*)&xid, sizeof(xid));
    fd_funk_fork(funk, rootxid, xid);

    auto insert_new = [&](ulong action) {
      // Insert a new record
      recordkey key;
      rg.genbytes((char*)&key, sizeof(key));
      auto len = (uint)((action<<3)%MAXLEN);
      rg.genbytes(scratch, len);
      fd_funk_write(funk, xid, key, scratch, 0, len);
      golden.push_back({});
      auto& p = golden.back();
      p.first = key;
      p.second.write(scratch, len, checksum);
    };

    auto delete_random = [&](ulong action) {
      // Delete a random key
      auto it = golden.begin() + (action%golden.size());
      fd_funk_delete_record(funk, xid, it->first);
      checksum.checksum(it->second);
      golden.erase(it);
    };

    auto update_random = [&](ulong action) {
      // Update an existing record
      auto it = golden.begin() + (action%golden.size());
      auto len = (uint)((action<<3)%MAXLEN);
      rg.genbytes(scratch, len);
      fd_funk_write(funk, xid, it->first, scratch, 0, len);
      it->second.write(scratch, len, checksum);
    };

    for (ulong i = 0; i < 10; ++i) {
      auto action = rg.genulong();
      if (golden.size() < 10) {
        insert_new(action);
      } else if (golden.size() > 100) {
        delete_random(action);
      } else {
        switch (action % 4) {
        case 0: insert_new(action); break;
        case 1: delete_random(action); break;
        default: update_random(action); break;
        }
      }
    }

    fd_funk_write(funk, xid, checksumkey, checksum.data(), 0, checksum.size());
    fd_funk_commit(funk, xid);

    ++xcnt;
    if (!(xcnt%2000)) FD_LOG_WARNING(("%lu transactions", xcnt));
  }

  free(scratch);
  
  fd_funk_delete(funk);
  fd_wksp_detach(wksp);
  unlink("testback");

  fd_log_flush();
}

int main(int argc, char** argv) {
  if (argc == 2) {
    // Child process
    if (strcmp(argv[1], "-1") == 0)
      grinder(argc, argv, true);
    else if (strcmp(argv[1], "-2") == 0)
      grinder(argc, argv, false);
    return 0;
  }

  if (argc == 1) {
    // Parent process
    unlink(BACKFILE);
    bool firsttime = true;
    for (unsigned cnt = 0;;) {
      pid_t p;
      if ((p = fork()) == 0) {
        static const char* EXE = "build/test/bin/test_funk_5";
        int r = execlp(EXE, EXE, (firsttime ? "-1" : "-2"), NULL);
        if (r == -1)
          fprintf(stderr, "failed to exec %s: %s\n", EXE, strerror(errno));
        return 1;
      }
      firsttime = false;

      sleep(3);

      printf("%u kills\n", ++cnt);
      kill(p, SIGKILL);
      int wstatus;
      waitpid(p, &wstatus, 0);
    }
  }

  return 0;
}
