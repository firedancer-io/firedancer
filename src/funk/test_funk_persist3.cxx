#include <stdlib.h>
#include "../util/fd_util.h"
extern "C" {
#include "fd_funk.h"
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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-aliasing"

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
      struct timeval* _s1_ptr = (struct timeval*) &_s1;
      gettimeofday(_s1_ptr, NULL);
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
    fd_funk_rec_key_t _id;
    recordkey() { }
    recordkey(const fd_funk_rec_key_t* x) { memcpy(&_id, x, sizeof(_id)); }
    recordkey(const recordkey& x) { memcpy(&_id, &x._id, sizeof(_id)); }
    recordkey(recordkey&& x) { memcpy(&_id, &x._id, sizeof(_id)); }
    bool operator== (const recordkey& x) const {
      return memcmp(&_id, &x._id, sizeof(_id)) == 0;
    }
    recordkey& operator= (const recordkey& x) { memcpy(&_id, &x._id, sizeof(_id)); return *this; }
    recordkey& operator= (recordkey&& x) { memcpy(&_id, &x._id, sizeof(_id)); return *this; }
    operator const fd_funk_rec_key_t* () const { return &_id; }
};

struct xactionkey {
    fd_funk_txn_xid_t _id;
    xactionkey() { }
    xactionkey(const xactionkey& x) { memcpy(&_id, &x._id, sizeof(_id)); }
    xactionkey(xactionkey&& x) { memcpy(&_id, &x._id, sizeof(_id)); }
    xactionkey(const fd_funk_txn_xid_t* id) { memcpy(&_id, id, sizeof(_id)); }
    bool operator== (const xactionkey& x) const {
      return memcmp(&_id, &x._id, sizeof(_id)) == 0;
    }
    operator const fd_funk_txn_xid_t* () const { return &_id; }
    xactionkey& operator= (const xactionkey& x) { memcpy(&_id, &x._id, sizeof(_id)); return *this; }
};

static void dumpdata(const char* label, const void* data, ulong datalen) {
  printf("%s: ", label);
  assert((datalen&(sizeof(ulong)-1)) == 0);
  datalen /= sizeof(ulong);
  const auto* data2 = (const ulong*)data;
  for (ulong i = 0; i < datalen; ++i)
    printf(" %016lx", data2[i]);
  printf("\n");
}

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

    void clear() {
      _buf.resize(0);
    }
    
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

    void dump(const char* label) {
      dumpdata(label, _buf.data(), _buf.size()*sizeof(ulong));
    }
};

static const char* BACKFILE = "/tmp/funktest";

volatile int stopflag = 0;
void stop(int) { stopflag = 1; }

void grinder(int argc, char** argv, bool firsttime) {
  fd_boot( &argc, &argv );

  signal(SIGINT, stop);

  if (firsttime)
    unlink(BACKFILE);
  
  ulong wksp_tag = 1UL;
  ulong txn_max = 10UL;
  ulong rec_max = 100000UL;
  ulong seed = 1234UL;

  fd_wksp_t* wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, 1UL, fd_log_cpu_id(), "wksp", 0UL );
  ulong align     = fd_funk_align();
  ulong footprint = fd_funk_footprint();
  void * shmem = fd_wksp_alloc_laddr( wksp, align, footprint, wksp_tag );
  void * shfunk = fd_funk_new( shmem, wksp_tag, seed, txn_max, rec_max );
  fd_funk_t * funk = fd_funk_join( shfunk );
  assert(fd_funk_persist_open(funk, BACKFILE) == FD_FUNK_SUCCESS);

  assert(fd_funk_verify(funk) == FD_FUNK_SUCCESS);

  auto funk_write = [&](fd_funk_txn_t* txn, recordkey& key, databuf& data) {
    auto sz = data.size();
    int err;
    auto* rec = fd_funk_rec_write_prepare(funk, txn, &key._id, sz, &err);
    assert(rec != NULL);
    auto* rec2 = fd_funk_val_copy(rec, data.data(), sz, sz, fd_funk_alloc(funk, wksp), wksp, &err);
    assert(rec2 != NULL);
    if (!txn)
      assert(fd_funk_rec_persist(funk, rec) == FD_FUNK_SUCCESS);
  };

  auto funk_remove = [&](fd_funk_txn_t* txn, recordkey& key) {
    int err;
    auto* rec = fd_funk_rec_write_prepare(funk, txn, &key._id, 0, &err);
    assert(rec != NULL);
    fd_funk_rec_remove(funk, rec, 1);
  };

  auto funk_read = [&](fd_funk_txn_t* txn, recordkey& key, databuf& data) {
    auto* rec = fd_funk_rec_query_const(funk, txn, &key._id);
    assert(rec != NULL);
    data.clear();
    data.write(fd_funk_val(rec, wksp), fd_funk_val_sz(rec));
  };

  databuf checksum;
  static const ulong MAXLEN = 8000;
  checksum.writezeros(MAXLEN);
  recordkey checksumkey;
  memset(&checksumkey._id, 'x', sizeof(checksumkey));
  if (firsttime)
    funk_write(NULL, checksumkey, checksum);

  std::vector<std::pair<recordkey,databuf>> golden;

  // Load existing data
  fd_funk_rec_t * rec_map  = fd_funk_rec_map( funk, wksp );
  for( fd_funk_rec_map_iter_t iter = fd_funk_rec_map_iter_init( rec_map );
       !fd_funk_rec_map_iter_done( rec_map, iter );
       iter = fd_funk_rec_map_iter_next( rec_map, iter ) ) {
    fd_funk_rec_t * rec = fd_funk_rec_map_iter_ele( rec_map, iter );
    
    ulong len = fd_funk_val_sz( rec );
    const void* data = fd_funk_val( rec, wksp );
    recordkey key(rec->pair.key);
    if (key == checksumkey) {
      checksum.write(data, len);
    } else {
      golden.push_back({});
      auto& p = golden.back();
      p.first = key;
      p.second.write(data, len);
    }
  }
  FD_LOG_WARNING(("recovered %lu records", golden.size()));

  auto* txn_map = fd_funk_txn_map(funk, wksp);
  auto validateall = [&](){
    assert(fd_funk_verify(funk) == FD_FUNK_SUCCESS);
    if (fd_funk_txn_map_key_cnt(txn_map) != 0)
      FD_LOG_ERR(("wrong transaction count"));
    if (fd_funk_rec_map_key_cnt(rec_map) != golden.size()+1)
      FD_LOG_ERR(("wrong record count"));
    databuf checksum2;
    checksum2.writezeros(MAXLEN);
    databuf tmpbuf;
    for (auto& [key,db] : golden) {
      funk_read(NULL, key, tmpbuf);
      if (!(db == tmpbuf))
        FD_LOG_ERR(("read returned wrong result"));
      db.checksum(checksum2);
    }
    funk_read(NULL, checksumkey, tmpbuf);
    if (!(checksum == tmpbuf) ||
        !(checksum == checksum2))
      FD_LOG_ERR(("checksum is wrong"));
  };
  validateall();

  char* scratch = (char*)malloc(MAXLEN);

  randgen rg;
  ulong xcnt = 0;
  while (!stopflag) {
    xactionkey xid;
    rg.genbytes((char*)&xid, sizeof(xid));
    auto* txn = fd_funk_txn_prepare( funk, NULL, &xid._id, 1 );

    auto insert_new = [&](ulong action) {
      // Insert a new record
      recordkey key;
      rg.genbytes((char*)&key, sizeof(key));
      auto len = (uint)((action<<3)%MAXLEN);
      rg.genbytes(scratch, len);
      golden.push_back({});
      auto& p = golden.back();
      p.first = key;
      p.second.write(scratch, len, checksum);
      funk_write(txn, p.first, p.second);
    };

    auto delete_random = [&](ulong action) {
      // Delete a random key
      auto it = golden.begin() + (long)(action%golden.size());
      funk_remove(txn, it->first);
      it->second.checksum(checksum);
      golden.erase(it);
    };

    auto update_random = [&](ulong action) {
      // Update an existing record
      auto it = golden.begin() + (long)(action%golden.size());
      auto len = (uint)((action<<3)%MAXLEN);
      rg.genbytes(scratch, len);
      it->second.write(scratch, len, checksum);
      funk_write(txn, it->first, it->second);
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

    funk_write(txn, checksumkey, checksum);
    assert(fd_funk_txn_publish( funk, txn, 1 ) == 1);

    ++xcnt;
    if (!(xcnt%2000)) {
      FD_LOG_WARNING(("%lu transactions", xcnt));
      validateall();
    }
  }

  validateall();

  free(scratch);
  
  fd_funk_delete( fd_funk_leave( funk ) );
  fd_wksp_detach(wksp);

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
        static const char* EXE = "test_funk_persist3";
        int r = execlp(argv[0], EXE, (firsttime ? "-1" : "-2"), NULL);
        if (r == -1)
          fprintf(stderr, "failed to exec %s: %s\n", EXE, strerror(errno));
        return 1;
      }
      firsttime = false;

      sleep(2);

      printf("%u kills\n", ++cnt);
      kill(p, SIGKILL);
      int wstatus;
      waitpid(p, &wstatus, 0);
    }
  }

  return 0;
}
