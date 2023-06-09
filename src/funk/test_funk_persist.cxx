#include "fd_funk.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <string_view>
#include <unordered_map>
#include <vector>

static ulong unique_tag = 0UL;

struct recordkey {
    fd_funk_rec_key_t id_;
    recordkey() { }
    recordkey(const recordkey& x) { memcpy(&id_, &x.id_, sizeof(id_)); }
    recordkey(recordkey&& x) { memcpy(&id_, &x.id_, sizeof(id_)); }
    bool operator== (const recordkey& x) const {
      return memcmp(&id_, &x.id_, sizeof(id_)) == 0;
    }
    void set_unique() {
      id_.ul[0] = fd_log_app_id();
      id_.ul[1] = fd_log_thread_id();
      id_.ul[2] = ++unique_tag;
# if FD_HAS_X86
      id_.ul[3] = (ulong)fd_tickcount();
# else
      id_.ul[3] = 0UL;
# endif
      id_.ul[4] = ~id_.ul[0]; id_.ul[5] = ~id_.ul[1]; id_.ul[6] = ~id_.ul[2]; id_.ul[7] = ~id_.ul[3];
    }

};

struct recordkeyhash {
    size_t operator() (const recordkey& key) const {
      std::string_view v((const char*)&key.id_, sizeof(key.id_));
      return std::hash<std::string_view>{}(v);
    }
};

struct recordvalue {
    std::vector<uchar> data_;
    fd_funk_rec_t * rec_ = NULL;

    void random_data(fd_rng_t * rng) {
      auto len = fd_rng_ulong( rng ) % 10000UL;
      data_.resize(len);
      auto* p = data_.data();
      while (len) {
        auto r = fd_rng_ulong( rng );
        if (len >= sizeof(ulong)) {
          *(ulong*)p = r;
          p += sizeof(ulong);
          len -= sizeof(ulong);
        } else {
          switch (len) {
          case 7: p[6] = ((uchar*)&r)[6]; __attribute__((fallthrough));
          case 6: p[5] = ((uchar*)&r)[5]; __attribute__((fallthrough));
          case 5: p[4] = ((uchar*)&r)[4]; __attribute__((fallthrough));
          case 4: p[3] = ((uchar*)&r)[3]; __attribute__((fallthrough));
          case 3: p[2] = ((uchar*)&r)[2]; __attribute__((fallthrough));
          case 2: p[1] = ((uchar*)&r)[1]; __attribute__((fallthrough));
          case 1: p[0] = ((uchar*)&r)[0];
          }
          break;
        }
      }
    }

    void write_data(fd_funk_t * funk, const recordkey& key) {
      int err;
      auto sz = data_.size();
      rec_ = fd_funk_rec_write_prepare(funk, NULL, &key.id_, sz, 1, &err);
      assert(rec_ != NULL);
      auto* wksp = fd_funk_wksp(funk);
      auto* rec2 = fd_funk_val_copy(rec_, data_.data(), sz, sz, fd_funk_alloc(funk, wksp), wksp, &err);
      assert(rec2 != NULL);
      assert(fd_funk_rec_persist(funk, rec_) == FD_FUNK_SUCCESS);
    }

    void erase_data(fd_funk_t * funk) {
      assert(fd_funk_rec_persist_erase(funk, rec_) == FD_FUNK_SUCCESS);
      assert(fd_funk_rec_remove(funk, rec_, 1) == FD_FUNK_SUCCESS);
      rec_ = NULL;
    }

    void verify(fd_funk_t * funk, const recordkey& key) {
      auto* rec = fd_funk_rec_query_const(funk, NULL, &key.id_);
      if (rec_ == NULL) // After rebuild
        rec_ = fd_funk_rec_modify(funk, rec);
      else
        assert(rec == rec_);
      assert(fd_funk_val_sz(rec_) == data_.size());
      assert(memcmp(fd_funk_val(rec_, fd_funk_wksp(funk)), data_.data(), data_.size()) == 0);
    }
};

struct TestHarness {
    fd_rng_t * rng_;
    fd_funk_t * funk_;
    std::unordered_map<recordkey,recordvalue,recordkeyhash> map_;

    TestHarness(fd_rng_t * rng) : rng_(rng), funk_(NULL) { }
    ~TestHarness() { }

    void random_insert() {
      recordkey key;
      key.set_unique();
      auto& val = map_[key];
      val.random_data(rng_);
      val.write_data(funk_, key);
    }

    void random_modify() {
      auto it = map_.begin();
      auto n = fd_rng_ulong_roll(rng_, map_.size());
      for (size_t i = 0; i < n; ++i)
        ++it;
      auto& val = it->second;
      val.random_data(rng_);
      val.write_data(funk_, it->first);
    }

    void random_erase() {
      auto it = map_.begin();
      auto n = fd_rng_ulong_roll(rng_, map_.size());
      for (size_t i = 0; i < n; ++i)
        ++it;
      it->second.erase_data(funk_);
      map_.erase(it);
    }

    void verify() {
      assert(fd_funk_verify(funk_) == FD_FUNK_SUCCESS);
      assert(fd_funk_rec_size(funk_, fd_funk_wksp(funk_)) == map_.size());
      for ( auto& [key,val] : map_)
        val.verify(funk_, key);
    }

    void teardown() {
      for ( auto& [_,val] : map_)
        val.rec_ = NULL;
    }
};

int main(int argc, char **argv) {
  fd_boot( &argc, &argv );

  ulong wksp_tag = 1UL;
  ulong txn_max = 10UL;
  ulong rec_max = 100000UL;
  ulong seed = 1234UL;
  const char* backfile = "testback";

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  fd_wksp_t* wksp = NULL;

  void * shmem = NULL;
  TestHarness harness(rng);
  auto buildup = [&](){
    wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, 1UL, fd_log_cpu_id(), "wksp", 0UL );
    ulong align     = fd_funk_align();
    ulong footprint = fd_funk_footprint();
    shmem = fd_wksp_alloc_laddr( wksp, align, footprint, wksp_tag );
    void * shfunk = fd_funk_new( shmem, wksp_tag, seed, txn_max, rec_max );
    harness.funk_ = fd_funk_join( shfunk );
    assert(fd_funk_persist_open( harness.funk_, backfile, 1 ) == FD_FUNK_SUCCESS);
  };
  unlink(backfile);
  buildup();
  harness.verify();

  for (int i = 0; i < 100; ++i)
    harness.random_insert();
  harness.verify();

  auto teardown = [&](){
    fd_funk_delete( fd_funk_leave( harness.funk_ ) );
    harness.funk_ = NULL;
    fd_wksp_free_laddr( shmem );
    fd_wksp_detach(wksp);
    wksp = NULL;
    harness.teardown();
  };
  teardown();
  buildup();
  harness.verify();

  for (int i = 0; i < 50; ++i)
    harness.random_erase();
  harness.verify();
  teardown();
  buildup();
  harness.verify();

  for (int i = 0; i < 10000; ++i)
    harness.random_insert();
  harness.verify();
  teardown();
  buildup();
  harness.verify();

  for (int j = 0; j < 20; ++j) {
    for (int i = 0; i < 5000; ++i)
      harness.random_erase();
    harness.verify();
    teardown();
    buildup();
    harness.verify();

    for (int i = 0; i < 1000; ++i)
      harness.random_modify();
    harness.verify();
    teardown();
    buildup();
    harness.verify();

    for (int i = 0; i < 5000; ++i)
      harness.random_insert();
    harness.verify();
    teardown();
    buildup();
    harness.verify();
  }

  teardown();

  unlink(backfile);

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(("pass"));
  fd_log_flush();
  return 0;
}
