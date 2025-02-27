extern "C" {
  #include "fd_funkier.h"
}
#include <map>
#include <vector>
#include <set>
#include <algorithm>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>

static const long ROOT_KEY = 0;
static const ulong MAX_TXNS = 100;
static const ulong MAX_CHILDREN = 100;
static const uint MAX_PARTS = 8;

struct fake_rec {
    ulong _key;
    std::vector<long> _data;
    bool _erased = false;
    bool _touched = false;
    static std::set<fake_rec*> _all;

    fake_rec() = delete;
    fake_rec(ulong key) : _key(key) {
      assert(_all.count(this) == 0);
      _all.insert(this);
    }
    ~fake_rec() {
      assert(_all.count(this) == 1);
      _all.erase(this);
    }

    static fake_rec * make_random() {
      auto * rec = new fake_rec(((ulong)lrand48())%MAX_CHILDREN);
      auto len = ((ulong)lrand48())%8UL;
      rec->_data.resize(len);
      for (ulong i = 0; i < len; ++i)
        rec->_data[i] = lrand48();
      return rec;
    }

    fd_funkier_rec_key_t real_id() const {
      fd_funkier_rec_key_t i;
      memset(&i, 0, sizeof(i));
      i.ul[0] = _key;
      return i;
    }

    ulong size() const {
      return _data.size()*sizeof(long);
    }

    const uchar* data() const {
      return (const uchar*)_data.data();
    }
};

std::set<fake_rec*> fake_rec::_all;

struct fake_txn {
    ulong _key;
    std::vector<fake_rec*> _recs;
    std::map<ulong,fake_txn*> _children;
    fake_txn * _parent = NULL;
    bool _touched = false;

    fake_txn(ulong key) : _key(key) { }
    ~fake_txn() {
      for (auto i : _recs) {
        delete i;
      }
    }

    fd_funkier_txn_xid_t real_id() const {
      fd_funkier_txn_xid_t i;
      memset(&i, 0, sizeof(i));
      i.ul[0] = _key;
      return i;
    }

    bool insert(fake_rec* rec) {
      for (auto i : _recs)
        if( i->_key == rec->_key ) {
          delete rec;
          return false; /* Error */
        }
      auto sz = _recs.size();
      _recs.resize(sz+1);
      _recs[sz] = rec;
      return true;
    }
};

struct fake_funk {
    fd_wksp_t * _wksp;
    fd_funkier_t * _real;
    std::map<ulong,fake_txn*> _txns;
    ulong _lastxid = 0;
#ifdef TEST_FUNKIER_FILE
    fd_funkier_close_file_args_t close_args;
#endif

    fake_funk(int * argc, char *** argv) {
      fd_boot( argc, argv );
      ulong txn_max = 128;
      ulong rec_max = 1<<16;

#ifdef TEST_FUNKIER_FILE
      _real = fd_funkier_open_file( "funk_test_file", 1, 1234U, txn_max, rec_max, FD_SHMEM_GIGANTIC_PAGE_SZ, FD_FUNKIER_OVERWRITE, &close_args );
      _wksp = fd_funkier_wksp( _real );

#else
      ulong  numa_idx = fd_shmem_numa_idx( 0 );
      _wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, 1U, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
      void * mem = fd_wksp_alloc_laddr( _wksp, fd_funkier_align(), fd_funkier_footprint( txn_max, rec_max ), FD_FUNKIER_MAGIC );
      _real = fd_funkier_join( fd_funkier_new( mem, 1, 1234U, txn_max, rec_max ) );
#endif

      _txns[ROOT_KEY] = new fake_txn(ROOT_KEY);
    }
    ~fake_funk() {
      for (auto i : _txns)
        delete i.second;
#ifdef TEST_FUNKIER_FILE
      fd_funkier_close_file( &close_args );
      unlink( "funk_test_file" );
#endif
      for( auto i : fake_rec::_all )
        FD_LOG_NOTICE(( "leaked record 0x%lx!", (ulong)i ));

    }

#ifdef TEST_FUNKIER_FILE
    void reopen_file() {
      fd_funkier_close_file( &close_args );
      _real = fd_funkier_open_file( "funk_test_file", 1, 0, 0, 0, 0, FD_FUNKIER_READ_WRITE, &close_args );
      _wksp = fd_funkier_wksp( _real );
    }
#endif

    fake_txn * pick_unfrozen_txn() {
      fake_txn* list[MAX_TXNS];
      uint listlen = 0;
      for (auto i : _txns)
        if (i.second->_children.size() == 0)
          list[listlen++] = i.second;
      return list[((uint)lrand48())%listlen];
    }

    fd_funkier_txn_t * get_real_txn(fake_txn * txn) {
      if (txn->_key == ROOT_KEY)
        return NULL;
      fd_funkier_txn_map_t txn_map = fd_funkier_txn_map( _real, _wksp );
      auto xid = txn->real_id();
      return fd_funkier_txn_query(&xid, &txn_map);
    }

    void random_insert() {
      fake_txn * txn = pick_unfrozen_txn();
      if( txn->_recs.size() == MAX_CHILDREN ) return;
      fake_rec * rec = NULL;
      do {
        rec = fake_rec::make_random();
        /* Prevent duplicate keys */
      } while (!txn->insert(rec));

      fd_funkier_txn_t * txn2 = get_real_txn(txn);
      auto key = rec->real_id();
      fd_funkier_rec_prepare_t prepare[1];
      fd_funkier_rec_t * rec2 = fd_funkier_rec_prepare(_real, txn2, &key, prepare, NULL);
      void * val = fd_funkier_val_truncate(rec2, rec->size(), fd_funkier_alloc(_real, _wksp), _wksp, NULL);
      memcpy(val, rec->data(), rec->size());
      fd_funkier_rec_publish( prepare );
      assert(fd_funkier_val_sz(rec2) == rec->size());
    }

    void random_remove() {
      fake_txn * txn = pick_unfrozen_txn();
      auto& recs = txn->_recs;
      fake_rec* list[MAX_CHILDREN];
      uint listlen = 0;
      for (auto i : recs)
        if (!i->_erased)
          list[listlen++] = i;
      if (!listlen) return;
      auto* rec = list[((uint)lrand48())%listlen];

      fd_funkier_txn_t * txn2 = get_real_txn(txn);
      auto key = rec->real_id();
      assert(fd_funkier_rec_remove(_real, txn2, &key, NULL, 0UL) == FD_FUNKIER_SUCCESS);

      rec->_erased = true;
      rec->_data.clear();
    }

    void random_new_txn() {
      if (_txns.size() == MAX_TXNS)
        return;

      fake_txn* list[MAX_TXNS];
      uint listlen = 0;
      for (auto i : _txns)
        list[listlen++] = i.second;
      auto * parent = list[((uint)lrand48())%listlen];

      ulong key = ++_lastxid;
      auto * txn = _txns[key] = new fake_txn(key);

      txn->_parent = parent;
      parent->_children[key] = txn;

      fd_funkier_txn_t * parent2 = get_real_txn(parent);
      auto xid = txn->real_id();
      assert(fd_funkier_txn_prepare(_real, parent2, &xid, 1) != NULL);
    }

    void fake_cancel_family(fake_txn* txn) {
      assert(txn->_key != ROOT_KEY);
      while (!txn->_children.empty())
        fake_cancel_family(txn->_children.begin()->second);
      txn->_parent->_children.erase(txn->_key);
      _txns.erase(txn->_key);
      delete txn;
    }

    void fake_publish_to_parent(fake_txn* txn) {
      // Move records into parent
      auto* parent = txn->_parent;
      for (auto i : txn->_recs) {
        uint p = 0;
        for (auto j : parent->_recs) {
          if( i->_key == j->_key ) {
            delete j;
            parent->_recs.erase(parent->_recs.begin()+p);
            break;
          }
          p++;
        }
        parent->insert(i);
      }
      txn->_recs.clear();

      // Cancel siblings
      for (;;) {
        bool repeat = false;
        for (auto i : parent->_children)
          if (txn != i.second) {
            fake_cancel_family(i.second);
            repeat = true;
            break;
          }
        if (!repeat) break;
      }
      assert(parent->_children.size() == 1 && parent->_children[txn->_key] == txn);

      // Move children up
      parent->_children.clear();
      for (auto i : txn->_children) {
        auto* child = i.second;
        child->_parent = parent;
        parent->_children[child->_key] = child;
      }

      _txns.erase(txn->_key);
      delete txn;
    }

    void fake_publish(fake_txn* txn) {
      assert(txn->_key != ROOT_KEY);
      if (txn->_parent->_key != ROOT_KEY)
        fake_publish(txn->_parent);
      assert(txn->_parent->_key == ROOT_KEY);
      fake_publish_to_parent(txn);
    }

    void random_publish() {
      fake_txn* list[MAX_TXNS];
      uint listlen = 0;
      for (auto i : _txns)
        if (i.second->_key != ROOT_KEY)
          list[listlen++] = i.second;
      if (!listlen) return;
      auto * txn = list[((uint)lrand48())%listlen];

      fd_funkier_txn_t * txn2 = get_real_txn(txn);
      assert(fd_funkier_txn_publish(_real, txn2, 1) > 0);

      // Simulate publication
      fake_publish(txn);
    }

    void random_publish_into_parent() {
      fake_txn* list[MAX_TXNS];
      uint listlen = 0;
      for (auto i : _txns)
        if (i.second->_key != ROOT_KEY)
          list[listlen++] = i.second;
      if (!listlen) {
        return;
      }
      auto * txn = list[((uint)lrand48())%listlen];

      fd_funkier_txn_t * txn2 = get_real_txn(txn);
      assert(fd_funkier_txn_publish_into_parent(_real, txn2, 1) == FD_FUNKIER_SUCCESS);

      // Simulate publication
      fake_publish_to_parent(txn);
    }

    void random_cancel() {
      fake_txn* list[MAX_TXNS];
      uint listlen = 0;
      for (auto i : _txns)
        if (i.second->_key != ROOT_KEY)
          list[listlen++] = i.second;
      if (!listlen) return;
      auto * txn = list[((uint)lrand48())%listlen];

      fd_funkier_txn_t * txn2 = get_real_txn(txn);
      assert(fd_funkier_txn_cancel(_real, txn2, 1) > 0);

      // Simulate cancel
      fake_cancel_family(txn);
    }

    void verify() {
#ifdef FD_FUNKIER_HANDHOLDING
      assert(fd_funkier_verify(_real) == FD_FUNKIER_SUCCESS);
#endif

      for (auto i : _txns) {
        assert(i.first == i.second->_key);
        for (auto j : i.second->_recs) {
          j->_touched = false;
        }
      }

      fd_funkier_all_iter_t iter[1];
      for( fd_funkier_all_iter_new( _real, iter ); !fd_funkier_all_iter_done( iter ); fd_funkier_all_iter_next( iter ) ) {
        fd_funkier_rec_t const * rec = fd_funkier_all_iter_ele_const( iter );
        auto const * xid = fd_funkier_rec_xid( rec );
        auto i = _txns.find(xid->ul[0]);
        assert(i != _txns.end());
        auto const * key = fd_funkier_rec_key( rec );
        auto& recs = i->second->_recs;
        auto j = std::find_if(recs.begin(), recs.end(), [key](auto * rec2) {return rec2->_key == key->ul[0];});
        assert(j != recs.end());
        auto * rec2 = *j;
        if (rec2->_erased) {
          assert(rec->flags & FD_FUNKIER_REC_FLAG_ERASE);
          assert(fd_funkier_val_sz(rec) == 0);
        } else {
          assert(!(rec->flags & FD_FUNKIER_REC_FLAG_ERASE));
          assert(fd_funkier_val_sz(rec) == rec2->size());
          assert(memcmp(fd_funkier_val(rec, _wksp), rec2->data(), rec2->size()) == 0);
        }

        fd_funkier_txn_map_t txn_map = fd_funkier_txn_map( _real, fd_funkier_wksp( _real ) );
        fd_funkier_txn_t * txn = fd_funkier_txn_query( xid, &txn_map );
        fd_funkier_rec_query_t query[1];
        auto* rec3 = fd_funkier_rec_query_try_global(_real, txn, rec->pair.key, NULL, query);
        if( ( rec->flags & FD_FUNKIER_REC_FLAG_ERASE ) )
          assert(rec3 == NULL);
        else
          assert(rec == rec3);
        assert(!fd_funkier_rec_query_test( query ));

        assert(!rec2->_touched);
        rec2->_touched = true;
      }

      for (auto i : _txns) {
        for (auto j : i.second->_recs) {
          assert(j->_touched || j->_erased);
        }
      }

      for (auto i : _txns) {
        auto * txn = i.second;
        assert(i.first == txn->_key);
        if (txn->_key == ROOT_KEY) {
          assert(txn->_parent == NULL);
        } else {
          assert(txn->_parent->_children.find(txn->_key)->second == txn);
        }
        txn->_touched = false;
      }

      {
        // Root transaction
        auto * txn2 = _txns[ROOT_KEY];
        assert(!txn2->_touched);
        txn2->_touched = true;

        auto& recs = txn2->_recs;
        for( auto const * rec = fd_funkier_txn_first_rec(_real, NULL);
             rec;
             rec = fd_funkier_txn_next_rec(_real, rec) ) {
          auto const * key = fd_funkier_rec_key( rec );
          auto j = std::find_if(recs.begin(), recs.end(), [key](auto * rec2) {return rec2->_key == key->ul[0];});
          assert(j != recs.end());
        }
      }

      fd_funkier_txn_pool_t txn_pool = fd_funkier_txn_pool( _real, _wksp );

      fd_funkier_txn_all_iter_t txn_iter[1];
      for( fd_funkier_txn_all_iter_new( _real, txn_iter ); !fd_funkier_txn_all_iter_done( txn_iter ); fd_funkier_txn_all_iter_next( txn_iter ) ) {
        fd_funkier_txn_t const * txn = fd_funkier_txn_all_iter_ele_const( txn_iter );

        auto i = _txns.find(txn->xid.ul[0]);
        assert(i != _txns.end());
        auto * txn2 = i->second;
        assert(!txn2->_touched);
        txn2->_touched = true;

        auto * parent = fd_funkier_txn_parent(txn, &txn_pool);
        if (parent == NULL)
          assert(ROOT_KEY == txn2->_parent->_key);
        else
          assert(parent->xid.ul[0] == txn2->_parent->_key);

        auto& recs = txn2->_recs;
        for( auto const * rec = fd_funkier_txn_first_rec(_real, txn);
             rec;
             rec = fd_funkier_txn_next_rec(_real, rec) ) {
          auto const * key = fd_funkier_rec_key( rec );
          auto j = std::find_if(recs.begin(), recs.end(), [key](auto * rec2) {return rec2->_key == key->ul[0];});
          assert(j != recs.end());
        }
      }

      for (auto i : _txns) {
        assert(i.second->_touched);
      }
    }
};
