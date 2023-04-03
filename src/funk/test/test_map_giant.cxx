#include <stdlib.h>
#include <assert.h>
#include <unordered_map>
#include "../../util/fd_util.h"

#define MAP_NAME test_map
struct test_element {
    ulong key;
    ulong value;
    uint next;
};
#define MAP_ELEMENT struct test_element
#define MAP_KEY ulong
ulong ulong_hash(const ulong* key, ulong hashseed) { return (*key)*544625467UL + hashseed; }
int ulong_equal(const ulong* key1, const ulong* key2) { return *key1 == *key2; }
void ulong_copy(ulong* key1, const ulong* key2) { *key1 = *key2; }
#include "../fd_map_giant.h"
#undef MAP_NAME
#undef MAP_ELEMENT
#undef MAP_KEY

int main() {
  ulong footprint = test_map_footprint(100000);
  auto* m = test_map_new(malloc(footprint), 100000, 123);
  auto capac = m->capacity;
  auto maxkey = (capac*4)/3;
  
  std::unordered_map<ulong,ulong> golden;

  for (unsigned i = 0; i < 200000000; ++i) {
    switch (i%3) {
    case 0: { // Random insert
      auto key = ((ulong)lrand48())%maxkey;
      auto val = (ulong)lrand48();
      int exist;
      auto* elem = test_map_insert(m, &key, &exist);
      auto it = golden.find(key);
      if (it == golden.end()) {
        if (golden.size() == capac) {
          assert(elem == NULL);
        } else {
          assert(!exist);
          golden[key] = val;
          elem->value = val;
        }
      } else {
        assert(exist);
        assert(it->second == elem->value);
        it->second = val;
        elem->value = val;
      }
      break;
    }

    case 1: { // Random query
      auto key = ((ulong)lrand48())%maxkey;
      auto* elem = test_map_query(m, &key);
      auto it = golden.find(key);
      if (it == golden.end()) {
        assert(elem == NULL);
      } else {
        assert(it->second == elem->value);
      }
      break;
    }

    case 2: { // Random remove
      auto key = ((ulong)lrand48())%maxkey;
      auto* found = test_map_remove(m, &key);
      auto it = golden.find(key);
      if (it == golden.end()) {
        assert(!found);
      } else {
        assert(found);
        golden.erase(it);
      }
      break;
    }
    }

    if ((i+1)%5000000 == 0) {
      // Force fill to capacity
      for (ulong key = 0; key < maxkey; ++key) {
        auto val = (ulong)lrand48();
        int exist;
        auto* elem = test_map_insert(m, &key, &exist);
        auto it = golden.find(key);
        if (it == golden.end()) {
          if (golden.size() == capac) {
            assert(elem == NULL);
          } else {
            assert(!exist);
            golden[key] = val;
            elem->value = val;
          }
        } else {
          assert(exist);
          assert(it->second == elem->value);
          it->second = val;
          elem->value = val;
        }
      }
    }

    if ((i+1)%5000000 == 25000000) {
      // Delete all keys
      for (ulong key = 0; key < maxkey; ++key) {
        auto* found = test_map_remove(m, &key);
        auto it = golden.find(key);
        if (it == golden.end()) {
          assert(!found);
        } else {
          assert(found);
        }
      }
      golden.clear();
    }

    if ((i+1)%5000000 == 66666) {
      assert(test_map_validate(m));
    }
  }

  test_map_destroy(m);
  free(m);
  return 0;
}
