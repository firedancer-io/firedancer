typedef unsigned long size_t;

#define MAP_FAILED ((void *)-1)
#define MAP_FIXED  (0x10)

void * mmap(void * addr, size_t length, int prot, int flags, int fd, long offset);
void   consume(void * ptr);

void
unchecked_result(void)
{
  void * ptr = mmap(0, 4096, 0, 0, -1, 0); // $ Alert
  consume(ptr);
}

void
discarded_result(void)
{
  (void)mmap(0, 4096, 0, 0, -1, 0); // $ Alert
}

void
checked_result(void)
{
  void * ptr = mmap(0, 4096, 0, 0, -1, 0);
  if (ptr == MAP_FAILED)
    return;
  consume(ptr);
}

void
checked_result_reversed(void)
{
  void * ptr = mmap(0, 4096, 0, 0, -1, 0);
  if (MAP_FAILED != ptr)
    consume(ptr);
}

void
checked_directly(void)
{
  if (mmap(0, 4096, 0, 0, -1, 0) == MAP_FAILED)
    return;
}

void
checked_fixed_address(void * requested)
{
  if (mmap(requested, 4096, 0, MAP_FIXED, -1, 0) != requested)
    return;
}

void
unchecked_address_hint(void * requested)
{
  if (mmap(requested, 4096, 0, 0, -1, 0) != requested) // $ Alert
    return;
}

void
wrong_fixed_address_checked(void * requested, void * other)
{
  if (mmap(requested, 4096, 0, MAP_FIXED, -1, 0) != other) // $ Alert
    return;
}

struct ring {
  void * sq;
  void * cq;
};

void
checked_field(struct ring * ring)
{
  ring->sq = mmap(0, 4096, 0, 0, -1, 0);
  if (ring->sq == MAP_FAILED)
    return;
  consume(ring->sq);
}

void
wrong_field_checked(struct ring * ring)
{
  ring->sq = mmap(0, 4096, 0, 0, -1, 0); // $ Alert
  if (ring->cq == MAP_FAILED)
    return;
  consume(ring->sq);
}
