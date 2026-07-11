#define NULL ((void *)0)

struct item {
  int ready;
};

int
bad_not_equal(struct item * ptr)
{
  return (ptr != NULL) & ptr->ready; // $ Alert
}

int
bad_equal(struct item * ptr)
{
  return (ptr == NULL) | ptr->ready; // $ Alert
}

int
bad_not(struct item * ptr)
{
  return (!ptr) | ptr->ready; // $ Alert
}

int
bad_reversed(struct item * ptr)
{
  return ptr->ready & (ptr != NULL); // $ Alert
}

int
safe_and(struct item * ptr)
{
  return (ptr != NULL) && ptr->ready;
}

int
safe_or(struct item * ptr)
{
  return (ptr == NULL) || ptr->ready;
}

int
different_pointer(struct item * ptr,
                  struct item * other)
{
  return (ptr != NULL) & other->ready;
}
