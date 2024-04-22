#include <stdlib.h>

#define VECT_(n)       FD_EXPAND_THEN_CONCAT3(VECT_NAME,_,n)

struct VECT_NAME {
    ulong cnt;
    ulong max;
    VECT_ELEMENT* elems;
};
typedef struct VECT_NAME VECT_(t);

static inline
void VECT_(new)(struct VECT_NAME* self) {
  self->cnt = 0;
  self->max = 64;
  self->elems = (VECT_ELEMENT*)malloc(sizeof(VECT_ELEMENT)*self->max);
}

static inline
void VECT_(destroy)(struct VECT_NAME* self) {
  free(self->elems);
}

static inline
void VECT_(push)(struct VECT_NAME* self, VECT_ELEMENT elem) {
  if (self->cnt == self->max) {
    self->max <<= 1;
    self->elems = (VECT_ELEMENT*)realloc(self->elems, sizeof(VECT_ELEMENT)*self->max);
  }
  self->elems[self->cnt ++] = elem;
}

static inline
void VECT_(push_front)(struct VECT_NAME* self, VECT_ELEMENT elem) {
  if (self->cnt == self->max) {
    self->max <<= 1;
    self->elems = (VECT_ELEMENT*)realloc(self->elems, sizeof(VECT_ELEMENT)*self->max);
  }
  memmove(&self->elems[1], &self->elems[0], sizeof(VECT_ELEMENT)*self->cnt++);
  self->elems[0] = elem;
}

static inline
int VECT_(empty)(struct VECT_NAME* self) {
  return self->cnt == 0;
}

static inline
void VECT_(clear)(struct VECT_NAME* self) {
  self->cnt = 0;
}

static inline
VECT_ELEMENT VECT_(pop_unsafe)(struct VECT_NAME* self) {
  // Not safe on purpose
  return self->elems[--(self->cnt)];
}

static inline
void VECT_(remove_at)(struct VECT_NAME* self, ulong i) {
  VECT_ELEMENT* const elems = self->elems;
  ulong cnt = --(self->cnt);
  while (i != cnt) {
    elems[i] = elems[i+1];
    i++;
  }
}

#undef VECT_
