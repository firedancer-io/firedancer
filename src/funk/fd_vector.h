#define VECT_(n)       FD_EXPAND_THEN_CONCAT3(VECT_NAME,_,n)

struct VECT_NAME {
    uint cnt;
    uint max;
    VECT_ELEMENT* elems; 
};

void VECT_(new)(struct VECT_NAME* self) {
  self->cnt = 0;
  self->max = 64;
  self->elems = (VECT_ELEMENT*)malloc(sizeof(VECT_ELEMENT)*self->max);
}

void VECT_(destroy)(struct VECT_NAME* self) {
  free(self->elems);
}

void VECT_(push)(struct VECT_NAME* self, const VECT_ELEMENT elem) {
  if (self->cnt == self->max) {
    self->max <<= 1;
    self->elems = (VECT_ELEMENT*)realloc(self->elems, sizeof(VECT_ELEMENT)*self->max);
  }
  self->elems[self->cnt ++] = elem;
}

int VECT_(empty)(struct VECT_NAME* self) {
  return self->cnt == 0;
}

VECT_ELEMENT VECT_(pop_unsafe)(struct VECT_NAME* self) {
  // Not safe on purpose
  return self->elems[--(self->cnt)];
}

void VECT_(remove_at)(struct VECT_NAME* self, uint i) {
  VECT_ELEMENT* const elems = self->elems;
  uint cnt = --(self->cnt);
  while (i != cnt) {
    elems[i] = elems[i+1];
    i++;
  }
}

#undef VECT_
