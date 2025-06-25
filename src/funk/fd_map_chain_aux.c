/* Auxilliary operations on a fd_map_chain_para */

#define MAP_(n) FD_EXPAND_THEN_CONCAT3(MAP_NAME,_,n)

#ifndef MAP_NEXT
#define MAP_NEXT next
#endif

#ifndef MAP_MEMOIZE
#define MAP_MEMOIZE 0
#endif

#ifndef MAP_KEY
#define MAP_KEY key
#endif

struct MAP_(purify_help_private) {
  MAP_(shmem_private_chain_t) * chain_base;
  ulong       chain_idx;
  ulong       chain_cnt;
  MAP_ELE_T * ele_base;    /* Pointer to the element store in the caller's address space */
  ulong       ele_max;     /* Size of element pool */
  ulong       ele_idx;     /* Current iteration element store index (or the null index) */
  uint      * ele_idx_ref; /* Where did the index come from */
  ulong       ele_cnt;     /* Number of elements in the chain */
  int         error;
  ulong       seed;      /* Hash seed, arbitrary */
};

typedef struct MAP_(purify_help_private) MAP_(purify_help_t);

static inline void
MAP_(purify_help_next_private)( MAP_(purify_help_t) * help ) {
  while( help->chain_idx < help->chain_cnt ) {
    MAP_(shmem_private_chain_t) * chain = &help->chain_base[help->chain_idx];
    chain->ver_cnt = 0; /* Reset chain */
    help->ele_idx_ref = &chain->head_cidx;
    help->ele_idx     = MAP_(private_idx)( *(help->ele_idx_ref) );
    if( MAP_(private_idx_is_null)( help->ele_idx ) ) {
      /* Fall through */
    } else if( help->ele_idx >= help->ele_max ) {
      /* Trim off bad chain */
      *(help->ele_idx_ref) = MAP_(private_cidx)(MAP_(private_idx_null()));
      help->error = 1;
    } else {
      help->ele_cnt ++;
      return;
    }
    help->ele_cnt = 0;
    help->chain_idx ++;
  }
  help->ele_idx_ref = NULL;
  help->ele_idx     = MAP_(private_idx_null());
}

FD_FN_PURE static inline void
MAP_(purify_help)( MAP_(t) const * join, ulong ele_max, MAP_(purify_help_t) * help ) {
  help->chain_base  = (MAP_(shmem_private_chain_t) *)(join->map + 1);
  help->chain_idx   = 0;
  help->chain_cnt   = join->map->chain_cnt;
  help->ele_base    = join->ele;
  help->ele_max     = ele_max;
  help->error       = 0;
  help->seed        = join->map->seed;
  help->ele_cnt     = 0;

  /* Advance to the first element */
  MAP_(purify_help_next_private)( help );
}

FD_FN_CONST static inline int
MAP_(purify_help_done)( MAP_(purify_help_t) * help ) {
  return ( help->chain_idx >= help->chain_cnt );
}

static inline void
MAP_(purify_help_next)( MAP_(purify_help_t) * help ) {
  MAP_ELE_T * ele = help->ele_base + help->ele_idx;
  help->ele_idx_ref = &ele->MAP_NEXT;
  help->ele_idx = MAP_(private_idx)( *(help->ele_idx_ref) );
  if( MAP_(private_idx_is_null)( help->ele_idx ) ) {
    /* Fall through */
  } else if( help->ele_idx >= help->ele_max ) {
    /* Trim off bad chain */
    *(help->ele_idx_ref) = MAP_(private_cidx)(MAP_(private_idx_null()));
    help->error = 1;
  } else {
    help->ele_cnt ++;
    return;
  }
  help->chain_base[help->chain_idx].ver_cnt = MAP_(private_vcnt)( 0, help->ele_cnt );
  /* Next chain */
  help->chain_idx ++;
  help->ele_cnt = 0;
  MAP_(purify_help_next_private)( help );
}

static inline MAP_ELE_T *
MAP_(purify_help_erase)( MAP_(purify_help_t) * help ) {
  MAP_ELE_T * ele = help->ele_base + help->ele_idx;
  uint idx = *(help->ele_idx_ref) = ele->MAP_NEXT;
  help->ele_idx = MAP_(private_idx)( idx );
  if( MAP_(private_idx_is_null)( help->ele_idx ) ) {
    /* Fall through */
  } else if( help->ele_idx >= help->ele_max ) {
    /* Trim off bad chain */
    *(help->ele_idx_ref) = MAP_(private_cidx)(MAP_(private_idx_null()));
    help->error = 1;
  } else {
    return ele;
  }
  help->chain_base[help->chain_idx].ver_cnt = MAP_(private_vcnt)( 0, help->ele_cnt );
  /* Next chain */
  help->chain_idx ++;
  help->ele_cnt = 0;
  MAP_(purify_help_next_private)( help );
  return ele;
}

static inline MAP_ELE_T *
MAP_(purify_help_ele)( MAP_(purify_help_t) * help ) {
  return help->ele_base + help->ele_idx;
}

static inline int
MAP_(purify_help_check_hash)( MAP_(purify_help_t) * help ) {
  MAP_ELE_T * ele = help->ele_base + help->ele_idx;
#if MAP_MEMOIZE
  ulong hash = ele->MAP_MEMO;
#else
  ulong hash = MAP_(key_hash)( &ele->MAP_KEY, help->seed );
#endif
  if( help->chain_idx != (hash & (help->chain_cnt-1UL)) ) {
    help->error = 1;
    return -1;
  }
  return 0;
}

#undef MAP_ELE_T
#undef MAP_
#undef MAP_NEXT
#undef MAP_NAME
#undef MAP_MEMO
#undef MAP_KEY
#undef MAP_MEMOIZE
