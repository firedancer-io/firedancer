#define __CODEQL_TEST__ 1

typedef unsigned long ulong;

#define NULL ((void *)0)
#define ULONG_MAX (~0UL)

typedef struct block_map block_map_t;
typedef struct other_map other_map_t;
typedef struct nested_map nested_map_t;

typedef struct block_info {
  ulong block;
  ulong height;
} block_info_t;

typedef struct nested_info {
  struct {
    ulong key;
  } hdr;
  ulong value;
} nested_info_t;

#define MAP_NAME block_map
#define MAP_KEY  block

block_info_t *       block_map_ele_query      ( block_map_t * map, ulong const * key, block_info_t * sentinel, block_info_t * pool );
block_info_t const * block_map_ele_query_const( block_map_t * map, ulong const * key, block_info_t const * sentinel, block_info_t * pool );
block_info_t *       block_map_ele_remove     ( block_map_t * map, ulong const * key, block_info_t * sentinel, block_info_t * pool );
ulong                block_map_idx_remove     ( block_map_t * map, ulong const * key, ulong sentinel, block_info_t * pool );
void                 block_map_ele_remove_fast( block_map_t * map, block_info_t * ele, block_info_t * pool );
void                 block_map_ele_insert     ( block_map_t * map, block_info_t * ele, block_info_t * pool );
ulong                other_map_idx_remove     ( other_map_t * map, ulong const * key, ulong sentinel, block_info_t * pool );

#undef MAP_NAME
#undef MAP_KEY
#define MAP_NAME nested_map
#define MAP_KEY  hdr.key

nested_info_t * nested_map_ele_query ( nested_map_t * map, ulong const * key, nested_info_t * sentinel, nested_info_t * pool );
ulong           nested_map_idx_remove( nested_map_t * map, ulong const * key, ulong sentinel, nested_info_t * pool );

void
unsafe_initializer_query( block_map_t * map, block_info_t * pool, ulong old_key, ulong new_key ) {
  block_info_t * ele = block_map_ele_query( map, &old_key, NULL, pool );
  ele->block = new_key; // $ Alert
}

void
unsafe_assignment_query( block_map_t * map, block_info_t * pool, ulong old_key, ulong new_key ) {
  block_info_t * ele;
  ele = block_map_ele_query( map, &old_key, NULL, pool );
  ele->block += new_key; // $ Alert
}

void
unsafe_increment( block_map_t * map, block_info_t * pool, ulong old_key ) {
  block_info_t * ele = block_map_ele_query( map, &old_key, NULL, pool );
  ele->block++; // $ Alert
}

void
unsafe_remove_after_mutation( block_map_t * map, block_info_t * pool, ulong old_key, ulong new_key ) {
  block_info_t * ele = block_map_ele_query( map, &old_key, NULL, pool );
  ele->block = new_key; // $ Alert
  block_map_idx_remove( map, &old_key, ULONG_MAX, pool );
}

void
unsafe_wrong_key_removed( block_map_t * map, block_info_t * pool, ulong old_key, ulong other_key, ulong new_key ) {
  block_info_t * ele = block_map_ele_query( map, &old_key, NULL, pool );
  block_map_idx_remove( map, &other_key, ULONG_MAX, pool );
  ele->block = new_key; // $ Alert
}

void
unsafe_wrong_map_removed( block_map_t * map, block_map_t * other_map, block_info_t * pool, ulong old_key, ulong new_key ) {
  block_info_t * ele = block_map_ele_query( map, &old_key, NULL, pool );
  block_map_idx_remove( other_map, &old_key, ULONG_MAX, pool );
  ele->block = new_key; // $ Alert
}

void
unsafe_wrong_map_family_removed( block_map_t * map, other_map_t * other_map, block_info_t * pool, ulong old_key, ulong new_key ) {
  block_info_t * ele = block_map_ele_query( map, &old_key, NULL, pool );
  other_map_idx_remove( other_map, &old_key, ULONG_MAX, pool );
  ele->block = new_key; // $ Alert
}

void
unsafe_branch_only_remove( block_map_t * map, block_info_t * pool, ulong old_key, ulong new_key, int remove_it ) {
  block_info_t * ele = block_map_ele_query( map, &old_key, NULL, pool );
  if( remove_it ) block_map_idx_remove( map, &old_key, ULONG_MAX, pool );
  ele->block = new_key; // $ Alert
}

void
unsafe_nested_key( nested_map_t * map, nested_info_t * pool, ulong old_key, ulong new_key ) {
  nested_info_t * ele = nested_map_ele_query( map, &old_key, NULL, pool );
  ele->hdr.key = new_key; // $ Alert
}

void
safe_remove_by_idx( block_map_t * map, block_info_t * pool, ulong old_key, ulong new_key ) {
  block_info_t * ele = block_map_ele_query( map, &old_key, NULL, pool );
  block_map_idx_remove( map, &old_key, ULONG_MAX, pool );
  ele->block = new_key;
  block_map_ele_insert( map, ele, pool );
}

void
safe_remove_by_ele( block_map_t * map, block_info_t * pool, ulong old_key, ulong new_key ) {
  block_info_t * ele = block_map_ele_query( map, &old_key, NULL, pool );
  block_map_ele_remove( map, &old_key, NULL, pool );
  ele->block = new_key;
}

void
safe_remove_fast_by_element( block_map_t * map, block_info_t * pool, ulong old_key, ulong new_key ) {
  block_info_t * ele = block_map_ele_query( map, &old_key, NULL, pool );
  block_map_ele_remove_fast( map, ele, pool );
  ele->block = new_key;
}

void
safe_mutate_non_key( block_map_t * map, block_info_t * pool, ulong old_key, ulong new_height ) {
  block_info_t * ele = block_map_ele_query( map, &old_key, NULL, pool );
  ele->height = new_height;
}

void
safe_const_query( block_map_t * map, block_info_t * pool, ulong old_key, ulong new_key ) {
  block_info_t const * ele = block_map_ele_query_const( map, &old_key, NULL, pool );
  ((block_info_t *)ele)->block = new_key;
}

void
safe_overwritten_pointer( block_map_t * map, block_info_t * pool, ulong old_key, block_info_t * other, ulong new_key ) {
  block_info_t * ele = block_map_ele_query( map, &old_key, NULL, pool );
  ele = other;
  ele->block = new_key;
}
