#include "fd_wksp_private.h"

/* fd_wksp_private_{join,leave}_func are used to automagically handle
   the first join / last leave by the fd_wksp_attach / fd_wksp_detach. */

static void *
fd_wksp_private_join_func( void *                       context,
                           fd_shmem_join_info_t const * info ) {
  (void)context;
  return fd_wksp_join( info->shmem ); /* logs details */
}

static void *
fd_wksp_private_leave_func( void *                       context,
                            fd_shmem_join_info_t const * info ) {
  (void)context;
  return fd_wksp_leave( info->join ); /* logs details */
}

/* fd_wksp_private_cstr populates cstr with [name]:[gaddr].  Assumes
   name is a valid wksp shmem name and that cstr is at least
   FD_WKSP_CSTR_MAX bytes.  Returns cstr. */

static char *
fd_wksp_private_cstr( char const * name,
                      ulong        gaddr,
                      char *       cstr ) {
  fd_cstr_fini( fd_cstr_append_ulong_as_text( fd_cstr_append_char( fd_cstr_append_cstr( fd_cstr_init( cstr ),
    name ), ':' ), ' ', '\0', gaddr, fd_ulong_base10_dig_cnt( gaddr ) ) );
  return cstr;
}

/* fd_wksp_private_cstr_parse extracts the name and gaddr from a
   [name]:[gaddr] cstr.  This doesn't actually validate if name is a
   compliant fd_shmem_name.  That will be handled automatically by the
   fd_shmem APIs. */

static char *                                      /* Returns name on success, NULL on failure (logs details) */
fd_wksp_private_cstr_parse( char const * cstr,     /* cstr to parse */
                            char *       name,     /* Non-NULL, room for FD_SHMEM_NAME_MAX bytes, holds name on success,
                                                      potentially clobbered otherwise */
                            ulong *      gaddr ) { /* Non-NULL, holds gaddr on success, untouched otherwise */
  if( FD_UNLIKELY( !cstr ) ) {
    FD_LOG_WARNING(( "NULL cstr" ));
    return NULL;
  }

  ulong len      = 0UL;
  ulong name_len = ULONG_MAX;
  for(;;) {
    if( cstr[len]=='\0' ) break;
    if( cstr[len]==':' ) name_len = len;
    len++;
  }
  ulong gaddr_len = len - name_len - 1UL;

  if( FD_UNLIKELY( !name_len ) ) {
    FD_LOG_WARNING(( "no name found; cstr should be of the form [name]:[gaddr]" ));
    return NULL;
  }

  if( FD_UNLIKELY( name_len==ULONG_MAX ) ) {
    FD_LOG_WARNING((  "no ':' found; cstr should be of the form [name]:[gaddr]" ));
    return NULL;
  }

  if( FD_UNLIKELY( !gaddr_len ) ) {
    FD_LOG_WARNING(( "no gaddr found; cstr should be of the form [name]:[gaddr]" ));
    return NULL;
  }

  if( FD_UNLIKELY( name_len>=FD_SHMEM_NAME_MAX ) ) {
    FD_LOG_WARNING(( "name too long" ));
    return NULL;
  }

  fd_memcpy( name, cstr, name_len );
  name[name_len] = '\0';
  gaddr[0] = fd_cstr_to_ulong( cstr + name_len + 1UL );
  return name;
}

/* shmem helper APIs **************************************************/

/* fd_ulong_sum_sat computes sum x[i] for i in [0,cnt), saturating at
   ULONG_MAX if the sum would overflow.  TODO: MOVE TO SAT LIBRARY */

FD_FN_PURE static inline ulong
fd_ulong_sum_sat( ulong         cnt,
                  ulong const * x ) {
  ulong sum  = 0UL;
  int   ovfl = 0;
  for( ulong idx=0UL; idx<cnt; idx++ ) {
    ulong tmp = sum + x[idx];
    ovfl |= (tmp < sum );
    sum = tmp;
  }
  return fd_ulong_if( ovfl, ULONG_MAX, sum );
}

int
fd_wksp_new_named( char const *  name,
                   ulong         page_sz,
                   ulong         sub_cnt,
                   ulong const * sub_page_cnt,
                   ulong const * sub_cpu_idx,
                   ulong         mode,
                   uint          seed,
                   ulong         part_max ) {

  /* Check input args */

  if( FD_UNLIKELY( !fd_shmem_name_len( name )      ) ) { FD_LOG_WARNING(( "bad name"            )); return FD_WKSP_ERR_INVAL; }
  if( FD_UNLIKELY( !fd_shmem_is_page_sz( page_sz ) ) ) { FD_LOG_WARNING(( "unsupported page_sz" )); return FD_WKSP_ERR_INVAL; }
  if( FD_UNLIKELY( !sub_cnt                        ) ) { FD_LOG_WARNING(( "zero sub_cnt"        )); return FD_WKSP_ERR_INVAL; }
  if( FD_UNLIKELY( !sub_page_cnt                   ) ) { FD_LOG_WARNING(( "NULL sub_page_cnt"   )); return FD_WKSP_ERR_INVAL; }
  if( FD_UNLIKELY( !sub_cpu_idx                    ) ) { FD_LOG_WARNING(( "NULL sub_cpu_idx"    )); return FD_WKSP_ERR_INVAL; }

  ulong page_cnt = fd_ulong_sum_sat( sub_cnt, sub_page_cnt );

  if( FD_UNLIKELY( !page_cnt                       ) ) { FD_LOG_WARNING(( "zero page_cnt"       )); return FD_WKSP_ERR_INVAL; }
  if( FD_UNLIKELY( page_cnt>=(ULONG_MAX/page_sz)   ) ) { FD_LOG_WARNING(( "page_cnt overflow"   )); return FD_WKSP_ERR_INVAL; }

  /* Configure the wksp */

  ulong footprint = page_cnt*page_sz;

  if( !part_max ) {
    part_max = fd_wksp_part_max_est( footprint, 64UL<<10 ); /* Typical size is fd_alloc top level superblock-ish */
    if( FD_UNLIKELY( !part_max ) ) { /* should not happen for typical page_sz and non-zero page_cnt */
      FD_LOG_WARNING(( "fd_wksp_part_max_est(%lu,64KiB) failed", footprint ));
      return FD_WKSP_ERR_INVAL;
    }
  }

  ulong data_max = fd_wksp_data_max_est( footprint, part_max );
  if( FD_UNLIKELY( !data_max ) ) {
    FD_LOG_WARNING(( "part_max (%lu) too large for footprint (%lu)", part_max, footprint ));
    return FD_WKSP_ERR_INVAL;
  }

  /* Create the memory region */

  int err = fd_shmem_create_multi( name, page_sz, sub_cnt, sub_page_cnt, sub_cpu_idx, mode ); /* logs details */
  if( FD_UNLIKELY( err ) ) return FD_WKSP_ERR_FAIL;

  /* Join the memory region */

  void * shmem = fd_shmem_join( name, FD_SHMEM_JOIN_MODE_READ_WRITE, NULL, NULL, NULL ); /* logs details */
  if( FD_UNLIKELY( !shmem ) ) {
    fd_shmem_unlink( name, page_sz ); /* logs details */
    return FD_WKSP_ERR_FAIL;
  }

  /* Format the region as a workspace */

  if( FD_UNLIKELY( !fd_wksp_new( shmem, name, seed, part_max, data_max ) ) ) { /* logs details */
    fd_shmem_unlink( name, page_sz ); /* logs details */
    fd_shmem_leave( shmem, NULL, NULL ); /* logs details, after the unlink as per unix file semantics */
    return FD_WKSP_ERR_FAIL;
  }

  fd_shmem_leave( shmem, NULL, NULL ); /* logs details */

  return FD_WKSP_SUCCESS;
}

int
fd_wksp_delete_named( char const * name ) {

  /* Join the region and get the page size */

  fd_shmem_join_info_t info[1];
  void * shwksp = fd_shmem_join( name, FD_SHMEM_JOIN_MODE_READ_WRITE, NULL, NULL, info ); /* logs details */
  if( FD_UNLIKELY( !shwksp ) ) return FD_WKSP_ERR_FAIL;
  ulong page_sz = info->page_sz;

  /* Delete the region */

  if( FD_UNLIKELY( !fd_wksp_delete( shwksp ) ) ) { /* logs details */
    fd_shmem_leave( shwksp, NULL, NULL );
    return FD_WKSP_ERR_FAIL;
  }

  if( FD_UNLIKELY( fd_shmem_unlink( name, page_sz ) ) ) { /* logs details */
    fd_shmem_leave( shwksp, NULL, NULL );
    return FD_WKSP_ERR_FAIL;
  }
    
  fd_shmem_leave( shwksp, NULL, NULL ); /* logs details, after the unlink as per UNIX file semantics */
  return FD_WKSP_SUCCESS;
}

fd_wksp_t *
fd_wksp_new_anon( char const *  name,
                  ulong         page_sz,
                  ulong         sub_cnt,
                  ulong const * sub_page_cnt,
                  ulong const * sub_cpu_idx,
                  uint          seed,
                  ulong         part_max ) {

  /* Check input args */

  if( FD_UNLIKELY( !fd_shmem_name_len( name )      ) ) { FD_LOG_WARNING(( "bad name"            )); return NULL; }
  if( FD_UNLIKELY( !fd_shmem_is_page_sz( page_sz ) ) ) { FD_LOG_WARNING(( "unsupported page_sz" )); return NULL; }
  if( FD_UNLIKELY( !sub_cnt                        ) ) { FD_LOG_WARNING(( "zero sub_cnt"        )); return NULL; }
  if( FD_UNLIKELY( !sub_page_cnt                   ) ) { FD_LOG_WARNING(( "NULL sub_page_cnt"   )); return NULL; }
  if( FD_UNLIKELY( !sub_cpu_idx                    ) ) { FD_LOG_WARNING(( "NULL sub_cpu_idx"    )); return NULL; }

  ulong page_cnt = fd_ulong_sum_sat( sub_cnt, sub_page_cnt );

  if( FD_UNLIKELY( !page_cnt                       ) ) { FD_LOG_WARNING(( "zero page_cnt"       )); return NULL; }
  if( FD_UNLIKELY( page_cnt>=(ULONG_MAX/page_sz)   ) ) { FD_LOG_WARNING(( "page_cnt overflow"   )); return NULL; }

  /* Configure the wksp */

  ulong footprint = page_cnt*page_sz;

  if( !part_max ) {
    part_max = fd_wksp_part_max_est( footprint, 64UL<<10 ); /* Typical size is fd_alloc top level superblock-ish */
    if( FD_UNLIKELY( !part_max ) ) { /* should not happen for typical page_sz and non-zero page_cnt */
      FD_LOG_WARNING(( "fd_wksp_part_max_est(%lu,64KiB) failed", footprint ));
      return NULL;
    }
  }

  ulong data_max = fd_wksp_data_max_est( footprint, part_max );
  if( FD_UNLIKELY( !data_max ) ) {
    FD_LOG_WARNING(( "part_max (%lu) too large for footprint (%lu)", part_max, footprint ));
    return NULL;
  }

  /* Acquire the pages */

  void * shmem = fd_shmem_acquire_multi( page_sz, sub_cnt, sub_page_cnt, sub_cpu_idx ); /* logs details */
  if( FD_UNLIKELY( !shmem ) ) return NULL;

  /* Format the memory as wksp */

  void* shwksp = fd_wksp_new( shmem, name, seed, part_max, data_max ); /* logs details */
  if( FD_UNLIKELY( !shwksp ) ) {
    fd_shmem_release( shmem, page_sz, page_cnt ); /* logs details */
    return NULL;
  }

  /* Join the wksp */

  fd_wksp_t * wksp = fd_wksp_join( shwksp ); /* logs details */
  if( FD_UNLIKELY( !wksp ) ) {
    fd_shmem_release( fd_wksp_delete( shwksp ), page_sz, page_cnt ); /* logs details */
    return NULL;
  }

  /* Register the join */

  if( FD_UNLIKELY( fd_shmem_join_anonymous( name, FD_SHMEM_JOIN_MODE_READ_WRITE, wksp, shmem, page_sz, page_cnt ) ) ) { /* logs */
    fd_shmem_release( fd_wksp_delete( fd_wksp_leave( wksp ) ), page_sz, page_cnt ); /* logs details */
    return NULL;
  }

  return wksp;
}

void
fd_wksp_delete_anon( fd_wksp_t * wksp ) {
  fd_shmem_join_info_t info[1];
  if( FD_UNLIKELY( fd_shmem_leave_anonymous( wksp, info ) ) ) return; /* logs details */
  fd_shmem_release( fd_wksp_delete( fd_wksp_leave( wksp ) ), info->page_sz, info->page_cnt ); /* logs details */
}

fd_wksp_t *
fd_wksp_attach( char const * name ) {
  return (fd_wksp_t *)
    fd_shmem_join( name, FD_SHMEM_JOIN_MODE_READ_WRITE, fd_wksp_private_join_func, NULL, NULL ); /* logs details */
}

int
fd_wksp_detach( fd_wksp_t * wksp ) {
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "NULL wksp" ));
    return 1;
  }
  return fd_shmem_leave( wksp, fd_wksp_private_leave_func, NULL ); /* logs details */
}

fd_wksp_t *
fd_wksp_containing( void const * laddr ) {
  if( FD_UNLIKELY( !laddr ) ) return NULL;

  fd_shmem_join_info_t info[1];
  if( FD_UNLIKELY( fd_shmem_join_query_by_addr( laddr, 1UL, info ) ) ) return NULL;

  fd_wksp_t * wksp = (fd_wksp_t *)info->join;
  if( FD_UNLIKELY( !wksp ) ) return NULL;

  if( FD_UNLIKELY( wksp->magic!=FD_WKSP_MAGIC ) ) return NULL;

  return wksp;
}

void *
fd_wksp_alloc_laddr( fd_wksp_t * wksp,
                     ulong       align,
                     ulong       sz,
                     ulong       tag ) {
  ulong gaddr = fd_wksp_alloc( wksp, align, sz, tag );
  if( FD_UNLIKELY( !gaddr ) ) return NULL;
  return fd_wksp_laddr_fast( wksp, gaddr );
}

void
fd_wksp_free_laddr( void * laddr ) {
  if( FD_UNLIKELY( !laddr ) ) return;

  fd_wksp_t * wksp = fd_wksp_containing( laddr );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "laddr does not appear to be from a workspace" ));
    return;
  }

  ulong gaddr = fd_wksp_gaddr_fast( wksp, laddr );
  if( FD_UNLIKELY( !((wksp->gaddr_lo<=gaddr) & (gaddr<=wksp->gaddr_hi)) ) ) {
    FD_LOG_WARNING(( "laddr does not appear to be from a workspace" ));
    return;
  }

  fd_wksp_free( wksp, gaddr );
}

/* cstr helper APIs ***************************************************/

char *
fd_wksp_cstr( fd_wksp_t const * wksp,
              ulong             gaddr,
              char *            cstr ) {
  if( FD_UNLIKELY( !cstr ) ) { FD_LOG_WARNING(( "NULL cstr" )); return NULL; }
  if( FD_UNLIKELY( !wksp ) ) { FD_LOG_WARNING(( "NULL wksp" )); return NULL; }

  if( FD_UNLIKELY( !( (!gaddr) | ((wksp->gaddr_lo<=gaddr) & (gaddr<=wksp->gaddr_hi)) ) ) ) {
    FD_LOG_WARNING(( "unmappable gaddr" ));
    return NULL;
  }

  return fd_wksp_private_cstr( wksp->name, gaddr, cstr );
}

char *
fd_wksp_cstr_laddr( void const * laddr,
                    char *       cstr ) {
  if( FD_UNLIKELY( !cstr ) ) { FD_LOG_WARNING(( "NULL cstr" )); return NULL; }

  fd_wksp_t const * wksp = fd_wksp_containing( laddr );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "laddr does not appear to be from a workspace" ));
    return NULL;
  }

  ulong gaddr = fd_wksp_gaddr_fast( wksp, laddr );
  if( FD_UNLIKELY( !((wksp->gaddr_lo<=gaddr) & (gaddr<=wksp->gaddr_hi)) ) ) {
    FD_LOG_WARNING(( "laddr does not appear to be from a workspace" ));
    return 0UL;
  }

  return fd_wksp_private_cstr( wksp->name, gaddr, cstr );
}

char *
fd_wksp_cstr_alloc( char const * name,
                    ulong        align,
                    ulong        sz,
                    ulong        tag,
                    char *       cstr ) {
  if( FD_UNLIKELY( !cstr ) ) {
    FD_LOG_WARNING(( "NULL cstr" ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_attach( name );
  if( FD_UNLIKELY( !wksp ) ) return NULL; /* logs details */
  /* name must be valid at this point */

  ulong gaddr = fd_wksp_alloc( wksp, align, sz, tag );
  if( FD_UNLIKELY( (!!sz) & (!gaddr) ) ) {
    fd_wksp_detach( wksp ); /* logs details */
    return NULL;
  }

  fd_wksp_detach( wksp ); /* logs details */
  return fd_wksp_private_cstr( name, gaddr, cstr );
}

void
fd_wksp_cstr_free( char const * cstr ) {
  char  name[ FD_SHMEM_NAME_MAX ];
  ulong gaddr;
  if( FD_UNLIKELY( !fd_wksp_private_cstr_parse( cstr, name, &gaddr ) ) ) return; /* logs details */

  fd_wksp_t * wksp = fd_wksp_attach( name ); /* logs details */
  if( FD_UNLIKELY( !wksp ) ) return;

  fd_wksp_free( wksp, gaddr ); /* logs details */

  fd_wksp_detach( wksp ); /* logs details */
}

ulong
fd_wksp_cstr_tag( char const * cstr ) {
  char  name[ FD_SHMEM_NAME_MAX ];
  ulong gaddr;
  if( FD_UNLIKELY( !fd_wksp_private_cstr_parse( cstr, name, &gaddr ) ) ) return 0UL; /* logs details */

  fd_wksp_t * wksp = fd_wksp_attach( name ); /* logs details */
  if( FD_UNLIKELY( !wksp ) ) return 0UL;

  ulong tag = fd_wksp_tag( wksp, gaddr ); /* logs details */

  fd_wksp_detach( wksp ); /* logs details */

  return tag;
}

void
fd_wksp_cstr_memset( char const * cstr,
                     int          c ) {
  char  name[ FD_SHMEM_NAME_MAX ];
  ulong gaddr;
  if( FD_UNLIKELY( !fd_wksp_private_cstr_parse( cstr, name, &gaddr ) ) ) return; /* logs details */

  fd_wksp_t * wksp = fd_wksp_attach( name ); /* logs details */
  if( FD_UNLIKELY( !wksp ) ) return;

  fd_wksp_memset( wksp, gaddr, c ); /* logs details */

  fd_wksp_detach( wksp ); /* logs details */
}

void *
fd_wksp_map( char const * cstr ) {
  char  name[ FD_SHMEM_NAME_MAX ];
  ulong gaddr;
  if( FD_UNLIKELY( !fd_wksp_private_cstr_parse( cstr, name, &gaddr ) ) ) return NULL; /* logs details */

  fd_wksp_t * wksp = fd_wksp_attach( name ); /* logs details */
  if( FD_UNLIKELY( !wksp ) ) return NULL;

  void * laddr = fd_wksp_laddr( wksp, gaddr ); /* logs details */
  if( FD_UNLIKELY( !laddr ) ) {
    /* We do a detach here regardless of this being an error case or not
       (i.e. gaddr was NULL) because unmap will not be able to figure
       out which wksp corresponds to the returned NULL */
    fd_wksp_detach( wksp ); /* logs details */
    return NULL;
  }

  return laddr;
}

void
fd_wksp_unmap( void const * laddr ) {
  if( FD_UNLIKELY( !laddr ) ) return; /* Silent because NULL might not be an error case (i.e. gaddr passed to map was 0/NULL) */

  /* Technically more efficient given current implementation to do:
       shmem_leave_addr( laddr );
     but the below is more official from a software maintainability POV */

  fd_shmem_join_info_t info[1];
  if( FD_UNLIKELY( fd_shmem_join_query_by_addr( laddr, 1UL, info ) ) ) {
    FD_LOG_WARNING(( "laddr does not seem to be from fd_wksp_map" ));
    return;
  }

  fd_wksp_t * wksp = (fd_wksp_t *)info->join;
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "Called within fd_wksp_join or fd_wksp_leave??" ));
    return;
  }

  fd_wksp_detach( wksp ); /* logs details */
}

/* pod helper APIs ****************************************************/

uchar const *
fd_wksp_pod_attach( char const * gaddr ) {
  if( FD_UNLIKELY( !gaddr ) ) FD_LOG_ERR(( "NULL gaddr" ));

  void * obj = fd_wksp_map( gaddr );
  if( FD_UNLIKELY( !obj ) ) FD_LOG_ERR(( "Unable to map pod at gaddr %s into local address space", gaddr ));

  uchar const * pod = fd_pod_join( obj );
  if( FD_UNLIKELY( !pod ) ) FD_LOG_ERR(( "fd_pod_join to pod at gaddr %s failed", gaddr ));

  return pod;
}

void
fd_wksp_pod_detach( uchar const * pod ) {
  if( FD_UNLIKELY( !pod ) ) FD_LOG_ERR(( "NULL pod" ));

  void * obj = fd_pod_leave( pod );
  if( FD_UNLIKELY( !obj ) ) FD_LOG_ERR(( "fd_pod_leave failed" ));

  fd_wksp_unmap( obj ); /* logs details */
}

void *
fd_wksp_pod_map( uchar const * pod,
                 char const *  path ) {
  if( FD_UNLIKELY( !pod  ) ) FD_LOG_ERR(( "NULL pod"  ));
  if( FD_UNLIKELY( !path ) ) FD_LOG_ERR(( "NULL path" ));

  char const * gaddr = fd_pod_query_cstr( pod, path, NULL );
  if( FD_UNLIKELY( !gaddr ) ) FD_LOG_ERR(( "cstr path %s not found in pod", path ));

  void * obj = fd_wksp_map( gaddr );
  if( FD_UNLIKELY( !obj ) ) FD_LOG_ERR(( "Unable to map pod cstr path %s (%s) into local address space", path, gaddr ));

  return obj;
}

void
fd_wksp_pod_unmap( void * obj ) {
  if( FD_UNLIKELY( !obj ) ) FD_LOG_ERR(( "NULL obj" ));

  fd_wksp_unmap( obj ); /* logs details */
}

