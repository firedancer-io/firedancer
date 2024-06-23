static char const fd_shm_path_prefix[] = "/fd/";  /* len 4 */
#define FD_SHMEM_PATH_MAX (FD_SHMEM_NAME_MAX+4UL)

static inline char *
fd_shm_path( char         buf[ static FD_SHMEM_PATH_MAX ],
             char const * name ) {
  if( name==SHM_ANON ) return SHM_ANON;
  return fd_cstr_fini( fd_cstr_append_cstr( fd_cstr_append_cstr( fd_cstr_init(
      buf ), fd_shm_path_prefix ), name ) );
}

static inline int
fd_shm_open( char const * name,
             int          flags,
             mode_t       mode ) {
  char _shm_path[ FD_SHMEM_PATH_MAX ];
  return shm_open( fd_shm_path( _shm_path, name ), flags, mode );
}

static inline int
fd_shm_create_largepage( char const * name,
                         int          flags,
                         int          psind,
                         int          alloc_policy,
                         mode_t       mode ) {
  char _shm_path[ FD_SHMEM_PATH_MAX ];
  return shm_create_largepage( fd_shm_path( _shm_path, name ), flags, psind, alloc_policy, mode );
}
