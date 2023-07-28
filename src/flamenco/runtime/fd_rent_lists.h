typedef struct fd_funk_rec fd_funk_rec_t;

typedef struct fd_rent_lists fd_rent_lists_t;

fd_rent_lists_t * fd_rent_lists_new( ulong slots_per_epoch );

void fd_rent_lists_delete( fd_rent_lists_t * lists );

ulong fd_rent_lists_get_slots_per_epoch( fd_rent_lists_t * lists );

/* Hook into funky */
void fd_rent_lists_cb( fd_funk_rec_t const * updated,
                       fd_funk_rec_t const * removed,
                       void *                arg ); /* fd_rent_lists_t */

typedef int (*fd_rent_lists_walk_cb)( fd_funk_rec_t const * rec, void * arg );

void fd_rent_lists_walk( fd_rent_lists_t * lists,
                         ulong offset,
                         fd_rent_lists_walk_cb cb,
                         void * cb_arg );
