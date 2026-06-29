/* Mock test file for NoSeccompPolicy.ql CodeQL query
 * Tests various scenarios of seccomp policy initialization in tile definitions */

typedef unsigned long ulong;

/* Mock structure for fd_topo_run_tile_t */
typedef struct fd_topo_run_tile_t {
  char const * name;
  ulong        loose_footprint;
  ulong      (*populate_allowed_seccomp)( void const *, void const *, ulong, void * );
  ulong      (*populate_allowed_fds)( void const *, void const *, ulong, int * );
  ulong      (*scratch_align)( void );
  ulong      (*scratch_footprint)( void const * );
  void       (*privileged_init)( void *, void * );
  void       (*unprivileged_init)( void *, void * );
  void       (*run)( void *, void *, void * );
} fd_topo_run_tile_t;

/* Forward declarations */
static ulong populate_sock_filter_policy_good_tile( ulong out_cnt, void * out, unsigned int log_fd );
static ulong populate_sock_filter_policy_another_tile( ulong out_cnt, void * out, unsigned int log_fd );

/* Dummy/stub functions that do NOT call populate_sock_filter_policy_* */
static ulong
dummy_populate_seccomp( void const * topo,
                        void const * tile,
                        ulong        out_cnt,
                        void *       out ) {
  (void)topo; (void)tile; (void)out_cnt; (void)out;
  return 0UL;
}

/* Proper seccomp function that calls populate_sock_filter_policy_good_tile */
static ulong
good_populate_allowed_seccomp( void const * topo,
                                void const * tile,
                                ulong        out_cnt,
                                void *       out ) {
  (void)topo;
  (void)tile;
  populate_sock_filter_policy_good_tile( out_cnt, out, 2U );
  return 10UL;
}

/* Another proper seccomp function with different naming */
static ulong
another_populate_allowed_seccomp( void const * topo,
                                   void const * tile,
                                   ulong        out_cnt,
                                   void *       out ) {
  (void)topo;
  (void)tile;
  populate_sock_filter_policy_another_tile( out_cnt, out, 1U );
  return 15UL;
}

/* Conditional seccomp function that doesn't ALWAYS call populate_sock_filter_policy */
static ulong
conditional_populate_allowed_seccomp( void const * topo,
                                       void const * tile,
                                       ulong        out_cnt,
                                       void *       out ) {
  (void)tile;
  /* This is problematic: only calls populate_sock_filter_policy_good_tile conditionally */
  if( topo ) {
    populate_sock_filter_policy_good_tile( out_cnt, out, 2U );
    return 10UL;
  }
  return 0UL; /* This path doesn't call populate_sock_filter_policy_* at all */
}

/* Helper function that ALWAYS calls populate_sock_filter_policy */
static ulong
helper_with_policy( ulong out_cnt, void * out ) {
  populate_sock_filter_policy_good_tile( out_cnt, out, 2U );
  return 10UL;
}

/* Helper function that does NOT call populate_sock_filter_policy */
static ulong
helper_without_policy( ulong out_cnt, void * out ) {
  (void)out_cnt; (void)out;
  /* Does some other work but never calls populate_sock_filter_policy_* */
  return 5UL;
}

/* Seccomp function that delegates to a helper that calls populate_sock_filter_policy */
static ulong
indirect_good_populate_allowed_seccomp( void const * topo,
                                         void const * tile,
                                         ulong        out_cnt,
                                         void *       out ) {
  (void)topo;
  (void)tile;
  return helper_with_policy( out_cnt, out );
}

/* Seccomp function that delegates to a helper that does NOT call populate_sock_filter_policy */
static ulong
indirect_bad_populate_allowed_seccomp( void const * topo,
                                        void const * tile,
                                        ulong        out_cnt,
                                        void *       out ) {
  (void)topo;
  (void)tile;
  return helper_without_policy( out_cnt, out );
}

/* Actual policy implementation stubs */
static ulong
populate_sock_filter_policy_good_tile( ulong out_cnt, void * out, unsigned int log_fd ) {
  (void)out_cnt; (void)out; (void)log_fd;
  return 10UL;
}

static ulong
populate_sock_filter_policy_another_tile( ulong out_cnt, void * out, unsigned int log_fd ) {
  (void)out_cnt; (void)out; (void)log_fd;
  return 15UL;
}

/* Mock function pointers for other tile fields */
static ulong mock_scratch_align( void ) { return 4096UL; }
static ulong mock_scratch_footprint( void const * tile ) { (void)tile; return 65536UL; }
static void  mock_privileged_init( void * topo, void * tile ) { (void)topo; (void)tile; }
static void  mock_unprivileged_init( void * topo, void * tile ) { (void)topo; (void)tile; }
static void  mock_run( void * topo, void * tile, void * cnc ) { (void)topo; (void)tile; (void)cnc; }
static ulong mock_populate_allowed_fds( void const * topo, void const * tile, ulong out_fds_cnt, int * out_fds ) {
  (void)topo; (void)tile; (void)out_fds_cnt; (void)out_fds;
  return 0UL;
}

/* Test Case 1: Tile with CORRECT seccomp policy initialization
 * This should NOT trigger an alert */
fd_topo_run_tile_t fd_tile_good_tile = {
  .name                     = "good_tile",
  .loose_footprint          = 0UL,
  .populate_allowed_seccomp = good_populate_allowed_seccomp,
  .populate_allowed_fds     = mock_populate_allowed_fds,
  .scratch_align            = mock_scratch_align,
  .scratch_footprint        = mock_scratch_footprint,
  .privileged_init          = mock_privileged_init,
  .unprivileged_init        = mock_unprivileged_init,
  .run                      = mock_run,
};

/* Test Case 2: Tile with CORRECT seccomp policy (different naming)
 * This should NOT trigger an alert */
fd_topo_run_tile_t fd_tile_another_good_tile = {
  .name                     = "another_good_tile",
  .loose_footprint          = 0UL,
  .populate_allowed_seccomp = another_populate_allowed_seccomp,
  .populate_allowed_fds     = mock_populate_allowed_fds,
  .scratch_align            = mock_scratch_align,
  .scratch_footprint        = mock_scratch_footprint,
  .privileged_init          = mock_privileged_init,
  .unprivileged_init        = mock_unprivileged_init,
  .run                      = mock_run,
};

/* Test Case 3: Tile with DUMMY seccomp function (doesn't call populate_sock_filter_policy_*)
 * This SHOULD trigger an alert */
fd_topo_run_tile_t fd_tile_dummy_tile = { // $ Alert
  .name                     = "dummy_tile",
  .loose_footprint          = 0UL,
  .populate_allowed_seccomp = dummy_populate_seccomp,
  .populate_allowed_fds     = mock_populate_allowed_fds,
  .scratch_align            = mock_scratch_align,
  .scratch_footprint        = mock_scratch_footprint,
  .privileged_init          = mock_privileged_init,
  .unprivileged_init        = mock_unprivileged_init,
  .run                      = mock_run,
};

/* Test Case 4: Tile with NO seccomp policy field initialized
 * This SHOULD trigger an alert */
fd_topo_run_tile_t fd_tile_missing_seccomp_tile = { // $ Alert
  .name                     = "missing_seccomp_tile",
  .loose_footprint          = 0UL,
  /* .populate_allowed_seccomp is intentionally missing */
  .populate_allowed_fds     = mock_populate_allowed_fds,
  .scratch_align            = mock_scratch_align,
  .scratch_footprint        = mock_scratch_footprint,
  .privileged_init          = mock_privileged_init,
  .unprivileged_init        = mock_unprivileged_init,
  .run                      = mock_run,
};

/* Test Case 5: Another tile missing seccomp (partially initialized)
 * This SHOULD trigger an alert */
fd_topo_run_tile_t fd_tile_incomplete_tile = { // $ Alert
  .name                = "incomplete_tile",
  .scratch_align       = mock_scratch_align,
  .scratch_footprint   = mock_scratch_footprint,
  .run                 = mock_run,
  /* populate_allowed_seccomp and other fields missing */
};

/* Test Case 6: Tile with conditional seccomp policy (doesn't ALWAYS call populate_sock_filter_policy_*)
 * This SHOULD trigger an alert because not all code paths call the policy function */
fd_topo_run_tile_t fd_tile_conditional_tile = { // $ Alert
  .name                     = "conditional_tile",
  .loose_footprint          = 0UL,
  .populate_allowed_seccomp = conditional_populate_allowed_seccomp,
  .populate_allowed_fds     = mock_populate_allowed_fds,
  .scratch_align            = mock_scratch_align,
  .scratch_footprint        = mock_scratch_footprint,
  .privileged_init          = mock_privileged_init,
  .unprivileged_init        = mock_unprivileged_init,
  .run                      = mock_run,
};

/* Test Case 7: Tile with indirect seccomp policy that calls helper that DOES call populate_sock_filter_policy_*
 * This should NOT trigger an alert */
fd_topo_run_tile_t fd_tile_indirect_good_tile = {
  .name                     = "indirect_good_tile",
  .loose_footprint          = 0UL,
  .populate_allowed_seccomp = indirect_good_populate_allowed_seccomp,
  .populate_allowed_fds     = mock_populate_allowed_fds,
  .scratch_align            = mock_scratch_align,
  .scratch_footprint        = mock_scratch_footprint,
  .privileged_init          = mock_privileged_init,
  .unprivileged_init        = mock_unprivileged_init,
  .run                      = mock_run,
};

/* Test Case 8: Tile with indirect seccomp policy that calls helper that does NOT call populate_sock_filter_policy_*
 * This SHOULD trigger an alert */
fd_topo_run_tile_t fd_tile_indirect_bad_tile = { // $ Alert
  .name                     = "indirect_bad_tile",
  .loose_footprint          = 0UL,
  .populate_allowed_seccomp = indirect_bad_populate_allowed_seccomp,
  .populate_allowed_fds     = mock_populate_allowed_fds,
  .scratch_align            = mock_scratch_align,
  .scratch_footprint        = mock_scratch_footprint,
  .privileged_init          = mock_privileged_init,
  .unprivileged_init        = mock_unprivileged_init,
  .run                      = mock_run,
};

int main() {
  /* This main function is just a placeholder to make the file complete.
   * The actual test is performed by the CodeQL query on the tile definitions above. */
  return 0;
}