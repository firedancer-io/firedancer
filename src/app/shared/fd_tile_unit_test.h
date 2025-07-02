#ifndef HEADER_fd_src_app_shared_fd_tile_unit_test_h
#define HEADER_fd_src_app_shared_fd_tile_unit_test_h

#include "../../app/shared/fd_config.h"

/* We want a way to test the transitions between the tile's callbacks
   (before/after_credit,before/during/after_frag, housekeeping).  To
   that end, we need to instantiate the tile's context (e.g.
   fd_net_ctx_t, fd_pack_ctx_t, etc), which requires calling
   unprivileged_init, or even privileged_init.  We therefore want to
   bring up the part of the topology that's relevant to the
   tile under testing, such as the upstream producer links, downstream
   consumer links, etc.  This approach loads the config TOML and
   invokes fd_topo_initialize from either Frankendancer or Firedancer
   topology, so that the tile is configured the same way as it would
   be in production running on mainnet or testnet.
   We don't want to treat the tile as a black box, and therefore
   cannot use fd_stem.c, so we include the following template to bring
   some structures to the test.  This is a basic structure for tile
   unit testing and is not meant to be an exhaustive API, but is
   expected to evolve over time: specific tiles may require manual
   configuration at initialization and during testing.  */

/* fd_tile_unit_test_init provides the skeleton initialization steps.
   From the three config paths, only default_topo_config_path is
   required, whereas the other two (override_topo_config_path and
   user_topo_config_path) are optional.  These inputs, together with
   netns, is_firedancer and is_local_cluster are passed to
   fd_config_load() (Refer to the functions documentation for further
   details).  fd_topo_initialize_ is a pointer to the initialization
   function inside the chosen topology (e.g. firedancer or fdctl).
   topo_run_tile is typically declared and defined inside the tile
   under test.  out_config is populated as part of the initialization
   process.  On error, the function logs a warning and returns NULL.
   On success, it return a (fd_topo_tile_t *) pointer, which is
   typically required by (un)priviliged_init. */

fd_topo_tile_t *
fd_tile_unit_test_init( char const *         default_topo_config_path,
                        char const *         override_topo_config_path,
                        char const *         user_topo_config_path,
                        int                  netns,
                        int                  is_firedancer,
                        int                  is_local_cluster,
                        void (*fd_topo_initialize_)(config_t *),
                        fd_topo_run_tile_t * topo_run_tile,
                        config_t *           out_config );

/* The following provides a generic, templated framework for unit
   testing Firedancer tiles under single-threaded environment.  It
   allows different tiles (pack, net, shred, etc.) to share common
   testing infrastructure using C preprocessor templates.  This
   framework focuses on testing the tile states across the
   before/after_credit and before/during/after_frag callbacks while
   using the topology instantiated like full Firedancer/Frankendancer.

   Typical usage:

      // Include the tile implementation and any needed headers at the
      // top of the tile unit test file to access any callbacks or
      // types declaration

         #include "fd_example_tile.c"
         #include "fd_example.h"

      // Define the test context fields local to the tile to track
      // test states across callback transitions.

         struct fd_tile_test_locals {
            ulong       after_credit_expected_sz;
            example_t * after_credit_expected_output;

            uint after_frag_expected_sz;
            ...
         };
      // The struct fd_tile_test_locals will be typedef as
      // fd_tile_test_locals_t and included in struct fd_tile_test_context
      // discussed later.

         struct fd_tile_test_context {
            ulong loop_i;
            void  (*select_in_link)   (fd_tile_test_link_t ** test_links, fd_tile_test_ctx_t *, TEST_TILE_CTX_TYPE *);
            void  (*select_out_links) (fd_tile_test_link_t ** test_links, fd_tile_test_ctx_t *, TEST_TILE_CTX_TYPE *);
            ....
            fd_tile_test_locals_t locals[ 1 ];  // Tile specific test fields.
         };

      // Define the tile's context type

         #define TEST_TILE_CTX_TYPE fd_example_ctx_t

      will replace all TEST_TILE_CTX_TYPE in the test template with fd_example_ctx_t

      // Define test callbacks, similar to stem

         #define TEST_CALLBACK_BEFORE_CREDIT before_credit
         #define TEST_CALLBACK_AFTER_CREDIT  after_credit
         #define TEST_CALLBACK_BEFORE_FRAG   before_frag
         #define TEST_CALLBACK_DURING_FRAG   during_frag
         #define TEST_CALLBACK_AFTER_FRAG    after_frag
         #define TEST_CALLBACK_HOUSEKEEPING  during_housekeeping

      // Include this framework header and template
      #include "../../app/shared/fd_tile_unit_test.h"
      #include "../../app/shared/fd_tile_unit_test_tmpl.c"

      Will generate the following structures that can be used for any
      upstream frag producers/verifiers and downstream frag verifiers
      during the test:

         // All TEST_TILE_CTX_TYPE will be replaced by
         // fd_example_ctx_t at compile time.

            typedef struct fd_tile_test_context fd_tile_test_ctx_t;
            struct fd_tile_test_context {
               ...
               fd_tile_test_locals_t locals[ 1 ];
            };
            // Contains both common testing infrastructure and
            // tile-specific state.

            typedef struct fd_tile_test_link fd_tile_test_link_t;
            struct fd_tile_test_link {
               ....
            };
            // This structure models the Firedancer communication
            // channels (fd_topo_link_t) between tiles.  The test
            // template will initialize these fields by calling
            // fd_tile_test_init_link_in/out that are discussed later.

      And will generate the following APIs:
         - TEST_TILE_CTX_TYPE below will be replaced by actual context
           type (e.g. fd_example_ctx_t):

         void
         fd_tile_test_init_link_in( ..... );
         void
         fd_tile_test_init_link_out( ..... );
         // Find the link in the topology according link_name, and
         // initialize the test link with callbacks for frags
         // generation and verification.

         void
         fd_tile_test_reset_env( .... );
         // Reset test environment between test runs.
         // Must be called before a new test run.

         void
         fd_tile_test_check_output( ... );
         // Notify test to verify output when the tested tile is
         // expected to produce frags after a tile callback.

         void
         fd_tile_test_run( ... );
         // Main test execution function

   // Custom functions to be implemented in test_xxx_tile.c:

   // Each run of test needs its own way of selecting an input link
   // and output links.  Each input/upstream/producer link usually has
   // its own input generator, such as publish(...) and make_sig(...),
   // and therefore their own state verifier.
   // Each output/downstream/consumer link usually has its own output
   // verifier.
   // Examples:

      static void
      run1_select_in_link{ ... test_links,
                               test_ctx,
                               tile_ctx }  {
         test_ctx->in_link = fd_uint_if( test_ctx->loop%2, test_links[ 0 ], NULL );
      };
      // Must set the test_ctx->in_link to NULL if no producer.

      static void
      run1_select_out_links( ... test_links,
                             ... test_ctx,
                             ... tile_ctx {
         if( test_ctx->loop%2 ) fd_tile_test_check_output( FD_TILE_TEST_CALLBACK_AFTER_CREDIT, test_links[ 1 ] );
      };
      // Must call fd_tile_test_check_output if expect the tile to produce a frag

      static ulong
      link1_publish( ... test_ctx,
                    ...  input_link ) {
         void * frag = get_test_vector( test_ctx, input_link );
         test_ctx->filter = !is_valid_frag( frag );   // set expected filter for before_frag
         return frag_sz;
      };

      static int
      link2_out_check(... test_ctx,
                      ... tile_ctx,
                      ... link2 ) {
         fd_frag_meta_t * mline = link2->mcache + fd_mcache_line_idx( link2->prod_seq, link2->depth );
         ulong out_mem          = (ulong)fd_chunk_to_laddr( (void *)link2->base, link2->chunk ) + mline->ctl;
         if( !verify_output_vector( out_mem ) ) {
            FD_LOG_WARNING(("output unmatched"));
            return -1;
         }
         return 0;
      };

      static void
      populate_test_vectors( fd_tile_test_ctx_t * test_ctx ) {
         for( ulong i=0; i<MAX_TEST; i++ ) {
            make_input( i  );
            make_output( i );
         }
      }
      // Populate any vectors ahead of time for testing later

      static void
      mock_privileged_init( fd_topo_t      * topo,
                            fd_topo_tile_t * tile ) {
         void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
         FD_SCRATCH_ALLOC_INIT( l, scratch );
         fd_example_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_example_ctx_t ), sizeof( fd_example_ctx_t ) );
         ....
      }
      // Often we need to manually replicate some work in priviledged_init.

      static void
      example_reset( fd_tile_test_ctx_t * test_ctx,
                     fd_example_ctx_t   * ctx,
                     ulong test_choice1,
                     ulong test_choice2 ) {
         test_ctx->locals->choice1 = ...;
         test_ctx->locals->choice2 = ...;
      }
      // Reset the test context according to some self-defined logic
      // for a fresh test run.  Usually called after fd_tile_test_reset_env.

   # main typically looks like:
      int
      main( int     argc, char ** argv ) {
         fd_boot( &argc, &argv );

         // Initialize tile unit test
         char const * default_topo_config_path  = TEST_DEFAULT_TOPO_CONFIG_PATH;
         char const * override_topo_config_path = NULL;
         char const * user_topo_config_path     = NULL;
         int          netns                     = 0;
         int          is_firedancer             = TEST_IS_FIREDANCER;
         int          is_local_cluster          = 0;
         fd_topo_tile_t * test_tile = fd_tile_unit_test_init( default_topo_config_path, override_topo_config_path, user_topo_config_path,
                                                               netns, is_firedancer, is_local_cluster,
                                                               fd_topo_initialize, &fd_tile_pack, config );
         FD_TEST( test_tile );
         fd_metrics_register( fd_metrics_new( metrics_scratch, 10, 10 ) );

         mock_privileged_init( &config->topo, test_tile );
         unprivileged_init(    &config->topo, test_tile );

         fd_tile_test_link_t input_link = {0};
         fd_tile_test_init_link_in( &config->topo, &input_link, "<input_tile>_<tested_tile>", ctx, find_in_index,
                                    link1_publish, NULL, NULL, link1_during_frag_check, link1_after_frag_check );
         fd_tile_test_link_t output_link = {0};
         fd_tile_test_init_link_out( &config->topo, &output_link, "<tested_tile>_<output_tile>", link2_out_check );
         fd_tile_test_link_t * test_links[ 2 ] = { input_link, output_link };
         ....

         populate_test_vectors( &test_ctx );

         // Tile test run 1
         fd_tile_test_reset_env( &test_ctx, &stem, test_links,
                                 run1_select_in_link, run1_select_out_link, bc_check1, ac_check1 );
         example_reset( &test_ctx, ctx, 1, 0 );
         fd_tile_test_run( ctx, &stem, test_links, &test_ctx, 12, 6 );

         // Tile test run 2
         fd_tile_test_update_callback_link_in( &input_link, FD_TILE_TEST_CALLBACK_PUBLISH, publish2, NULL );
         fd_tile_test_reset_env( &test_ctx, &stem, test_links,
                                 stress_test_select_in_link, stress_test_select_out_link, bc_check2, ac_check2 );
         example_reset( &test_ctx, ctx, 1, 0 );
         fd_tile_test_run( ctx, &stem, test_links, &test_ctx, 200000, 1000 );

         // Tile test run 3
         fd_tile_test_update_callback_link_in
         fd_tile_test_reset_env...
         example_reset...
         fd_tile_test_run...

         ...
      }
*/

#ifdef TEST_TILE_CTX_TYPE

typedef struct fd_tile_test_link    fd_tile_test_link_t;
typedef struct fd_tile_test_context fd_tile_test_ctx_t;

/* Represents an input/output link for the tile under test.
   This structure models the Firedancer communication channels
   (fd_topo_link_t) between tiles.  The test template will initialize
   these fields by calling fd_tile_test_init_link_in/out.
   Each check function should return 0 on success, error code on
   failure and log warnings. The fd_tile_test_run will abort the test
   on error code. */
struct fd_tile_test_link {
   fd_frag_meta_t * mcache;  // mcache of the link
   void           * dcache;  // dcache of the link
   ulong            depth;   // depth of the link
   const void     * base;    // base of dcache == fd_wksp_containing( link->dcache ).
   ulong            chunk0;  // dcache chunk0  == fd_dcache_compact_chunk0( link->base, link->dcache )
   ulong            wmark;   // dcache chunk watermark == fd_dcache_compact_wmark( link->base, link->dcache, link->mtu );
   ulong            chunk;   // current chunk. initialized to chunk0
   ulong            in_idx;  // index of this link in the context if this link is an input link, ULONG_MAX otherwise.

   ulong prod_seq;  // seq of newly produced frag. initialized to 0, and incremented everytime when a new frag is produced from this link
   ulong cons_seq;  // seq of currently processing frag. initialized to ULONG_MAX, and incremented everytime before the test loop processes a frag

   int is_input_link;   // 1 the link is an input/producer/upstream link, 0 if the link is an output/consumer/downstream link

   // for input/producer/upstream link
   ulong (*publish) ( fd_tile_test_ctx_t *, fd_tile_test_link_t * );    // callback to publish a frag
   ulong (*make_sig)( fd_tile_test_ctx_t *, fd_tile_test_link_t * );    // callback to make signature for the published frag
   int   (*before_frag_check)( fd_tile_test_ctx_t *, TEST_TILE_CTX_TYPE * );  // callback to check before_frag
   int   (*during_frag_check)( fd_tile_test_ctx_t *, TEST_TILE_CTX_TYPE * );  // callback to check during_frag
   int   (*after_frag_check) ( fd_tile_test_ctx_t *, TEST_TILE_CTX_TYPE * );  // callback to check after_frag

   // for output/consumer/downstream link
   int (*output_verifier) ( fd_tile_test_ctx_t *, TEST_TILE_CTX_TYPE *, fd_tile_test_link_t * ); // callback to verify an output
};

#define FD_TILE_TEST_CALLBACK_BEFORE_CREDIT 0
#define FD_TILE_TEST_CALLBACK_AFTER_CREDIT  1
#define FD_TILE_TEST_CALLBACK_BEFORE_FRAG   2
#define FD_TILE_TEST_CALLBACK_DURING_FRAG   3
#define FD_TILE_TEST_CALLBACK_AFTER_FRAG    4
#define FD_TILE_TEST_CALLBACK_PUBLISH       5
#define FD_TILE_TEST_CALLBACK_MAKE_SIG      6
#define FD_TILE_TEST_CALLBACK_OUT_VERIFY    7

/* fd_tile_test_ctx_t contains both common testing infrastructure and
   tile-specific state.  This structure is updated and checked during
   each test loop.  The select_in_link function can set the in_link
   field to the selected input/upstream/producer link for a test loop,
   and NULL if no link selected.  The select_out_link function can set
   the out_link field to the selected output/downstream/consumer
   link for a test loop, and NULL if no link selected.  The
   tile_specific_struct should be defined in the tile unit test file
   and contains any fields local to the tested tile. */
typedef struct fd_tile_test_locals fd_tile_test_locals_t;
struct fd_tile_test_context {
   ulong loop_i; // test loop counter

   void (*select_in_link)   (fd_tile_test_link_t ** test_links, fd_tile_test_ctx_t *, TEST_TILE_CTX_TYPE *); // for selecting upstream producer
   void (*select_out_links) (fd_tile_test_link_t ** test_links, fd_tile_test_ctx_t *, TEST_TILE_CTX_TYPE *); // for selecting downstream consumers

   fd_tile_test_link_t * in_link;   // input link for current loop, set by select_in_link above.

   ulong is_overrun; // whether the current frag is overrun

   int filter;      // filter returned by before_frag(...)
   int filter_exp;  // expected before_frag filter.
                    // Initialized to 0. Usually set by the publish callback.

   fd_tile_test_locals_t locals[ 1 ];  // Tile specific test fields
};

/* Initialize an output/consumer/downstream test_link:
   Find the link in the topology according link_name, and initialize
   the test link with callbacks for frag verification.  Usually, the
   link was added to topology by fd_topob_tile_out.  The check
   functions should return a non-zero error code when fail and log
   warning. */
void
fd_tile_test_init_link_out( fd_topo_t           * topo,
                            fd_tile_test_link_t * test_link,
                            const char          * link_name,
                            int (*output_verifier) ( fd_tile_test_ctx_t *, TEST_TILE_CTX_TYPE *, fd_tile_test_link_t * ) );

/* Initialize an input/producer/upstream test_link:
   Find the link in the topology according link_name, and initialize
   the test link with callbacks for frags generation and verification,
   and for checking the tile's context when consuming a frag.  Usually
   the link was added to topology thourgh fd_topob_tile_in.
   find_in_idx is a callback to find the index of this link in tile's
   ctx, and cannot be NULL.  The check functions should return a
   non-zero error code when fail and log warning.  */
void
fd_tile_test_init_link_in( fd_topo_t           * topo,
                           fd_tile_test_link_t * test_link,
                           const char          * link_name,
                           TEST_TILE_CTX_TYPE  * ctx,
                           void  (*find_in_idx)( fd_tile_test_link_t *, TEST_TILE_CTX_TYPE *  ),
                           ulong (*publish) (    fd_tile_test_ctx_t  *, fd_tile_test_link_t * ),
                           ulong (*make_sig)(    fd_tile_test_ctx_t  *, fd_tile_test_link_t * ),
                           int   (*before_frag_check)( fd_tile_test_ctx_t *, TEST_TILE_CTX_TYPE * ),
                           int   (*during_frag_check)( fd_tile_test_ctx_t *, TEST_TILE_CTX_TYPE * ),
                           int   (*after_frag_check) ( fd_tile_test_ctx_t *, TEST_TILE_CTX_TYPE * ) );


/* Update one of the input test link's callback.  Only one of
   pub_or_sig and check will be used, depending on the
   callback_fn_num (must be one of test_callback_fn_num above) */
void
fd_tile_test_update_callback_link_in( fd_tile_test_link_t * test_link,
                                      int                   callback_fn_num,
                                      ulong (*pub_or_sig)( fd_tile_test_ctx_t *, fd_tile_test_link_t * ),
                                      int   (*check)(      fd_tile_test_ctx_t *, TEST_TILE_CTX_TYPE *  ) );

/* Update one of the output test link's callback.  callback_fn_num
   must be FD_TILE_TEST_CALLBACK_OUTVER. */
void
fd_tile_test_update_callback_link_out( fd_tile_test_link_t * test_link,
                                       int                   callback_fn_num,
                                       int (*output_verifier)( fd_tile_test_ctx_t *, TEST_TILE_CTX_TYPE *, fd_tile_test_link_t * ) );


/* Used in select_output_links callback when the tested tile is
   expected to produce frags after a tile callback.  The
   callback_fn_num must be one of FD_TILE_TEST_CALLBACK_BEFORE_CREDIT,
   FD_TILE_TEST_CALLBACK_AFTER_CREDIT, and
   FD_TILE_TEST_CALLBACK_AFTER_FRAG.  The fd_tile_test_run will invoke
   the output_verifier callback defined in the test_link after the
   specified tile callback to verify output.  */
void
fd_tile_test_check_output( int                   callback_fn_num,
                           fd_tile_test_link_t * test_link );

/* Reset test environment between test runs (clears state, resets
   input/output selection callbacks, etc ).  Must be called before
   each test run. */
void
fd_tile_test_reset_env( fd_tile_test_ctx_t  *  test_ctx,
                        fd_stem_context_t   *  stem,
                        fd_tile_test_link_t ** test_links,
                        void (*select_in_link)  ( fd_tile_test_link_t **, fd_tile_test_ctx_t *, TEST_TILE_CTX_TYPE * ),
                        void (*select_out_links)( fd_tile_test_link_t **, fd_tile_test_ctx_t *, TEST_TILE_CTX_TYPE * ),
                        int  (*before_credit_check)( fd_tile_test_ctx_t *, TEST_TILE_CTX_TYPE * ),
                        int  (*after_credit_check) ( fd_tile_test_ctx_t *, TEST_TILE_CTX_TYPE * ) );

/* Main test execution function - runs the tile test through multiple
   iterations determined by loop_cnt.  For every
   'housekeeping_interval' loops, housekeeping will be ran, including
   the very first loop.

   For each iteration:
   Select input/upstream/producer link from test_links by callback
   test_ctx->select_in_link, which should set test_ctx->in_link.
   If an input/upstream/producer link is selected (test_ctx->in_link!=NULL):
      - publish data by callback to test_ctx->in_link->publish(...),
      - make signature by callback to test_ctx->in_link->make_sig(...)
      - Increment the prod_seq by 1, and test_ctx->in_link->chunk by
        calling fd_dcache_compact_next
      - update the test callbacks that check the tile's frag callbacks.
   Select output/downstream/consumer links from test_links by callback
   test_ctx->select_out_links.
   Execute housekeeping according to 'housekeeping_interval'.
   Execute the before_credit and after_credit tile callbacks if defined.
   Run verification callback after tile callback to before/after_credit.
   If input/upstream/producer link does not publish a frag, continue
   to next loop.
   Increment the input/upstream/producer link's cons_seq before
   calling the first defined tile frag callback.
   Run overrun detection between calls to before/during_frag,
   and between during/after_frag.
   If overrun is detected:
      - set input/upstream/producer link's cons_seq to prod_seq-1
      - skip the tile's next frag callback and continue to next loop
   Run verification callback after each tile's frag callback.
   Execute output verifier callbacks if defined.

   Note that under a single-threaded environment, we cannot properly
   test overrun.  But it's possible to semi-mock the overrun behavior
   by incresing the prod_seq in an upstream link by more than depth
   amount in the publish callback while only publish one frag to the
   tested tile.  This will cause the detect_overrun to set the
   test_ctx->is_overrun flag, set cons_seq to prod_seq-1 and continue
   to the next loop, skipping the next frag callback.  We can then
   verify whether the overrun frag can been properly cleaned up in the
   next test iteration. */

void
fd_tile_test_run( TEST_TILE_CTX_TYPE  *  ctx,
                  fd_stem_context_t   *  stem,
                  fd_tile_test_link_t ** test_links,
                  fd_tile_test_ctx_t  *  test_ctx,
                  ulong                  loop_cnt,
                  ulong                  housekeeping_interval );

#endif  /* TEST_TILE_CTX_TYPE */

#endif /* HEADER_fd_src_app_shared_fd_tile_unit_test_h */
