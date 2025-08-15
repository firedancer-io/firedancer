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
   allows different tile (pack, net, shred, etc.) to share common
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

         struct tile_test_locals {
            ulong       after_credit_expected_sz;
            example_t * after_credit_expected_output;

            uint after_frag_expected_sz;
            ...
         };
      // The struct tile_test_locals will be typedef as
      // tile_test_locals_t and included in struct test_context
      // discussed later.

         struct test_context {
            ulong loop_i;
            void  (*select_in_link)  (test_link_t ** test_links, test_ctx_t *, TEST_TILE_CTX_TYPE *);
            void  (*select_out_link) (test_link_t ** test_links, test_ctx_t *, TEST_TILE_CTX_TYPE *);
            ....
            tile_test_locals_t locals[ 1 ];  // Tile specific test fields.
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
      upstream frag producers/verifiers and downstream verifiers
      during the test:

         // All TEST_TILE_CTX_TYPE will be replaced by
         // fd_example_ctx_t at compile time.

            typedef struct test_context test_ctx_t;
            struct test_context {
               ...
               tile_test_locals_t locals[ 1 ];
            };
            // Contains both common testing infrastructure and tile-specific state.

            typedef struct test_link test_link_t;
            struct test_link {
               ....
            };
            // This structure models the Firedancer communication channels
            // (fd_topo_link_t) between tiles. The test template will initialize
            // these fields by calling init_test_link that's discussed later.

      And will generate the following APIs:
         - TEST_TILE_CTX_TYPE below will be replaced by actual context
           type (e.g. fd_example_ctx_t):

         void
         init_test_link( ..... );
         // Find the link in the topology according link_name, and initialize the
         // test link with callbacks for frags generation and verification.

         void
         reset_test_env( .... );
         // Reset test environment between test runs.
         // Must be called before a new test run.

         void
         tile_test_run( ... );
         // Main test execution function

   // Custom functions to be implemented in test_xxx_tile.c:

   // Each run of test needs its own way of selecting an input link
   // and output link.  Each input/upstream/producer link usually has
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
      run1_select_out_link( ... test_links,
                            ... test_ctx,
                            ... tile_ctx {
         test_ctx->out_link = fd_uint_if( test_ctx->loop%2, test_links[ 1 ], NULL );
      };
      // Must set the test_ctx->out_link to NULL if do not expect tile to output anything.

      static ulong
      link1_publish( ... test_ctx,
                    ...  input_link ) {
         void * frag = get_test_vector( test_ctx, input_link );
         test_ctx->filter = !is_valid_frag( frag );   // set expected filter for before_frag
         return frag_sz;
      };

      static int
      link2_ac_check(... test_ctx,
                    ... tile_ctx ) {
         test_link_t * out_link = test_ctx->out_link;
         fd_frag_meta_t * mline = out_link->mcache + fd_mcache_line_idx( out_link->prod_seq, out_link->depth );
         ulong out_mem          = (ulong)fd_chunk_to_laddr( (void *)out_link->base, out_link->chunk ) + mline->ctl;
         if( !verify_output_vector( out_mem ) ) {
            FD_LOG_WARNING(("output unmatched"));
            return -1;
         }
         return 0;
      };

      static void
      populate_test_vectors( test_ctx_t * test_ctx ) {
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
      example_reset( test_ctx_t       * test_ctx,
                     fd_example_ctx_t * ctx,
                     ulong test_choice1,
                     ulong test_choice2 ) {
         test_ctx->locals->choice1 = ...;
         test_ctx->locals->choice2 = ...;
      }
      // Reset the test context according to some self-defined logic
      // for a fresh test run.  Usually called after reset_test_env.

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

         test_link_t input_link = {0};
         init_test_link( &config->topo, &input_link, "<input_tile>_<tested_tile>", ctx,
                         link1_publish, NULL,
                         NULL, NULL, NULL, link1_df_check, link1_af_check );
         test_links_t * test_links[ 2 ] = {input_link, output_link};
         ....

         populate_test_vectors( &test_ctx );

         // Tile test run 1
         reset_test_env( &test_ctx, &stem, test_links,
                         run1_select_in_link, run1_select_out_link );
         example_reset( &test_ctx, ctx, 1, 0 );
         tile_test_run( ctx, &stem, test_links, &test_ctx, 12, 6 );

         // Tile test run 2
         update_test_link_callback( &input_link, CALLBACK_FN_PUB, publish2, NULL );
         reset_test_env( &test_ctx, &stem, test_links,
                         stress_test_select_in_link, stress_test_select_out_link );
         example_reset( &test_ctx, ctx, 1, 0 );
         tile_test_run( ctx, &stem, test_links, &test_ctx, 200000, 1000 );

         // Tile test run 3
         update_test_link_callback
         reset_test_env...
         example_reset...
         tile_test_run...

         ...
      }
*/

#ifdef TEST_TILE_CTX_TYPE

typedef struct test_link test_link_t;
typedef struct test_context test_ctx_t;

/* Represents an input/output link for the tile under test.
   This structure models the Firedancer communication channels
   (fd_topo_link_t) between tiles.  The test template will initialize
   these fields by calling init_test_link.
   Each check function should return 0 on success, error code on
   failure and log warnings. The tile_test_run will abort the test on
   error code. */
struct test_link {
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

   ulong (*publish) ( test_ctx_t *, test_link_t * );    // callback to publish a frag
   ulong (*make_sig)( test_ctx_t *, test_link_t * );    // callback to make signature for the published frag
   int (*bc_check)( test_ctx_t *, TEST_TILE_CTX_TYPE * );  // callback to check before_credit.
   int (*ac_check)( test_ctx_t *, TEST_TILE_CTX_TYPE * );  // callback to check after_credit
   int (*bf_check)( test_ctx_t *, TEST_TILE_CTX_TYPE * );  // callback to check before_frag
   int (*df_check)( test_ctx_t *, TEST_TILE_CTX_TYPE * );  // callback to check during_frag
   int (*af_check)( test_ctx_t *, TEST_TILE_CTX_TYPE * );  // callback to check after_frag
};

/* For updating a callback for a test link in update_test_link_callback */
enum test_callback_fn_num {
   CALLBACK_FN_BC  = 0,    // before_credit
   CALLBACK_FN_AC  = 1,    // after_credit
   CALLBACK_FN_BF  = 2,    // before_frag
   CALLBACK_FN_DF  = 3,    // during_frag
   CALLBACK_FN_AF  = 4,    // after_frag
   CALLBACK_FN_PUB = 5,    // publish
   CALLBACK_FN_SIG = 6     // make_sign
};

/* test_ctx_t contains both common testing infrastructure and
   tile-specific state.  This structure is updated and checked during
   each test loop.  The select_in_link function can set the in_link
   field to the selected input/upstream/producer link for a test loop,
   and NULL if no link selected.  The select_out_link function can set
   the out_link field to the selected output/downstream/consumer
   link for a test loop, and NULL if no link selected.  The
   tile_specific_struct should be defined in the tile unit test file
   and contains any fields local to the tested tile. */
typedef struct tile_test_locals tile_test_locals_t;
struct test_context {
   ulong loop_i;       // test loop counter
   void (*select_in_link)  (test_link_t ** test_links, test_ctx_t *, TEST_TILE_CTX_TYPE *); // for selecting upstream producer
   void (*select_out_link) (test_link_t ** test_links, test_ctx_t *, TEST_TILE_CTX_TYPE *); // for selecting downstream consumer
   test_link_t * out_link;  // output link for current loop, set by select_in_link above.
   test_link_t * in_link;   // input link for current loop, set by select_out_link above.

   ulong is_overrun; // whether the current frag is overrun

   int filter;      // filter returned by before_frag(...)
   int filter_exp;  // expected before_frag filter.
                    // Initialized to 0. Usually set by the publish callback.

   tile_test_locals_t locals[ 1 ];     // Tile specific test fields
};

/* Initialize test_link:
   Find the link in the topology according link_name, and initialize
   the test link with callbacks for frags generation and verification.
   find_in_idx is a callback to find the index of this link in
   context, if possible. A producer link will specify publish,
   make_sig, and bf/df/af_check, while a consumer link will have
   bc/ac_check. The check functions should return a non-zero error
   code when fail and log warning. The tile_test_run will abort the
   test if any of the check functions return an error code. */
void
init_test_link( fd_topo_t     * topo,
                test_link_t   * test_link,
                const char    * link_name,
                TEST_TILE_CTX_TYPE * ctx,
                void  (*find_in_idx)( test_link_t *, TEST_TILE_CTX_TYPE * ),
                ulong (*publish) ( test_ctx_t *, test_link_t * ),
                ulong (*make_sig)( test_ctx_t *, test_link_t * ),
                int (*bc_check)( test_ctx_t *, TEST_TILE_CTX_TYPE * ),
                int (*ac_check)( test_ctx_t *, TEST_TILE_CTX_TYPE * ),
                int (*bf_check)( test_ctx_t *, TEST_TILE_CTX_TYPE * ),
                int (*df_check)( test_ctx_t *, TEST_TILE_CTX_TYPE * ),
                int (*af_check)( test_ctx_t *, TEST_TILE_CTX_TYPE * ) );


/* Update one of the test link's callback.  Only one of pub_or_sig and
   check will be used, depending on the callback_fn_num (must be one
   of test_callback_fn_num above) */
void
update_test_link_callback( test_link_t * test_link,
                           int callback_fn_num,
                           ulong (*pub_or_sig)( test_ctx_t *, test_link_t *   ),
                           int (*check)(        test_ctx_t *, TEST_TILE_CTX_TYPE * ) );


/* Reset test environment between test runs (clears state, resets
   input/output selection callbacks, etc ).  Must be called before
   each test run. */
void
reset_test_env( test_ctx_t        *  test_ctx,
                fd_stem_context_t *  stem,
                test_link_t       ** test_links,
                void (*selec_in_link) ( test_link_t **, test_ctx_t *, TEST_TILE_CTX_TYPE * ),
                void (*selec_out_link)( test_link_t **, test_ctx_t *, TEST_TILE_CTX_TYPE * ) );


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
   Select output/downstream/consumer link from test_links by callback
   test_ctx->select_out_link.
   If an output/downstream/consumer link is selected, update the
   callbacks to before/after_credit checks.
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
tile_test_run( TEST_TILE_CTX_TYPE     *  ctx,
               fd_stem_context_t *  stem,
               test_link_t       ** test_links,
               test_ctx_t        *  test_ctx,
               ulong                loop_cnt,
               ulong                housekeeping_interval );

#endif  /* TEST_TILE_CTX_TYPE */

#endif /* HEADER_fd_src_app_shared_fd_tile_unit_test_h */
