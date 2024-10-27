#ifndef SOL_COMPAT_HARNESS_CTX_H
#define SOL_COMPAT_HARNESS_CTX_H

#include "../../nanopb/pb_firedancer.h"


struct sol_compat_harness_ctx {
    pb_msgdesc_t const* fixture_desc;
    uchar context_submsg_tag;
    uchar effects_submsg_tag;
    pb_msgdesc_t const* context_desc;
    pb_msgdesc_t const* effects_desc;


    char const ** effects_tags_fieldnames;
};

typedef struct sol_compat_harness_ctx sol_compat_harness_ctx_t;

/* Forward declare harness contexts */
extern const sol_compat_harness_ctx_t instr_harness_ctx;
extern const sol_compat_harness_ctx_t txn_harness_ctx;
extern const sol_compat_harness_ctx_t syscall_harness_ctx;
extern const sol_compat_harness_ctx_t vm_validate_harness_ctx;
extern const sol_compat_harness_ctx_t elf_loader_harness_ctx;

/* TODO: Helper functions */



/* Harness Generator Macros.
   TODO: Python-based approach? 
*/

#define EVAL(x) x
#define CONCAT(x, y) x ## y
#define EXPAND_CONCAT(x, y) CONCAT(x, y)

#define PB_GEN_FIELD_NAMES(structname, atype, htype, ltype, fieldname, tag) \
    #fieldname,

#define GEN_HARNESS_CTX_EX( harness_name, fixture_descriptor, context_submsg_tag_, effects_submsg_tag_, context_descriptor, effects_descriptor, effects_msgname ) \
    char const * effects_msgname## _fieldnames[] = { \
        NULL, \
        effects_msgname ## _FIELDLIST(PB_GEN_FIELD_NAMES, NULL) \
    }; \
    const sol_compat_harness_ctx_t harness_name = { \
        .fixture_desc = fixture_descriptor, \
        .context_submsg_tag = context_submsg_tag_, \
        .effects_submsg_tag = effects_submsg_tag_, \
        .context_desc = context_descriptor, \
        .effects_desc = effects_descriptor, \
        .effects_tags_fieldnames = effects_msgname## _fieldnames \
    };

/* Only use this if fixture message looks something like:
    Fixture {
        FixtureMetadata metadata = 1;
        Context input = 2;
        Effects output = 3;
    }
    Specifically, the input/context and output/effects fields are named "input" and "output"
    and are tagged 2 and 3 respectively.
*/
#define GEN_HARNESS_CTX( harness_name, fixture_type, effects_msgname ) \
    GEN_HARNESS_CTX_EX( harness_name, &fixture_type ##_msg, 2, 3, &EXPAND_CONCAT(EVAL(fixture_type##_input_MSGTYPE), _msg), & EXPAND_CONCAT(EVAL(fixture_type##_output_MSGTYPE), _msg), effects_msgname )


#endif
