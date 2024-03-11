#include "../fd_ballet.h"
#include "fd_pack.h"
#include "fd_compute_budget_program.h"
#include "../txn/fd_txn.h"
#include "../base58/fd_base58.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../util/sanitize/fd_fuzz.h"
#include <math.h>
#include <assert.h>


// FD_IMPORT_BINARY( sample_vote, "src/ballet/pack/sample_vote.bin" );
// #define SAMPLE_VOTE_COST (3435UL)

#define MAX_TEST_TXNS (1024UL)
#define DUMMY_PAYLOAD_MAX_SZ (FD_TXN_ACCT_ADDR_SZ * 256UL + 64UL)
#define PACK_SCRATCH_SZ (272UL*1024UL*1024UL)
#define SET_NAME aset
#include "../../util/tmpl/fd_smallset.c"
uchar txn_scratch[MAX_TEST_TXNS][FD_TXN_MAX_SZ];
uchar payload_scratch[MAX_TEST_TXNS][DUMMY_PAYLOAD_MAX_SZ];
ulong payload_sz[MAX_TEST_TXNS];
uchar pack_scratch[PACK_SCRATCH_SZ] __attribute__((aligned(128)));
uchar metrics_scratch[FD_METRICS_FOOTPRINT(0, 0)]
    __attribute__((aligned(FD_METRICS_ALIGN)));
const char SIGNATURE_SUFFIX[FD_TXN_SIGNATURE_SZ - sizeof(ulong) -
                            sizeof(uint)] =
    ": this is the fake signature of transaction number ";
const char WORK_PROGRAM_ID[FD_TXN_ACCT_ADDR_SZ] =
    "Work Program Id Consumes 1<<j CU";


struct pack_outcome {
    ulong microblock_cnt;
    aset_t r_accts_in_use[FD_PACK_MAX_BANK_TILES];
    aset_t w_accts_in_use[FD_PACK_MAX_BANK_TILES];
    fd_txn_p_t results[1024];
};
typedef struct pack_outcome pack_outcome_t;

pack_outcome_t outcome;
fd_pack_t *pack;

/* Makes enough of a transaction to schedule that reads one account for
   each character in reads and writes one account for each character in
   writes.  The characters before the nul-terminator in reads and writes
   should be in [0x30, 0x70), basically numbers and uppercase letters.
   Adds a unique signer.  Packing should estimate compute usage near the
   specified value.  Fee will be set to 5^priority, so that even with a
   large stall, it should still schedule in decreasing priority order.
   priority should be in (0, 13.5].  Stores the created transaction in
   txn_scratch[ i ] and payload_scratch[ i ].  Returns the priority fee
   in lamports. */
static ulong
make_transaction(ulong i,
                 uint compute,
                 double priority, char const *writes, char const *reads)
{
    uchar *p = payload_scratch[i];
    uchar *p_base = p;
    fd_txn_t *t = (fd_txn_t *) txn_scratch[i];

    *(p++) = (uchar) 1;
    fd_memcpy(p, &i, sizeof(ulong));
    fd_memcpy(p + sizeof(ulong), SIGNATURE_SUFFIX,
              FD_TXN_SIGNATURE_SZ - sizeof(ulong) - sizeof(uint));
    fd_memcpy(p + FD_TXN_SIGNATURE_SZ - sizeof(ulong), &compute,
              sizeof(uint));
    p += FD_TXN_SIGNATURE_SZ;
    t->transaction_version = FD_TXN_VLEGACY;
    t->signature_cnt = 1;
    t->signature_off = 1;
    t->message_off = FD_TXN_SIGNATURE_SZ + 1UL;
    t->readonly_signed_cnt = 0;
    ulong programs_to_include = 2UL;    /* 1 for compute budget, 1 for "work" program */
    t->readonly_unsigned_cnt =
        (uchar) (strlen(reads) + programs_to_include);
    t->acct_addr_cnt =
        (ushort) (1UL + strlen(reads) + programs_to_include +
                  strlen(writes));

    t->acct_addr_off = FD_TXN_SIGNATURE_SZ + 1UL;

    /* Add the signer */
    *p = 's' + 0x80;
    fd_memcpy(p + 1, &i, sizeof(ulong));
    memset(p + 9, 'S', 32 - 9);
    p += FD_TXN_ACCT_ADDR_SZ;
    /* Add the writable accounts */
    for (ulong i = 0UL; writes[i] != '\0'; i++) {
        memset(p, writes[i], FD_TXN_ACCT_ADDR_SZ);
        p += FD_TXN_ACCT_ADDR_SZ;
    }
    /* Add the compute budget */
    fd_memcpy(p, FD_COMPUTE_BUDGET_PROGRAM_ID, FD_TXN_ACCT_ADDR_SZ);
    p += FD_TXN_ACCT_ADDR_SZ;
    /* Add the work program */
    fd_memcpy(p, WORK_PROGRAM_ID, FD_TXN_ACCT_ADDR_SZ);
    p += FD_TXN_ACCT_ADDR_SZ;
    /* Add the readonly accounts */
    for (ulong i = 0UL; reads[i] != '\0'; i++) {
        memset(p, reads[i], FD_TXN_ACCT_ADDR_SZ);
        p += FD_TXN_ACCT_ADDR_SZ;
    }

    t->recent_blockhash_off = 0;
    t->addr_table_lookup_cnt = 0;
    t->addr_table_adtl_writable_cnt = 0;
    t->addr_table_adtl_cnt = 0;
    t->instr_cnt = (ushort) (1UL + (ulong) fd_uint_popcnt(compute));

    uchar prog_start = (uchar) (1UL + strlen(writes));

    t->instr[0].program_id = prog_start;
    t->instr[0].acct_cnt = 0;
    t->instr[0].data_sz = 9;
    t->instr[0].acct_off = (ushort) (p - p_base);
    t->instr[0].data_off = (ushort) (p - p_base);


    /* Write instruction data */
    uint rewards = (uint) pow(5.0, priority);
    *p = '\0';
    fd_memcpy(p + 1, &compute, sizeof(uint));
    fd_memcpy(p + 5, &rewards, sizeof(uint));
    p += 9UL;

    ulong j = 1UL;
    for (uint i = 0U; i < 32U; i++) {
        if (compute & (1U << i)) {
            *p = (uchar) i;
            t->instr[j].program_id = (uchar) (prog_start + 1);
            t->instr[j].acct_cnt = 0;
            t->instr[j].data_sz = 1;
            t->instr[j].acct_off = (ushort) (p - p_base);
            t->instr[j].data_off = (ushort) (p - p_base);
            j++;
            p++;
        }
    }
    assert(p >= p_base);
    payload_sz[i] = (ulong) (p - p_base);
    return rewards;
}

static void insert(ulong i, fd_pack_t * pack)
{
    fd_txn_p_t *slot = fd_pack_insert_txn_init(pack);
    fd_txn_t *txn = (fd_txn_t *) txn_scratch[i];
    slot->payload_sz = payload_sz[i];
    fd_memcpy(slot->payload, payload_scratch[i], payload_sz[i]);
    fd_memcpy(TXN(slot), txn,
              fd_txn_footprint(txn->instr_cnt,
                               txn->addr_table_lookup_cnt));

    fd_pack_insert_txn_fini(pack, slot, i);
}

static void
schedule_validate_microblock(fd_pack_t * pack,
                             ulong total_cus,
                             float vote_fraction,
                             ulong min_txns,
                             ulong min_rewards,
                             ulong bank_tile, pack_outcome_t * outcome)
{

    ulong pre_txn_cnt = fd_pack_avail_txn_cnt(pack);
    fd_pack_microblock_complete(pack, bank_tile);
    ulong txn_cnt =
        fd_pack_schedule_next_microblock(pack, total_cus, vote_fraction,
                                         bank_tile, outcome->results);
    ulong post_txn_cnt = fd_pack_avail_txn_cnt(pack);

#if DETAILED_STATUS_MESSAGES
    FD_LOG_NOTICE(("Scheduling microblock. %lu avail -> %lu avail. %lu scheduled", pre_txn_cnt, post_txn_cnt, txn_cnt));
#endif

    if (!(txn_cnt >= min_txns)) {
        return;
    }                         
    FD_TEST(pre_txn_cnt - post_txn_cnt == txn_cnt);

    ulong total_rewards = 0UL;

    aset_t read_accts = aset_null();
    aset_t write_accts = aset_null();

    for (ulong i = 0UL; i < txn_cnt; i++) {
        fd_txn_p_t *txnp = outcome->results + i;
        fd_txn_t *txn = TXN(txnp);

        fd_compute_budget_program_state_t cbp;
        fd_compute_budget_program_init(&cbp);

        ulong rewards = 0UL;
        uint compute = 0U;
        if (FD_LIKELY(txn->instr_cnt > 1UL)) {
            fd_txn_instr_t ix = txn->instr[0];  /* For these transactions, the compute budget instr is always the 1st */
            FD_TEST(fd_compute_budget_program_parse
                    (txnp->payload + ix.data_off, ix.data_sz, &cbp));
            fd_compute_budget_program_finalize(&cbp, txn->instr_cnt,
                                               &rewards, &compute);
        }                       /* else it's a vote */

        total_rewards += rewards;

        fd_acct_addr_t const *acct =
            fd_txn_get_acct_addrs(txn, txnp->payload);
        fd_txn_acct_iter_t ctrl[1];
        for (ulong j =
             fd_txn_acct_iter_init(txn,
                                   FD_TXN_ACCT_CAT_WRITABLE_NONSIGNER_IMM,
                                   ctrl); j < fd_txn_acct_iter_end();
             j = fd_txn_acct_iter_next(j, ctrl)) {
            uchar b0 = acct[j].b[0];
            uchar b1 = acct[j].b[1];
            if ((0x30UL <= b0) & (b0 < 0x70UL) & (b0 == b1)) {
                FD_TEST(!aset_test(write_accts, (ulong) b0 - 0x30));
                write_accts =
                    aset_insert(write_accts, (ulong) b0 - 0x30UL);
            }
        }
        for (ulong j =
             fd_txn_acct_iter_init(txn,
                                   FD_TXN_ACCT_CAT_READONLY_NONSIGNER_IMM,
                                   ctrl); j < fd_txn_acct_iter_end();
             j = fd_txn_acct_iter_next(j, ctrl)) {
            uchar b0 = acct[j].b[0];
            uchar b1 = acct[j].b[1];
            if ((0x30UL <= b0) & (b0 < 0x70UL) & (b0 == b1))
                read_accts = aset_insert(read_accts, (ulong) b0 - 0x30UL);
        }
    }

    if (!(total_rewards >= min_rewards)) {
        return;
    }                           //todo make sure this is sane

    FD_TEST(aset_is_null(aset_intersect(read_accts, write_accts)));

    /* Check for conflict with microblocks on other bank tiles */
    for (ulong i = 0UL; i < fd_pack_bank_tile_cnt(pack); i++) {
        if (i == bank_tile)
            continue;

        FD_TEST(aset_is_null
                (aset_intersect(write_accts, outcome->r_accts_in_use[i])));
        FD_TEST(aset_is_null
                (aset_intersect(write_accts, outcome->w_accts_in_use[i])));
        FD_TEST(aset_is_null
                (aset_intersect(read_accts, outcome->w_accts_in_use[i])));
    }
    outcome->r_accts_in_use[bank_tile] = read_accts;
    outcome->w_accts_in_use[bank_tile] = write_accts;

    outcome->microblock_cnt++;
}

int LLVMFuzzerInitialize(int *pargc, char ***pargv)
{
    /* Set up shell without signal handlers */
    putenv("FD_LOG_BACKTRACE=0");
    fd_boot(pargc, pargv);
    // init_all from test_pack.c
    // metrics! need your metrics!
    fd_metrics_register((ulong *)
                        fd_metrics_new(metrics_scratch, 0UL, 0UL));


#define MAX_BANKING_THREADS 1

    outcome.microblock_cnt = 0UL;
    for (ulong i = 0UL; i < FD_PACK_MAX_BANK_TILES; i++) {
        outcome.r_accts_in_use[i] = aset_null();
        outcome.w_accts_in_use[i] = aset_null();
    }

    //init_all inlined :) 
    atexit(fd_halt);
    return 0;
}

int LLVMFuzzerTestOneInput(uchar const *data, ulong data_sz)
{

    ulong s = data_sz;
    uchar const *ptr = data;

    if (s < 100UL)
        return -1;
    ulong pack_depth = 1024UL;
    ulong gap = 1UL;
    ulong max_txn_per_microblock = 30UL;
    ulong footprint =
        fd_pack_footprint(pack_depth, gap, max_txn_per_microblock);

    fd_rng_t _rng[1];
    fd_rng_t *rng = fd_rng_join(fd_rng_new(_rng, 0U, 0UL));

    if (footprint > PACK_SCRATCH_SZ)
        FD_LOG_ERR(("Test required %lu bytes, but scratch was only %lu",
                    footprint, PACK_SCRATCH_SZ));
#if DETAILED_STATUS_MESSAGES
    else
        FD_LOG_NOTICE(("Test required %lu bytes of %lu available bytes",
                       footprint, PACK_SCRATCH_SZ));
#endif

    void *_mem =
        fd_pack_new(pack_scratch, pack_depth, gap, max_txn_per_microblock,
                    MAX_TEST_TXNS, rng);
    fd_rng_delete(fd_rng_leave(rng));
    assert(_mem != NULL);
    pack = fd_pack_join(_mem);
    assert(pack);
    uint rewards = 0UL;
// decide how many of which type of operations to perform
    uint insert_idx = 0UL;
    uint32_t arr[1024];

    while (insert_idx < 1000) {
        if (s < 5) {
            break;
        }
        uint8_t firstThreeBytes[3] = { ptr[0], ptr[1], ptr[2] };
        ptr += 3;
        s -= 3;
        for (int i = 0; i < 3; i++) {
            for (int j = 0; j < 8; j++) {
                int bit = (firstThreeBytes[i] >> j) & 1;
                if (bit) {
                    if (s < 5) {
                        break;
                    }

                    const char *acc1 = "D";
                    const char *acc2 = "U";
                    // Add insert operation
                    rewards +=
                        make_transaction(insert_idx, (uint) ptr[0],
                                         (double) ptr[1], acc1, acc2);
                    // printf("rewards: %d\n", rewards);
                    // free((void *) acc1);
                    // free((void *) acc2);
                    ptr += 5;
                    s -= 5;
                    insert(insert_idx++, pack);
                    arr[insert_idx] = insert_idx;


                } else {
                  // todo actually help it delete txns
                    fd_ed25519_sig_t const *sig = fd_txn_get_signatures((fd_txn_t *) txn_scratch[insert_idx], payload_scratch);
                    int d = fd_pack_delete_transaction(pack, sig);
                }
            }
            schedule_validate_microblock(pack, 30000UL, 0.0f, 1, rewards,
                                     0UL, &outcome);
        }

    }

    fd_pack_end_block(pack);
    rewards = 0;
    // rewards = 0UL;
    return 0;
}
