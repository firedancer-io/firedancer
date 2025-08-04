#include "fd_ssmanifest_parser.h"

#include "fd_ssmsg.h"

#include "../../../util/log/fd_log.h"

struct acc_vec_key {
  ulong slot;
  ulong id;
};

typedef struct acc_vec_key acc_vec_key_t;

struct acc_vec {
  acc_vec_key_t key;
  ulong         file_sz;

  ulong         map_next;
  ulong         map_prev;

  ulong         pool_next;
};

typedef struct acc_vec acc_vec_t;

#define POOL_NAME  acc_vec_pool
#define POOL_T     acc_vec_t
#define POOL_NEXT  pool_next
#define POOL_IDX_T ulong

#include "../../../util/tmpl/fd_pool.c"

#define MAP_NAME          acc_vec_map
#define MAP_ELE_T         acc_vec_t
#define MAP_KEY_T         acc_vec_key_t
#define MAP_KEY           key
#define MAP_IDX_T         ulong
#define MAP_NEXT          map_next
#define MAP_PREV          map_prev
#define MAP_KEY_HASH(k,s) fd_hash( s, k, sizeof(acc_vec_key_t) )
#define MAP_KEY_EQ(k0,k1) ( ((k0)->slot==(k1)->slot) && ((k0)->id==(k1)->id) )

#include "../../../util/tmpl/fd_map_chain.c"

#define SSMANIFEST_DEBUG 0

#define STATE_BLOCKHASH_QUEUE_LAST_HASH_INDEX                                                         (  0)
#define STATE_BLOCKHASH_QUEUE_LAST_HASH_OPTION                                                        (  1)
#define STATE_BLOCKHASH_QUEUE_LAST_HASH                                                               (  2)
#define STATE_BLOCKHASH_QUEUE_AGES_LENGTH                                                             (  3)
#define STATE_BLOCKHASH_QUEUE_AGES_HASH                                                               (  4)
#define STATE_BLOCKHASH_QUEUE_AGES_LAMPORTS_PER_SIGNATURE                                             (  5)
#define STATE_BLOCKHASH_QUEUE_AGES_HASH_INDEX                                                         (  6)
#define STATE_BLOCKHASH_QUEUE_AGES_TIMESTAMP                                                          (  7)
#define STATE_BLOCKHASH_QUEUE_MAX_AGE                                                                 (  8)
#define STATE_ANCESTORS_LENGTH                                                                        (  9)
#define STATE_ANCESTORS                                                                               ( 10)
#define STATE_HASH                                                                                    ( 11)
#define STATE_PARENT_HASH                                                                             ( 12)
#define STATE_PARENT_SLOT                                                                             ( 13)
#define STATE_HARD_FORKS_LENGTH                                                                       ( 14)
#define STATE_HARD_FORKS_SLOT                                                                         ( 15)
#define STATE_HARD_FORKS_VAL                                                                          ( 16)
#define STATE_TRANSACTION_COUNT                                                                       ( 17)
#define STATE_TICK_HEIGHT                                                                             ( 18)
#define STATE_SIGNATURE_COUNT                                                                         ( 19)
#define STATE_CAPITALIZATION                                                                          ( 20)
#define STATE_MAX_TICK_HEIGHT                                                                         ( 21)
#define STATE_HASHES_PER_TICK_OPTION                                                                  ( 22)
#define STATE_HASHES_PER_TICK                                                                         ( 23)
#define STATE_TICKS_PER_SLOT                                                                          ( 24)
#define STATE_NS_PER_SLOT                                                                             ( 25)
#define STATE_GENSIS_CREATION_TIME                                                                    ( 26)
#define STATE_SLOTS_PER_YEAR                                                                          ( 27)
#define STATE_ACCOUNTS_DATA_LEN                                                                       ( 28)
#define STATE_SLOT                                                                                    ( 29)
#define STATE_EPOCH                                                                                   ( 30)
#define STATE_BLOCK_HEIGHT                                                                            ( 31)
#define STATE_COLLECTOR_ID                                                                            ( 32)
#define STATE_COLLECTOR_FEES                                                                          ( 33)
#define STATE_FEE_COLLECTOR_LAMPORTS_PER_SIGNATURE                                                    ( 34)
#define STATE_FEE_RATE_GOVERNOR_TARGET_LAMPORTS_PER_SIGNATURE                                         ( 35)
#define STATE_FEE_RATE_GOVERNOR_TARGET_SIGNATURES_PER_SLOT                                            ( 36)
#define STATE_FEE_RATE_GOVERNOR_MIN_LAMPORTS_PER_SIGNATURE                                            ( 37)
#define STATE_FEE_RATE_GOVERNOR_MAX_LAMPORTS_PER_SIGNATURE                                            ( 38)
#define STATE_FEE_RATE_GOVERNOR_BURN_PERCENT                                                          ( 39)
#define STATE_COLLECTED_RENT                                                                          ( 40)
#define STATE_RENT_COLLECTOR_EPOCH                                                                    ( 41)
#define STATE_RENT_COLLECTOR_EPOCH_SCHEDULE_SLOTS_PER_EPOCH                                           ( 42)
#define STATE_RENT_COLLECTOR_EPOCH_SCHEDULE_LEADER_SCHEDULE_SLOT_OFFSET                               ( 43)
#define STATE_RENT_COLLECTOR_EPOCH_SCHEDULE_WARMUP                                                    ( 44)
#define STATE_RENT_COLLECTOR_EPOCH_SCHEDULE_FIRST_NORMAL_EPOCH                                        ( 45)
#define STATE_RENT_COLLECTOR_EPOCH_SCHEDULE_FIRST_NORMAL_SLOT                                         ( 46)
#define STATE_RENT_COLLECTOR_SLOTS_PER_YEAR                                                           ( 47)
#define STATE_RENT_COLLECTOR_RENT_LAMPORTS_PER_UINT8_YEAR                                             ( 48)
#define STATE_RENT_COLLECTOR_RENT_EXEMPTION_THRESHOLD                                                 ( 49)
#define STATE_RENT_COLLECTOR_RENT_BURN_PERCENT                                                        ( 50)
#define STATE_EPOCH_SCHEDULE_SLOTS_PER_EPOCH                                                          ( 51)
#define STATE_EPOCH_SCHEDULE_LEADER_SCHEDULE_SLOT_OFFSET                                              ( 52)
#define STATE_EPOCH_SCHEDULE_WARMUP                                                                   ( 53)
#define STATE_EPOCH_SCHEDULE_FIRST_NORMAL_EPOCH                                                       ( 54)
#define STATE_EPOCH_SCHEDULE_FIRST_NORMAL_SLOT                                                        ( 55)
#define STATE_INFLATION_INITIAL                                                                       ( 56)
#define STATE_INFLATION_TERMINAL                                                                      ( 57)
#define STATE_INFLATION_TAPER                                                                         ( 58)
#define STATE_INFLATION_FOUNDATION                                                                    ( 59)
#define STATE_INFLATION_FOUNDATION_TERM                                                               ( 60)
#define STATE_INFLATION_UNUSED                                                                        ( 61)
#define STATE_STAKES_VOTE_ACCOUNTS_LENGTH                                                             ( 62)
#define STATE_STAKES_VOTE_ACCOUNTS_KEY                                                                ( 63)
#define STATE_STAKES_VOTE_ACCOUNTS_STAKE                                                              ( 64)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_LAMPORTS                                                     ( 65)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_LENGTH                                                  ( 66)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_VARIANT                                                 ( 67)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_NODE_PUBKEY                                     ( 68)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_AUTHORIZED_WITHDRAWER                           ( 69)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_COMMISSION                                      ( 70)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_VOTES_LENGTH                                    ( 71)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_VOTES                                           ( 72)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_ROOT_SLOT_OPTION                                ( 73)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_ROOT_SLOT                                       ( 74)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_AUTHORIZED_VOTERS_LENGTH                        ( 75)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_AUTHORIZED_VOTERS                               ( 76)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_PRIOR_VOTERS                                    ( 77)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_EPOCH_CREDITS_LENGTH                            ( 78)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_EPOCH_CREDITS                                   ( 79)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_LAST_TIMESTAMP_SLOT                             ( 80)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_LAST_TIMESTAMP_TIMESTAMP                        ( 81)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_NODE_PUBKEY                                      ( 82)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_AUTHORIZED_WITHDRAWER                            ( 83)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_COMMISSION                                       ( 84)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_VOTES_LENGTH                                     ( 85)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_VOTES                                            ( 86)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_ROOT_SLOT_OPTION                                 ( 87)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_ROOT_SLOT                                        ( 88)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_AUTHORIZED_VOTERS_LENGTH                         ( 89)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_AUTHORIZED_VOTERS                                ( 90)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_PRIOR_VOTERS                                     ( 91)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_EPOCH_CREDITS_LENGTH                             ( 92)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_EPOCH_CREDITS                                    ( 93)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_LAST_TIMESTAMP_SLOT                              ( 94)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_LAST_TIMESTAMP_TIMESTAMP                         ( 95)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_NODE_PUBKEY                                       ( 96)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_AUTHORIZED_VOTER                                  ( 97)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_AUTHORIZED_VOTER_EPOCH                            ( 98)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_PRIOR_VOTERS                                      ( 99)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_AUTHORIZED_WITHDRAWER                             (100)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_COMMISSION                                        (101)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_VOTES_LENGTH                                      (102)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_VOTES                                             (103)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_ROOT_SLOT_OPTION                                  (104)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_ROOT_SLOT                                         (105)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_EPOCH_CREDITS_LENGTH                              (106)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_EPOCH_CREDITS                                     (107)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_LAST_TIMESTAMP_SLOT                               (108)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_LAST_TIMESTAMP_TIMESTAMP                          (109)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_DUMMY                                                   (110)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_OWNER                                                        (111)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_EXECUTABLE                                                   (112)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_RENT_EPOCH                                                   (113)
#define STATE_STAKES_STAKE_DELEGATIONS_LENGTH                                                         (114)
#define STATE_STAKES_STAKE_DELEGATIONS_KEY                                                            (115)
#define STATE_STAKES_STAKE_DELEGATIONS_VOTER_PUBKEY                                                   (116)
#define STATE_STAKES_STAKE_DELEGATIONS_STAKE                                                          (117)
#define STATE_STAKES_STAKE_DELEGATIONS_ACTIVATION_EPOCH                                               (118)
#define STATE_STAKES_STAKE_DELEGATIONS_DEACTIVATION_EPOCH                                             (119)
#define STATE_STAKES_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE                                           (120)
#define STATE_STAKES_UNUSED                                                                           (121)
#define STATE_STAKES_EPOCH                                                                            (122)
#define STATE_STAKES_STAKE_HISTORY_LENGTH                                                             (123)
#define STATE_STAKES_STAKE_HISTORY                                                                    (124)
#define STATE_UNUSED_ACCOUNTS1_LENGTH                                                                 (125)
#define STATE_UNUSED_ACCOUNTS1_UNUSED                                                                 (126)
#define STATE_UNUSED_ACCOUNTS2_LENGTH                                                                 (127)
#define STATE_UNUSED_ACCOUNTS2_UNUSED                                                                 (128)
#define STATE_UNUSED_ACCOUNTS3_LENGTH                                                                 (129)
#define STATE_UNUSED_ACCOUNTS3_UNUSED                                                                 (130)
#define STATE_EPOCH_STAKES_LENGTH                                                                     (131)
#define STATE_EPOCH_STAKES_KEY                                                                        (132)
#define STATE_EPOCH_STAKES_VOTE_ACCOUNTS_LENGTH                                                       (133)
#define STATE_EPOCH_STAKES_VOTE_ACCOUNTS_KEY                                                          (134)
#define STATE_EPOCH_STAKES_VOTE_ACCOUNTS_STAKE                                                        (135)
#define STATE_EPOCH_STAKES_VOTE_ACCOUNTS_VALUE_LAMPORTS                                               (136)
#define STATE_EPOCH_STAKES_VOTE_ACCOUNTS_VALUE_DATA_LENGTH                                            (137)
#define STATE_EPOCH_STAKES_VOTE_ACCOUNTS_VALUE_DATA                                                   (138)
#define STATE_EPOCH_STAKES_VOTE_ACCOUNTS_VALUE_OWNER                                                  (139)
#define STATE_EPOCH_STAKES_VOTE_ACCOUNTS_VALUE_EXECUTABLE                                             (140)
#define STATE_EPOCH_STAKES_VOTE_ACCOUNTS_VALUE_RENT_EPOCH                                             (141)
#define STATE_EPOCH_STAKES_STAKE_DELEGATIONS_LENGTH                                                   (142)
#define STATE_EPOCH_STAKES_STAKE_DELEGATIONS_KEY                                                      (143)
#define STATE_EPOCH_STAKES_STAKE_DELEGATIONS_VOTER_PUBKEY                                             (144)
#define STATE_EPOCH_STAKES_STAKE_DELEGATIONS_STAKE                                                    (145)
#define STATE_EPOCH_STAKES_STAKE_DELEGATIONS_ACTIVATION_EPOCH                                         (146)
#define STATE_EPOCH_STAKES_STAKE_DELEGATIONS_DEACTIVATION_EPOCH                                       (147)
#define STATE_EPOCH_STAKES_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE                                     (148)
#define STATE_EPOCH_STAKES_UNUSED                                                                     (149)
#define STATE_EPOCH_STAKES_EPOCH                                                                      (150)
#define STATE_EPOCH_STAKES_STAKE_HISTORY_LENGTH                                                       (151)
#define STATE_EPOCH_STAKES_STAKE_HISTORY                                                              (152)
#define STATE_EPOCH_STAKES_TOTAL_STAKE                                                                (153)
#define STATE_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_LENGTH                                            (154)
#define STATE_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_KEY                                               (155)
#define STATE_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_VOTE_ACCOUNTS_LENGTH                              (156)
#define STATE_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_VOTE_ACCOUNTS                                     (157)
#define STATE_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_TOTAL_STAKE                                       (158)
#define STATE_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS_LENGTH                                             (159)
#define STATE_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS                                                    (160)
#define STATE_IS_DELTA                                                                                (161)
#define STATE_ACCOUNTS_DB_STORAGES_LENGTH                                                             (162)
#define STATE_ACCOUNTS_DB_STORAGES_SLOT                                                               (163)
#define STATE_ACCOUNTS_DB_STORAGES_ACCOUNT_VECS_LENGTH                                                (164)
#define STATE_ACCOUNTS_DB_STORAGES_ACCOUNT_VECS_ID                                                    (165)
#define STATE_ACCOUNTS_DB_STORAGES_ACCOUNT_VECS_FILE_SZ                                               (166)
#define STATE_ACCOUNTS_DB_STORAGES_DUMMY                                                              (167)
#define STATE_ACCOUNTS_DB_VERSION                                                                     (168)
#define STATE_ACCOUNTS_DB_SLOT                                                                        (169)
#define STATE_ACCOUNTS_DB_BANK_HASH_INFO_ACCOUNTS_DELTA_HASH                                          (170)
#define STATE_ACCOUNTS_DB_BANK_HASH_INFO_ACCOUNTS_HASH                                                (171)
#define STATE_ACCOUNTS_DB_BANK_HASH_INFO_STATS_NUM_UPDATED_ACCOUNTS                                   (172)
#define STATE_ACCOUNTS_DB_BANK_HASH_INFO_STATS_NUM_REMOVED_ACCOUNTS                                   (173)
#define STATE_ACCOUNTS_DB_BANK_HASH_INFO_STATS_NUM_LAMPORTS_STORED                                    (174)
#define STATE_ACCOUNTS_DB_BANK_HASH_INFO_STATS_TOTAL_DATA_LEN                                         (175)
#define STATE_ACCOUNTS_DB_BANK_HASH_INFO_STATS_NUM_EXECUTABLE_ACCOUNTS                                (176)
#define STATE_ACCOUNTS_DB_HISTORICAL_ROOTS_LENGTH                                                     (177)
#define STATE_ACCOUNTS_DB_HISTORICAL_ROOTS                                                            (178)
#define STATE_ACCOUNTS_DB_HISTORICAL_WITH_HASH_LENGTH                                                 (179)
#define STATE_ACCOUNTS_DB_HISTORICAL_WITH_HASH                                                        (180)
#define STATE_LAMPORTS_PER_SIGNATURE                                                                  (181)
#define STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_OPTION                                            (182)
#define STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_FULL_SLOT                                         (183)
#define STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_FULL_HASH                                         (184)
#define STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_FULL_CAPITALIZATION                               (185)
#define STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_INCREMENTAL_HASH                                  (186)
#define STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_INCREMENTAL_CAPITALIZATION                        (187)
#define STATE_EPOCH_ACCOUNT_HASH_OPTION                                                               (188)
#define STATE_EPOCH_ACCOUNT_HASH                                                                      (189)
#define STATE_VERSIONED_EPOCH_STAKES_LENGTH                                                           (190)
#define STATE_VERSIONED_EPOCH_STAKES_EPOCH                                                            (191)
#define STATE_VERSIONED_EPOCH_STAKES_VARIANT                                                          (192)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_LENGTH                                      (193)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_KEY                                         (194)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_STAKE                                       (195)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_LAMPORTS                              (196)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_LENGTH                           (197)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_VARIANT                          (198)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_NODE_PUBKEY              (199)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_AUTHORIZED_WITHDRAWER    (200)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_COMMISSION               (201)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_VOTES_LENGTH             (202)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_VOTES                    (203)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_ROOT_SLOT_OPTION         (204)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_ROOT_SLOT                (205)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_AUTHORIZED_VOTERS_LENGTH (206)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_AUTHORIZED_VOTERS        (207)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_PRIOR_VOTERS             (208)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_EPOCH_CREDITS_LENGTH     (209)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_EPOCH_CREDITS            (210)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_LAST_TIMESTAMP_SLOT      (211)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_LAST_TIMESTAMP_TIMESTAMP (212)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_NODE_PUBKEY               (213)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_AUTHORIZED_WITHDRAWER     (214)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_COMMISSION                (215)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_VOTES_LENGTH              (216)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_VOTES                     (217)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_ROOT_SLOT_OPTION          (218)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_ROOT_SLOT                 (219)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_AUTHORIZED_VOTERS_LENGTH  (220)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_AUTHORIZED_VOTERS         (221)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_PRIOR_VOTERS              (222)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_EPOCH_CREDITS_LENGTH      (223)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_EPOCH_CREDITS             (224)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_LAST_TIMESTAMP_SLOT       (225)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_LAST_TIMESTAMP_TIMESTAMP  (226)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_NODE_PUBKEY                (227)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_AUTHORIZED_VOTER           (228)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_AUTHORIZED_VOTER_EPOCH     (229)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_PRIOR_VOTERS               (230)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_AUTHORIZED_WITHDRAWER      (231)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_COMMISSION                 (232)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_VOTES_LENGTH               (233)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_VOTES                      (234)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_ROOT_SLOT_OPTION           (235)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_ROOT_SLOT                  (236)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_EPOCH_CREDITS_LENGTH       (237)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_EPOCH_CREDITS              (238)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_LAST_TIMESTAMP_SLOT        (239)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_LAST_TIMESTAMP_TIMESTAMP   (240)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_DUMMY                            (241)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_OWNER                                 (242)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_EXECUTABLE                            (243)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_RENT_EPOCH                            (244)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_LENGTH                                  (245)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_KEY                                     (246)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_VOTER_PUBKEY                            (247)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_STAKE                                   (248)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_ACTIVATION_EPOCH                        (249)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_DEACTIVATION_EPOCH                      (250)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE                    (251)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_CREDITS_OBSERVED                        (252)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_UNUSED                                                    (253)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_EPOCH                                                     (254)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_HISTORY_LENGTH                                      (255)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_HISTORY                                             (256)
#define STATE_VERSIONED_EPOCH_STAKES_TOTAL_STAKE                                                      (257)
#define STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_LENGTH                                  (258)
#define STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_KEY                                     (259)
#define STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_VOTE_ACCOUNTS_LENGTH                    (260)
#define STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_VOTE_ACCOUNTS                           (261)
#define STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_TOTAL_STAKE                             (262)
#define STATE_VERSIONED_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS_LENGTH                                   (263)
#define STATE_VERSIONED_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS                                          (264)
#define STATE_LTHASH_OPTION                                                                           (265)
#define STATE_LTHASH                                                                                  (266)
#define STATE_DONE                                                                                    (267)

struct fd_ssmanifest_parser_private {
  int     state;
  ulong   off;
  uchar * dst;
  ulong   dst_cur;
  ulong   dst_sz;

  uchar   option;
  uint    variant;

  ulong   idx1;
  ulong   idx2;
  ulong   length1;
  ulong   length2;
  ulong   length3;
  ulong   length4;

  ulong   epoch_stakes_len;
  ulong   epoch;
  ulong   epoch_stakes_epoch;
  ulong   epoch_idx;

  ulong   account_data_start;

  ulong acc_vec_slot;
  ulong acc_vec_id;
  ulong acc_vec_file_sz;

  ulong max_acc_vecs;
  ulong seed;

  acc_vec_map_t * acc_vec_map;
  acc_vec_t *     acc_vec_pool;

  fd_snapshot_manifest_t * manifest;
};

static inline ulong
state_size( fd_ssmanifest_parser_t * parser ) {
  ulong length1 = parser->length1;
  ulong length2 = parser->length2;
  ulong length3 = parser->length3;
  ulong length4 = parser->length4;

  switch( parser->state ) {
    case STATE_BLOCKHASH_QUEUE_LAST_HASH_INDEX:                                                               return 8UL         ;
    case STATE_BLOCKHASH_QUEUE_LAST_HASH_OPTION:                                                              return 1UL         ;
    case STATE_BLOCKHASH_QUEUE_LAST_HASH:                                                                     return 32UL        ;
    case STATE_BLOCKHASH_QUEUE_AGES_LENGTH:                                                                   return 8UL         ;
    case STATE_BLOCKHASH_QUEUE_AGES_HASH:                                                                     return 32UL        ;
    case STATE_BLOCKHASH_QUEUE_AGES_LAMPORTS_PER_SIGNATURE:                                                   return 8UL         ;
    case STATE_BLOCKHASH_QUEUE_AGES_HASH_INDEX:                                                               return 8UL         ;
    case STATE_BLOCKHASH_QUEUE_AGES_TIMESTAMP:                                                                return 8UL         ;
    case STATE_BLOCKHASH_QUEUE_MAX_AGE:                                                                       return 8UL         ;
    case STATE_ANCESTORS_LENGTH:                                                                              return 8UL         ;
    case STATE_ANCESTORS:                                                                                     return 16UL*length1;
    case STATE_HASH:                                                                                          return 32UL        ;
    case STATE_PARENT_HASH:                                                                                   return 32UL        ;
    case STATE_PARENT_SLOT:                                                                                   return 8UL         ;
    case STATE_HARD_FORKS_LENGTH:                                                                             return 8UL         ;
    case STATE_HARD_FORKS_SLOT:                                                                               return 8UL         ;
    case STATE_HARD_FORKS_VAL:                                                                                return 8UL         ;
    case STATE_TRANSACTION_COUNT:                                                                             return 8UL         ;
    case STATE_TICK_HEIGHT:                                                                                   return 8UL         ;
    case STATE_SIGNATURE_COUNT:                                                                               return 8UL         ;
    case STATE_CAPITALIZATION:                                                                                return 8UL         ;
    case STATE_MAX_TICK_HEIGHT:                                                                               return 8UL         ;
    case STATE_HASHES_PER_TICK_OPTION:                                                                        return 1UL         ;
    case STATE_HASHES_PER_TICK:                                                                               return 8UL         ;
    case STATE_TICKS_PER_SLOT:                                                                                return 8UL         ;
    case STATE_NS_PER_SLOT:                                                                                   return 16UL        ;
    case STATE_GENSIS_CREATION_TIME:                                                                          return 8UL         ;
    case STATE_SLOTS_PER_YEAR:                                                                                return 8UL         ;
    case STATE_ACCOUNTS_DATA_LEN:                                                                             return 8UL         ;
    case STATE_SLOT:                                                                                          return 8UL         ;
    case STATE_EPOCH:                                                                                         return 8UL         ;
    case STATE_BLOCK_HEIGHT:                                                                                  return 8UL         ;
    case STATE_COLLECTOR_ID:                                                                                  return 32UL        ;
    case STATE_COLLECTOR_FEES:                                                                                return 8UL         ;
    case STATE_FEE_COLLECTOR_LAMPORTS_PER_SIGNATURE:                                                          return 8UL         ;
    case STATE_FEE_RATE_GOVERNOR_TARGET_LAMPORTS_PER_SIGNATURE:                                               return 8UL         ;
    case STATE_FEE_RATE_GOVERNOR_TARGET_SIGNATURES_PER_SLOT:                                                  return 8UL         ;
    case STATE_FEE_RATE_GOVERNOR_MIN_LAMPORTS_PER_SIGNATURE:                                                  return 8UL         ;
    case STATE_FEE_RATE_GOVERNOR_MAX_LAMPORTS_PER_SIGNATURE:                                                  return 8UL         ;
    case STATE_FEE_RATE_GOVERNOR_BURN_PERCENT:                                                                return 1UL         ;
    case STATE_COLLECTED_RENT:                                                                                return 8UL         ;
    case STATE_RENT_COLLECTOR_EPOCH:                                                                          return 8UL         ;
    case STATE_RENT_COLLECTOR_EPOCH_SCHEDULE_SLOTS_PER_EPOCH:                                                 return 8UL         ;
    case STATE_RENT_COLLECTOR_EPOCH_SCHEDULE_LEADER_SCHEDULE_SLOT_OFFSET:                                     return 8UL         ;
    case STATE_RENT_COLLECTOR_EPOCH_SCHEDULE_WARMUP:                                                          return 1UL         ;
    case STATE_RENT_COLLECTOR_EPOCH_SCHEDULE_FIRST_NORMAL_EPOCH:                                              return 8UL         ;
    case STATE_RENT_COLLECTOR_EPOCH_SCHEDULE_FIRST_NORMAL_SLOT:                                               return 8UL         ;
    case STATE_RENT_COLLECTOR_SLOTS_PER_YEAR:                                                                 return 8UL         ;
    case STATE_RENT_COLLECTOR_RENT_LAMPORTS_PER_UINT8_YEAR:                                                   return 8UL         ;
    case STATE_RENT_COLLECTOR_RENT_EXEMPTION_THRESHOLD:                                                       return 8UL         ;
    case STATE_RENT_COLLECTOR_RENT_BURN_PERCENT:                                                              return 1UL         ;
    case STATE_EPOCH_SCHEDULE_SLOTS_PER_EPOCH:                                                                return 8UL         ;
    case STATE_EPOCH_SCHEDULE_LEADER_SCHEDULE_SLOT_OFFSET:                                                    return 8UL         ;
    case STATE_EPOCH_SCHEDULE_WARMUP:                                                                         return 1UL         ;
    case STATE_EPOCH_SCHEDULE_FIRST_NORMAL_EPOCH:                                                             return 8UL         ;
    case STATE_EPOCH_SCHEDULE_FIRST_NORMAL_SLOT:                                                              return 8UL         ;
    case STATE_INFLATION_INITIAL:                                                                             return 8UL         ;
    case STATE_INFLATION_TERMINAL:                                                                            return 8UL         ;
    case STATE_INFLATION_TAPER:                                                                               return 8UL         ;
    case STATE_INFLATION_FOUNDATION:                                                                          return 8UL         ;
    case STATE_INFLATION_FOUNDATION_TERM:                                                                     return 8UL         ;
    case STATE_INFLATION_UNUSED:                                                                              return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_LENGTH:                                                                   return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_KEY:                                                                      return 32UL        ;
    case STATE_STAKES_VOTE_ACCOUNTS_STAKE:                                                                    return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_LAMPORTS:                                                           return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_LENGTH:                                                        return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_VARIANT:                                                       return 4UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_NODE_PUBKEY:                                           return 32UL        ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_AUTHORIZED_WITHDRAWER:                                 return 32UL        ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_COMMISSION:                                            return 1UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_VOTES_LENGTH:                                          return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_VOTES:                                                 return 13UL*length3;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_ROOT_SLOT_OPTION:                                      return 1UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_ROOT_SLOT:                                             return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_AUTHORIZED_VOTERS_LENGTH:                              return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_AUTHORIZED_VOTERS:                                     return 40UL*length3;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_PRIOR_VOTERS:                                          return 9UL+48UL*32UL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_EPOCH_CREDITS_LENGTH:                                  return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_EPOCH_CREDITS:                                         return 24UL*parser->manifest->vote_accounts[ parser->idx1 ].epoch_credits_history_len;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_LAST_TIMESTAMP_SLOT:                                   return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_LAST_TIMESTAMP_TIMESTAMP:                              return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_NODE_PUBKEY:                                            return 32UL        ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_AUTHORIZED_WITHDRAWER:                                  return 32UL        ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_COMMISSION:                                             return 1UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_VOTES_LENGTH:                                           return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_VOTES:                                                  return 12UL*length3;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_ROOT_SLOT_OPTION:                                       return 1UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_ROOT_SLOT:                                              return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_AUTHORIZED_VOTERS_LENGTH:                               return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_AUTHORIZED_VOTERS:                                      return 40UL*length3;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_PRIOR_VOTERS:                                           return 9UL+48UL*32UL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_EPOCH_CREDITS_LENGTH:                                   return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_EPOCH_CREDITS:                                          return 24UL*parser->manifest->vote_accounts[ parser->idx1 ].epoch_credits_history_len;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_LAST_TIMESTAMP_SLOT:                                    return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_LAST_TIMESTAMP_TIMESTAMP:                               return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_NODE_PUBKEY:                                             return 32UL        ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_AUTHORIZED_VOTER:                                        return 32UL        ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_AUTHORIZED_VOTER_EPOCH:                                  return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_PRIOR_VOTERS:                                            return 1800UL      ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_AUTHORIZED_WITHDRAWER:                                   return 32UL        ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_COMMISSION:                                              return 1UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_VOTES_LENGTH:                                            return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_VOTES:                                                   return 12UL*length3;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_ROOT_SLOT_OPTION:                                        return 1UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_ROOT_SLOT:                                               return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_EPOCH_CREDITS_LENGTH:                                    return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_EPOCH_CREDITS:                                           return 24UL*parser->manifest->vote_accounts[ parser->idx1 ].epoch_credits_history_len;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_LAST_TIMESTAMP_SLOT:                                     return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_LAST_TIMESTAMP_TIMESTAMP:                                return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_DUMMY:                                                         return parser->length2-(parser->off-parser->account_data_start);
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_OWNER:                                                              return 32UL        ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_EXECUTABLE:                                                         return 1UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_RENT_EPOCH:                                                         return 8UL         ;
    case STATE_STAKES_STAKE_DELEGATIONS_LENGTH:                                                               return 8UL         ;
    case STATE_STAKES_STAKE_DELEGATIONS_KEY:                                                                  return 32UL        ;
    case STATE_STAKES_STAKE_DELEGATIONS_VOTER_PUBKEY:                                                         return 32UL        ;
    case STATE_STAKES_STAKE_DELEGATIONS_STAKE:                                                                return 8UL         ;
    case STATE_STAKES_STAKE_DELEGATIONS_ACTIVATION_EPOCH:                                                     return 8UL         ;
    case STATE_STAKES_STAKE_DELEGATIONS_DEACTIVATION_EPOCH:                                                   return 8UL         ;
    case STATE_STAKES_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE:                                                 return 8UL         ;
    case STATE_STAKES_UNUSED:                                                                                 return 8UL         ;
    case STATE_STAKES_EPOCH:                                                                                  return 8UL         ;
    case STATE_STAKES_STAKE_HISTORY_LENGTH:                                                                   return 8UL         ;
    case STATE_STAKES_STAKE_HISTORY:                                                                          return 32UL*length1;
    case STATE_UNUSED_ACCOUNTS1_LENGTH:                                                                       return 8UL         ;
    case STATE_UNUSED_ACCOUNTS1_UNUSED:                                                                       return 32UL*length1;
    case STATE_UNUSED_ACCOUNTS2_LENGTH:                                                                       return 8UL         ;
    case STATE_UNUSED_ACCOUNTS2_UNUSED:                                                                       return 32UL*length1;
    case STATE_UNUSED_ACCOUNTS3_LENGTH:                                                                       return 8UL         ;
    case STATE_UNUSED_ACCOUNTS3_UNUSED:                                                                       return 40UL*length1;
    case STATE_EPOCH_STAKES_LENGTH:                                                                           return 8UL         ;
    case STATE_EPOCH_STAKES_KEY:                                                                              return 8UL         ;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_LENGTH:                                                             return 8UL         ;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_KEY:                                                                return 32UL        ;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_STAKE:                                                              return 8UL         ;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_VALUE_LAMPORTS:                                                     return 8UL         ;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_VALUE_DATA_LENGTH:                                                  return 8UL         ;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_VALUE_DATA:                                                         return length3     ;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_VALUE_OWNER:                                                        return 32UL        ;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_VALUE_EXECUTABLE:                                                   return 1UL         ;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_VALUE_RENT_EPOCH:                                                   return 8UL         ;
    case STATE_EPOCH_STAKES_STAKE_DELEGATIONS_LENGTH:                                                         return 8UL         ;
    case STATE_EPOCH_STAKES_STAKE_DELEGATIONS_KEY:                                                            return 32UL        ;
    case STATE_EPOCH_STAKES_STAKE_DELEGATIONS_VOTER_PUBKEY:                                                   return 32UL        ;
    case STATE_EPOCH_STAKES_STAKE_DELEGATIONS_STAKE:                                                          return 8UL         ;
    case STATE_EPOCH_STAKES_STAKE_DELEGATIONS_ACTIVATION_EPOCH:                                               return 8UL         ;
    case STATE_EPOCH_STAKES_STAKE_DELEGATIONS_DEACTIVATION_EPOCH:                                             return 8UL         ;
    case STATE_EPOCH_STAKES_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE:                                           return 8UL         ;
    case STATE_EPOCH_STAKES_UNUSED:                                                                           return 8UL         ;
    case STATE_EPOCH_STAKES_EPOCH:                                                                            return 8UL         ;
    case STATE_EPOCH_STAKES_STAKE_HISTORY_LENGTH:                                                             return 8UL         ;
    case STATE_EPOCH_STAKES_STAKE_HISTORY:                                                                    return 32UL*length2;
    case STATE_EPOCH_STAKES_TOTAL_STAKE:                                                                      return 8UL         ;
    case STATE_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_LENGTH:                                                  return 8UL         ;
    case STATE_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_KEY:                                                     return 32UL        ;
    case STATE_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_VOTE_ACCOUNTS_LENGTH:                                    return 8UL         ;
    case STATE_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_VOTE_ACCOUNTS:                                           return 32UL*length3;
    case STATE_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_TOTAL_STAKE:                                             return 8UL         ;
    case STATE_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS_LENGTH:                                                   return 8UL         ;
    case STATE_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS:                                                          return 64UL*length2;
    case STATE_IS_DELTA:                                                                                      return 1UL         ;
    case STATE_ACCOUNTS_DB_STORAGES_LENGTH:                                                                   return 8UL         ;
    case STATE_ACCOUNTS_DB_STORAGES_SLOT:                                                                     return 8UL         ;
    case STATE_ACCOUNTS_DB_STORAGES_ACCOUNT_VECS_LENGTH:                                                      return 8UL         ;
    case STATE_ACCOUNTS_DB_STORAGES_ACCOUNT_VECS_ID:                                                          return 8UL         ;
    case STATE_ACCOUNTS_DB_STORAGES_ACCOUNT_VECS_FILE_SZ:                                                     return 8UL         ;
    case STATE_ACCOUNTS_DB_STORAGES_DUMMY:                                                                    return 0UL         ;
    case STATE_ACCOUNTS_DB_VERSION:                                                                           return 8UL         ;
    case STATE_ACCOUNTS_DB_SLOT:                                                                              return 8UL         ;
    case STATE_ACCOUNTS_DB_BANK_HASH_INFO_ACCOUNTS_DELTA_HASH:                                                return 32UL        ;
    case STATE_ACCOUNTS_DB_BANK_HASH_INFO_ACCOUNTS_HASH:                                                      return 32UL        ;
    case STATE_ACCOUNTS_DB_BANK_HASH_INFO_STATS_NUM_UPDATED_ACCOUNTS:                                         return 8UL         ;
    case STATE_ACCOUNTS_DB_BANK_HASH_INFO_STATS_NUM_REMOVED_ACCOUNTS:                                         return 8UL         ;
    case STATE_ACCOUNTS_DB_BANK_HASH_INFO_STATS_NUM_LAMPORTS_STORED:                                          return 8UL         ;
    case STATE_ACCOUNTS_DB_BANK_HASH_INFO_STATS_TOTAL_DATA_LEN:                                               return 8UL         ;
    case STATE_ACCOUNTS_DB_BANK_HASH_INFO_STATS_NUM_EXECUTABLE_ACCOUNTS:                                      return 8UL         ;
    case STATE_ACCOUNTS_DB_HISTORICAL_ROOTS_LENGTH:                                                           return 8UL         ;
    case STATE_ACCOUNTS_DB_HISTORICAL_ROOTS:                                                                  return 8UL*length1 ;
    case STATE_ACCOUNTS_DB_HISTORICAL_WITH_HASH_LENGTH:                                                       return 8UL         ;
    case STATE_ACCOUNTS_DB_HISTORICAL_WITH_HASH:                                                              return 40UL*length1;
    case STATE_LAMPORTS_PER_SIGNATURE:                                                                        return 8UL         ;
    case STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_OPTION:                                                  return 1UL         ;
    case STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_FULL_SLOT:                                               return 8UL         ;
    case STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_FULL_HASH:                                               return 32UL        ;
    case STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_FULL_CAPITALIZATION:                                     return 8UL         ;
    case STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_INCREMENTAL_HASH:                                        return 32UL        ;
    case STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_INCREMENTAL_CAPITALIZATION:                              return 8UL         ;
    case STATE_EPOCH_ACCOUNT_HASH_OPTION:                                                                     return 1UL         ;
    case STATE_EPOCH_ACCOUNT_HASH:                                                                            return 32UL        ;
    case STATE_VERSIONED_EPOCH_STAKES_LENGTH:                                                                 return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_EPOCH:                                                                  return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_VARIANT:                                                                return 4UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_LENGTH:                                            return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_KEY:                                               return 32UL        ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_STAKE:                                             return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_LAMPORTS:                                    return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_LENGTH:                                 return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_VARIANT:                                return 4UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_NODE_PUBKEY:                    return 32UL        ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_AUTHORIZED_WITHDRAWER:          return 32UL        ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_COMMISSION:                     return 1UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_VOTES_LENGTH:                   return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_VOTES:                          return 13UL*length4;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_ROOT_SLOT_OPTION:               return 1UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_ROOT_SLOT:                      return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_AUTHORIZED_VOTERS_LENGTH:       return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_AUTHORIZED_VOTERS:              return 40UL*length4;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_PRIOR_VOTERS:                   return 9UL+48UL*32UL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_EPOCH_CREDITS_LENGTH:           return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_EPOCH_CREDITS:                  return 24UL*length4;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_LAST_TIMESTAMP_SLOT:            return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_LAST_TIMESTAMP_TIMESTAMP:       return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_NODE_PUBKEY:                     return 32UL        ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_AUTHORIZED_WITHDRAWER:           return 32UL        ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_COMMISSION:                      return 1UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_VOTES_LENGTH:                    return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_VOTES:                           return 12UL*length4;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_ROOT_SLOT_OPTION:                return 1UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_ROOT_SLOT:                       return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_AUTHORIZED_VOTERS_LENGTH:        return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_AUTHORIZED_VOTERS:               return 40UL*length4;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_PRIOR_VOTERS:                    return 9UL+48UL*32UL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_EPOCH_CREDITS_LENGTH:            return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_EPOCH_CREDITS:                   return 24UL*length4;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_LAST_TIMESTAMP_SLOT:             return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_LAST_TIMESTAMP_TIMESTAMP:        return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_NODE_PUBKEY:                      return 32UL        ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_AUTHORIZED_VOTER:                 return 32UL        ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_AUTHORIZED_VOTER_EPOCH:           return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_PRIOR_VOTERS:                     return 1800UL      ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_AUTHORIZED_WITHDRAWER:            return 32UL        ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_COMMISSION:                       return 1UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_VOTES_LENGTH:                     return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_VOTES:                            return 12UL*length4;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_ROOT_SLOT_OPTION:                 return 1UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_ROOT_SLOT:                        return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_EPOCH_CREDITS_LENGTH:             return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_EPOCH_CREDITS:                    return 24UL*length4;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_LAST_TIMESTAMP_SLOT:              return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_LAST_TIMESTAMP_TIMESTAMP:         return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_DUMMY:                                  return parser->length3-(parser->off-parser->account_data_start);
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_OWNER:                                       return 32UL        ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_EXECUTABLE:                                  return 1UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_RENT_EPOCH:                                  return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_LENGTH:                                        return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_KEY:                                           return 32UL        ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_VOTER_PUBKEY:                                  return 32UL        ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_STAKE:                                         return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_ACTIVATION_EPOCH:                              return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_DEACTIVATION_EPOCH:                            return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE:                          return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_CREDITS_OBSERVED:                              return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_UNUSED:                                                          return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_EPOCH:                                                           return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_HISTORY_LENGTH:                                            return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_HISTORY:                                                   return 32UL*length2;
    case STATE_VERSIONED_EPOCH_STAKES_TOTAL_STAKE:                                                            return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_LENGTH:                                        return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_KEY:                                           return 32UL        ;
    case STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_VOTE_ACCOUNTS_LENGTH:                          return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_VOTE_ACCOUNTS:                                 return 32UL*length3;
    case STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_TOTAL_STAKE:                                   return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS_LENGTH:                                         return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS:                                                return 64UL*length2;
    case STATE_LTHASH_OPTION:                                                                                 return 1UL         ;
    case STATE_LTHASH:                                                                                        return 2048UL      ;
    case STATE_DONE:                                                                                          return 0UL         ;
    default: FD_LOG_ERR(( "unknown state %d", parser->state ));
  }
}

static inline uchar *
state_dst( fd_ssmanifest_parser_t * parser ) {
  ulong idx1 = parser->idx1;
  ulong idx2 = parser->idx2;
  fd_snapshot_manifest_t * manifest = parser->manifest;

  switch( parser->state ) {
    case STATE_BLOCKHASH_QUEUE_LAST_HASH_INDEX:                                                               return NULL;
    case STATE_BLOCKHASH_QUEUE_LAST_HASH_OPTION:                                                              return NULL;
    case STATE_BLOCKHASH_QUEUE_LAST_HASH:                                                                     return NULL;
    case STATE_BLOCKHASH_QUEUE_AGES_LENGTH:                                                                   return (uchar*)&manifest->blockhashes_len;
    case STATE_BLOCKHASH_QUEUE_AGES_HASH:                                                                     return (uchar*)manifest->blockhashes[ idx1 ].hash;
    case STATE_BLOCKHASH_QUEUE_AGES_LAMPORTS_PER_SIGNATURE:                                                   return (uchar*)&manifest->blockhashes[ idx1 ].lamports_per_signature;
    case STATE_BLOCKHASH_QUEUE_AGES_HASH_INDEX:                                                               return (uchar*)&manifest->blockhashes[ idx1 ].hash_index;
    case STATE_BLOCKHASH_QUEUE_AGES_TIMESTAMP:                                                                return (uchar*)&manifest->blockhashes[ idx1 ].timestamp;
    case STATE_BLOCKHASH_QUEUE_MAX_AGE:                                                                       return NULL;
    case STATE_ANCESTORS_LENGTH:                                                                              return (uchar*)&parser->length1;
    case STATE_ANCESTORS:                                                                                     return NULL;
    case STATE_HASH:                                                                                          return manifest->bank_hash;
    case STATE_PARENT_HASH:                                                                                   return manifest->parent_bank_hash;
    case STATE_PARENT_SLOT:                                                                                   return (uchar*)&manifest->parent_slot;
    case STATE_HARD_FORKS_LENGTH:                                                                             return (uchar*)&manifest->hard_forks_len;
    case STATE_HARD_FORKS_SLOT:                                                                               return (uchar*)&manifest->hard_forks[ idx1 ];
    case STATE_HARD_FORKS_VAL:                                                                                return NULL;
    case STATE_TRANSACTION_COUNT:                                                                             return (uchar*)&manifest->transaction_count;
    case STATE_TICK_HEIGHT:                                                                                   return (uchar*)&manifest->tick_height;
    case STATE_SIGNATURE_COUNT:                                                                               return (uchar*)&manifest->signature_count;
    case STATE_CAPITALIZATION:                                                                                return (uchar*)&manifest->capitalization;
    case STATE_MAX_TICK_HEIGHT:                                                                               return (uchar*)&manifest->max_tick_height;
    case STATE_HASHES_PER_TICK_OPTION:                                                                        return &parser->option;
    case STATE_HASHES_PER_TICK:                                                                               return (uchar*)&manifest->hashes_per_tick;
    case STATE_TICKS_PER_SLOT:                                                                                return (uchar*)&manifest->ticks_per_slot;
    case STATE_NS_PER_SLOT:                                                                                   return (uchar*)&manifest->ns_per_slot;
    case STATE_GENSIS_CREATION_TIME:                                                                          return (uchar*)&manifest->creation_time_millis;
    case STATE_SLOTS_PER_YEAR:                                                                                return (uchar*)&manifest->slots_per_year;
    case STATE_ACCOUNTS_DATA_LEN:                                                                             return NULL;
    case STATE_SLOT:                                                                                          return (uchar*)&manifest->slot;
    case STATE_EPOCH:                                                                                         return (uchar*)&parser->epoch;
    case STATE_BLOCK_HEIGHT:                                                                                  return (uchar*)&manifest->block_height;
    case STATE_COLLECTOR_ID:                                                                                  return NULL;
    case STATE_COLLECTOR_FEES:                                                                                return (uchar*)&manifest->collector_fees;
    case STATE_FEE_COLLECTOR_LAMPORTS_PER_SIGNATURE:                                                          return NULL;
    case STATE_FEE_RATE_GOVERNOR_TARGET_LAMPORTS_PER_SIGNATURE:                                               return (uchar*)&manifest->fee_rate_governor.target_lamports_per_signature;
    case STATE_FEE_RATE_GOVERNOR_TARGET_SIGNATURES_PER_SLOT:                                                  return (uchar*)&manifest->fee_rate_governor.target_signatures_per_slot;
    case STATE_FEE_RATE_GOVERNOR_MIN_LAMPORTS_PER_SIGNATURE:                                                  return (uchar*)&manifest->fee_rate_governor.min_lamports_per_signature;
    case STATE_FEE_RATE_GOVERNOR_MAX_LAMPORTS_PER_SIGNATURE:                                                  return (uchar*)&manifest->fee_rate_governor.max_lamports_per_signature;
    case STATE_FEE_RATE_GOVERNOR_BURN_PERCENT:                                                                return (uchar*)&manifest->fee_rate_governor.burn_percent;
    case STATE_COLLECTED_RENT:                                                                                return NULL;
    case STATE_RENT_COLLECTOR_EPOCH:                                                                          return NULL;
    case STATE_RENT_COLLECTOR_EPOCH_SCHEDULE_SLOTS_PER_EPOCH:                                                 return NULL;
    case STATE_RENT_COLLECTOR_EPOCH_SCHEDULE_LEADER_SCHEDULE_SLOT_OFFSET:                                     return NULL;
    case STATE_RENT_COLLECTOR_EPOCH_SCHEDULE_WARMUP:                                                          return NULL;
    case STATE_RENT_COLLECTOR_EPOCH_SCHEDULE_FIRST_NORMAL_EPOCH:                                              return NULL;
    case STATE_RENT_COLLECTOR_EPOCH_SCHEDULE_FIRST_NORMAL_SLOT:                                               return NULL;
    case STATE_RENT_COLLECTOR_SLOTS_PER_YEAR:                                                                 return NULL;
    case STATE_RENT_COLLECTOR_RENT_LAMPORTS_PER_UINT8_YEAR:                                                   return (uchar*)&manifest->rent_params.lamports_per_uint8_year;
    case STATE_RENT_COLLECTOR_RENT_EXEMPTION_THRESHOLD:                                                       return (uchar*)&manifest->rent_params.exemption_threshold;
    case STATE_RENT_COLLECTOR_RENT_BURN_PERCENT:                                                              return (uchar*)&manifest->rent_params.burn_percent;
    case STATE_EPOCH_SCHEDULE_SLOTS_PER_EPOCH:                                                                return (uchar*)&manifest->epoch_schedule_params.slots_per_epoch;
    case STATE_EPOCH_SCHEDULE_LEADER_SCHEDULE_SLOT_OFFSET:                                                    return (uchar*)&manifest->epoch_schedule_params.leader_schedule_slot_offset;
    case STATE_EPOCH_SCHEDULE_WARMUP:                                                                         return (uchar*)&manifest->epoch_schedule_params.warmup;
    case STATE_EPOCH_SCHEDULE_FIRST_NORMAL_EPOCH:                                                             return (uchar*)&manifest->epoch_schedule_params.first_normal_epoch;
    case STATE_EPOCH_SCHEDULE_FIRST_NORMAL_SLOT:                                                              return (uchar*)&manifest->epoch_schedule_params.first_normal_slot;
    case STATE_INFLATION_INITIAL:                                                                             return (uchar*)&manifest->inflation_params.initial;
    case STATE_INFLATION_TERMINAL:                                                                            return (uchar*)&manifest->inflation_params.terminal;
    case STATE_INFLATION_TAPER:                                                                               return (uchar*)&manifest->inflation_params.taper;
    case STATE_INFLATION_FOUNDATION:                                                                          return (uchar*)&manifest->inflation_params.foundation;
    case STATE_INFLATION_FOUNDATION_TERM:                                                                     return (uchar*)&manifest->inflation_params.foundation_term;
    case STATE_INFLATION_UNUSED:                                                                              return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_LENGTH:                                                                   return (uchar*)&manifest->vote_accounts_len;
    case STATE_STAKES_VOTE_ACCOUNTS_KEY:                                                                      return manifest->vote_accounts[ idx1 ].vote_account_pubkey;
    case STATE_STAKES_VOTE_ACCOUNTS_STAKE:                                                                    return (uchar*)&manifest->vote_accounts[ idx1 ].stake;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_LAMPORTS:                                                           return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_LENGTH:                                                        return (uchar*)&parser->length2;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_VARIANT:                                                       return (uchar*)&parser->variant;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_NODE_PUBKEY:                                           return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_AUTHORIZED_WITHDRAWER:                                 return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_COMMISSION:                                            return (uchar*)&manifest->vote_accounts[ idx1 ].commission;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_VOTES_LENGTH:                                          return (uchar*)&parser->length3;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_VOTES:                                                 return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_ROOT_SLOT_OPTION:                                      return &parser->option;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_ROOT_SLOT:                                             return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_AUTHORIZED_VOTERS_LENGTH:                              return (uchar*)&parser->length3;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_AUTHORIZED_VOTERS:                                     return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_PRIOR_VOTERS:                                          return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_EPOCH_CREDITS_LENGTH:                                  return (uchar*)&manifest->vote_accounts[ idx1 ].epoch_credits_history_len;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_EPOCH_CREDITS:                                         return (uchar*)manifest->vote_accounts[ idx1 ].epoch_credits;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_LAST_TIMESTAMP_SLOT:                                   return (uchar*)&manifest->vote_accounts[ idx1 ].last_slot;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_LAST_TIMESTAMP_TIMESTAMP:                              return (uchar*)&manifest->vote_accounts[ idx1 ].last_timestamp;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_NODE_PUBKEY:                                            return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_AUTHORIZED_WITHDRAWER:                                  return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_COMMISSION:                                             return (uchar*)&manifest->vote_accounts[ idx1 ].commission;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_VOTES_LENGTH:                                           return (uchar*)&parser->length3;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_VOTES:                                                  return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_ROOT_SLOT_OPTION:                                       return &parser->option;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_ROOT_SLOT:                                              return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_AUTHORIZED_VOTERS_LENGTH:                               return (uchar*)&parser->length3;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_AUTHORIZED_VOTERS:                                      return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_PRIOR_VOTERS:                                           return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_EPOCH_CREDITS_LENGTH:                                   return (uchar*)&manifest->vote_accounts[ idx1 ].epoch_credits_history_len;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_EPOCH_CREDITS:                                          return (uchar*)manifest->vote_accounts[ idx1 ].epoch_credits;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_LAST_TIMESTAMP_SLOT:                                    return (uchar*)&manifest->vote_accounts[ idx1 ].last_slot;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_LAST_TIMESTAMP_TIMESTAMP:                               return (uchar*)&manifest->vote_accounts[ idx1 ].last_timestamp;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_NODE_PUBKEY:                                             return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_AUTHORIZED_VOTER:                                        return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_AUTHORIZED_VOTER_EPOCH:                                  return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_PRIOR_VOTERS:                                            return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_AUTHORIZED_WITHDRAWER:                                   return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_COMMISSION:                                              return (uchar*)&manifest->vote_accounts[ idx1 ].commission;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_VOTES_LENGTH:                                            return (uchar*)&parser->length3;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_VOTES:                                                   return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_ROOT_SLOT_OPTION:                                        return &parser->option;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_ROOT_SLOT:                                               return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_EPOCH_CREDITS_LENGTH:                                    return (uchar*)&manifest->vote_accounts[ idx1 ].epoch_credits_history_len;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_EPOCH_CREDITS:                                           return (uchar*)manifest->vote_accounts[ idx1 ].epoch_credits;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_LAST_TIMESTAMP_SLOT:                                     return (uchar*)&manifest->vote_accounts[ idx1 ].last_slot;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_LAST_TIMESTAMP_TIMESTAMP:                                return (uchar*)&manifest->vote_accounts[ idx1 ].last_timestamp;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_DUMMY:                                                         return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_OWNER:                                                              return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_EXECUTABLE:                                                         return (uchar*)&parser->option;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_RENT_EPOCH:                                                         return NULL;
    case STATE_STAKES_STAKE_DELEGATIONS_LENGTH:                                                               return (uchar*)&parser->length1;
    case STATE_STAKES_STAKE_DELEGATIONS_KEY:                                                                  return NULL;
    case STATE_STAKES_STAKE_DELEGATIONS_VOTER_PUBKEY:                                                         return NULL;
    case STATE_STAKES_STAKE_DELEGATIONS_STAKE:                                                                return NULL;
    case STATE_STAKES_STAKE_DELEGATIONS_ACTIVATION_EPOCH:                                                     return NULL;
    case STATE_STAKES_STAKE_DELEGATIONS_DEACTIVATION_EPOCH:                                                   return NULL;
    case STATE_STAKES_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE:                                                 return NULL;
    case STATE_STAKES_UNUSED:                                                                                 return NULL;
    case STATE_STAKES_EPOCH:                                                                                  return NULL;
    case STATE_STAKES_STAKE_HISTORY_LENGTH:                                                                   return (uchar*)&parser->length1;
    case STATE_STAKES_STAKE_HISTORY:                                                                          return NULL;
    case STATE_UNUSED_ACCOUNTS1_LENGTH:                                                                       return (uchar*)&parser->length1;
    case STATE_UNUSED_ACCOUNTS1_UNUSED:                                                                       return NULL;
    case STATE_UNUSED_ACCOUNTS2_LENGTH:                                                                       return (uchar*)&parser->length1;
    case STATE_UNUSED_ACCOUNTS2_UNUSED:                                                                       return NULL;
    case STATE_UNUSED_ACCOUNTS3_LENGTH:                                                                       return (uchar*)&parser->length1;
    case STATE_UNUSED_ACCOUNTS3_UNUSED:                                                                       return NULL;
    case STATE_EPOCH_STAKES_LENGTH:                                                                           return (uchar*)&parser->length1;
    case STATE_EPOCH_STAKES_KEY:                                                                              return NULL;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_LENGTH:                                                             return (uchar*)&parser->length2;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_KEY:                                                                return NULL;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_STAKE:                                                              return NULL;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_VALUE_LAMPORTS:                                                     return NULL;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_VALUE_DATA_LENGTH:                                                  return (uchar*)&parser->length3;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_VALUE_DATA:                                                         return NULL;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_VALUE_OWNER:                                                        return NULL;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_VALUE_EXECUTABLE:                                                   return NULL;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_VALUE_RENT_EPOCH:                                                   return NULL;
    case STATE_EPOCH_STAKES_STAKE_DELEGATIONS_LENGTH:                                                         return (uchar*)&parser->length2;
    case STATE_EPOCH_STAKES_STAKE_DELEGATIONS_KEY:                                                            return NULL;
    case STATE_EPOCH_STAKES_STAKE_DELEGATIONS_VOTER_PUBKEY:                                                   return NULL;
    case STATE_EPOCH_STAKES_STAKE_DELEGATIONS_STAKE:                                                          return NULL;
    case STATE_EPOCH_STAKES_STAKE_DELEGATIONS_ACTIVATION_EPOCH:                                               return NULL;
    case STATE_EPOCH_STAKES_STAKE_DELEGATIONS_DEACTIVATION_EPOCH:                                             return NULL;
    case STATE_EPOCH_STAKES_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE:                                           return NULL;
    case STATE_EPOCH_STAKES_UNUSED:                                                                           return NULL;
    case STATE_EPOCH_STAKES_EPOCH:                                                                            return NULL;
    case STATE_EPOCH_STAKES_STAKE_HISTORY_LENGTH:                                                             return (uchar*)&parser->length2;
    case STATE_EPOCH_STAKES_STAKE_HISTORY:                                                                    return NULL;
    case STATE_EPOCH_STAKES_TOTAL_STAKE:                                                                      return NULL;
    case STATE_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_LENGTH:                                                  return (uchar*)&parser->length2;
    case STATE_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_KEY:                                                     return NULL;
    case STATE_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_VOTE_ACCOUNTS_LENGTH:                                    return (uchar*)&parser->length3;
    case STATE_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_VOTE_ACCOUNTS:                                           return NULL;
    case STATE_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_TOTAL_STAKE:                                             return NULL;
    case STATE_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS_LENGTH:                                                   return (uchar*)&parser->length2;
    case STATE_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS:                                                          return NULL;
    case STATE_IS_DELTA:                                                                                      return NULL;
    case STATE_ACCOUNTS_DB_STORAGES_LENGTH:                                                                   return (uchar*)&parser->length1;
    case STATE_ACCOUNTS_DB_STORAGES_SLOT:                                                                     return (uchar*)&parser->acc_vec_slot;
    case STATE_ACCOUNTS_DB_STORAGES_ACCOUNT_VECS_LENGTH:                                                      return (uchar*)&parser->length2;
    case STATE_ACCOUNTS_DB_STORAGES_ACCOUNT_VECS_ID:                                                          return (uchar*)&parser->acc_vec_id;
    case STATE_ACCOUNTS_DB_STORAGES_ACCOUNT_VECS_FILE_SZ:                                                     return (uchar*)&parser->acc_vec_file_sz;
    case STATE_ACCOUNTS_DB_STORAGES_DUMMY:                                                                    return NULL;
    case STATE_ACCOUNTS_DB_VERSION:                                                                           return NULL;
    case STATE_ACCOUNTS_DB_SLOT:                                                                              return NULL;
    case STATE_ACCOUNTS_DB_BANK_HASH_INFO_ACCOUNTS_DELTA_HASH:                                                return manifest->accounts_delta_hash;
    case STATE_ACCOUNTS_DB_BANK_HASH_INFO_ACCOUNTS_HASH:                                                      return manifest->accounts_hash;
    case STATE_ACCOUNTS_DB_BANK_HASH_INFO_STATS_NUM_UPDATED_ACCOUNTS:                                         return NULL;
    case STATE_ACCOUNTS_DB_BANK_HASH_INFO_STATS_NUM_REMOVED_ACCOUNTS:                                         return NULL;
    case STATE_ACCOUNTS_DB_BANK_HASH_INFO_STATS_NUM_LAMPORTS_STORED:                                          return NULL;
    case STATE_ACCOUNTS_DB_BANK_HASH_INFO_STATS_TOTAL_DATA_LEN:                                               return NULL;
    case STATE_ACCOUNTS_DB_BANK_HASH_INFO_STATS_NUM_EXECUTABLE_ACCOUNTS:                                      return NULL;
    case STATE_ACCOUNTS_DB_HISTORICAL_ROOTS_LENGTH:                                                           return (uchar*)&parser->length1;
    case STATE_ACCOUNTS_DB_HISTORICAL_ROOTS:                                                                  return NULL;
    case STATE_ACCOUNTS_DB_HISTORICAL_WITH_HASH_LENGTH:                                                       return (uchar*)&parser->length1;
    case STATE_ACCOUNTS_DB_HISTORICAL_WITH_HASH:                                                              return NULL;
    case STATE_LAMPORTS_PER_SIGNATURE:                                                                        return (uchar*)&manifest->lamports_per_signature;
    case STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_OPTION:                                                  return &parser->option;
    case STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_FULL_SLOT:                                               return NULL;
    case STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_FULL_HASH:                                               return NULL;
    case STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_FULL_CAPITALIZATION:                                     return NULL;
    case STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_INCREMENTAL_HASH:                                        return NULL;
    case STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_INCREMENTAL_CAPITALIZATION:                              return NULL;
    case STATE_EPOCH_ACCOUNT_HASH_OPTION:                                                                     return &parser->option;
    case STATE_EPOCH_ACCOUNT_HASH:                                                                            return manifest->epoch_account_hash;
    case STATE_VERSIONED_EPOCH_STAKES_LENGTH:                                                                 return (uchar*)&parser->epoch_stakes_len;
    case STATE_VERSIONED_EPOCH_STAKES_EPOCH:                                                                  return (uchar*)&parser->epoch_stakes_epoch;
    case STATE_VERSIONED_EPOCH_STAKES_VARIANT:                                                                return (uchar*)&parser->variant;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_LENGTH:                                            return parser->epoch_idx!=ULONG_MAX ? (uchar*)&manifest->epoch_stakes[ parser->epoch_idx ].vote_stakes_len : (uchar*)&parser->length2;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_KEY:                                               return parser->epoch_idx!=ULONG_MAX ? manifest->epoch_stakes[ parser->epoch_idx ].vote_stakes[ idx2 ].vote : NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_STAKE:                                             return parser->epoch_idx!=ULONG_MAX ? (uchar*)&manifest->epoch_stakes[ parser->epoch_idx ].vote_stakes[ idx2 ].stake : NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_LAMPORTS:                                    return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_LENGTH:                                 return (uchar*)&parser->length3;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_VARIANT:                                return (uchar*)&parser->variant;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_NODE_PUBKEY:                    return parser->epoch_idx!=ULONG_MAX ? manifest->epoch_stakes[ parser->epoch_idx ].vote_stakes[ idx2 ].identity : NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_AUTHORIZED_WITHDRAWER:          return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_COMMISSION:                     return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_VOTES_LENGTH:                   return (uchar*)&parser->length4;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_VOTES:                          return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_ROOT_SLOT_OPTION:               return &parser->option;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_ROOT_SLOT:                      return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_AUTHORIZED_VOTERS_LENGTH:       return (uchar*)&parser->length4;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_AUTHORIZED_VOTERS:              return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_PRIOR_VOTERS:                   return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_EPOCH_CREDITS_LENGTH:           return (uchar*)&parser->length4;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_EPOCH_CREDITS:                  return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_LAST_TIMESTAMP_SLOT:            return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_LAST_TIMESTAMP_TIMESTAMP:       return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_NODE_PUBKEY:                     return parser->epoch_idx!=ULONG_MAX ? manifest->epoch_stakes[ parser->epoch_idx ].vote_stakes[ idx2 ].identity : NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_AUTHORIZED_WITHDRAWER:           return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_COMMISSION:                      return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_VOTES_LENGTH:                    return (uchar*)&parser->length4;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_VOTES:                           return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_ROOT_SLOT_OPTION:                return &parser->option;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_ROOT_SLOT:                       return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_AUTHORIZED_VOTERS_LENGTH:        return (uchar*)&parser->length4;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_AUTHORIZED_VOTERS:               return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_PRIOR_VOTERS:                    return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_EPOCH_CREDITS_LENGTH:            return (uchar*)&parser->length4;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_EPOCH_CREDITS:                   return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_LAST_TIMESTAMP_SLOT:             return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_LAST_TIMESTAMP_TIMESTAMP:        return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_NODE_PUBKEY:                      return parser->epoch_idx!=ULONG_MAX ? manifest->epoch_stakes[ parser->epoch_idx ].vote_stakes[ idx2 ].identity : NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_AUTHORIZED_VOTER:                 return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_AUTHORIZED_VOTER_EPOCH:           return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_PRIOR_VOTERS:                     return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_AUTHORIZED_WITHDRAWER:            return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_COMMISSION:                       return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_VOTES_LENGTH:                     return (uchar*)&parser->length4;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_VOTES:                            return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_ROOT_SLOT_OPTION:                 return &parser->option;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_ROOT_SLOT:                        return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_EPOCH_CREDITS_LENGTH:             return (uchar*)&parser->length4;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_EPOCH_CREDITS:                    return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_LAST_TIMESTAMP_SLOT:              return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_LAST_TIMESTAMP_TIMESTAMP:         return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_DUMMY:                                  return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_OWNER:                                       return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_EXECUTABLE:                                  return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_RENT_EPOCH:                                  return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_LENGTH:                                        return (uchar*)&parser->length2;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_KEY:                                           return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_VOTER_PUBKEY:                                  return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_STAKE:                                         return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_ACTIVATION_EPOCH:                              return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_DEACTIVATION_EPOCH:                            return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE:                          return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_CREDITS_OBSERVED:                              return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_UNUSED:                                                          return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_EPOCH:                                                           return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_HISTORY_LENGTH:                                            return (uchar*)&parser->length2;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_HISTORY:                                                   return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_TOTAL_STAKE:                                                            return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_LENGTH:                                        return (uchar*)&parser->length2;
    case STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_KEY:                                           return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_VOTE_ACCOUNTS_LENGTH:                          return (uchar*)&parser->length3;
    case STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_VOTE_ACCOUNTS:                                 return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_TOTAL_STAKE:                                   return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS_LENGTH:                                         return (uchar*)&parser->length2;
    case STATE_VERSIONED_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS:                                                return NULL;
    case STATE_LTHASH_OPTION:                                                                                 return &parser->option;
    case STATE_LTHASH:                                                                                        return manifest->accounts_lthash;
    case STATE_DONE:                                                                                          return NULL;
    default: FD_LOG_ERR(( "unknown state %d", parser->state ));
  }
}

#if SSMANIFEST_DEBUG
static inline void
state_log( fd_ssmanifest_parser_t * parser ) {
  fd_snapshot_manifest_t * manifest = parser->manifest;

  switch( parser->state ) {
    case STATE_FEE_RATE_GOVERNOR_TARGET_LAMPORTS_PER_SIGNATURE:                  FD_LOG_NOTICE(( "STATE_FEE_RATE_GOVERNOR_TARGET_LAMPORTS_PER_SIGNATURE                   %lu", manifest->fee_rate_governor.target_lamports_per_signature ));   break;
    case STATE_FEE_RATE_GOVERNOR_TARGET_SIGNATURES_PER_SLOT:                     FD_LOG_NOTICE(( "STATE_FEE_RATE_GOVERNOR_TARGET_SIGNATURES_PER_SLOT                      %lu", manifest->fee_rate_governor.target_signatures_per_slot ));      break;
    case STATE_FEE_RATE_GOVERNOR_MIN_LAMPORTS_PER_SIGNATURE:                     FD_LOG_NOTICE(( "STATE_FEE_RATE_GOVERNOR_MIN_LAMPORTS_PER_SIGNATURE                      %lu", manifest->fee_rate_governor.min_lamports_per_signature ));      break;
    case STATE_FEE_RATE_GOVERNOR_MAX_LAMPORTS_PER_SIGNATURE:                     FD_LOG_NOTICE(( "STATE_FEE_RATE_GOVERNOR_MAX_LAMPORTS_PER_SIGNATURE                      %lu", manifest->fee_rate_governor.max_lamports_per_signature ));      break;
    case STATE_FEE_RATE_GOVERNOR_BURN_PERCENT:                                   FD_LOG_NOTICE(( "STATE_FEE_RATE_GOVERNOR_BURN_PERCENT                                    %u",  manifest->fee_rate_governor.burn_percent ));                    break;
    case STATE_EPOCH_SCHEDULE_SLOTS_PER_EPOCH:                                   FD_LOG_NOTICE(( "STATE_EPOCH_SCHEDULE_SLOTS_PER_EPOCH                                    %lu", manifest->epoch_schedule_params.slots_per_epoch ));             break;
    case STATE_EPOCH_SCHEDULE_LEADER_SCHEDULE_SLOT_OFFSET:                       FD_LOG_NOTICE(( "STATE_EPOCH_SCHEDULE_LEADER_SCHEDULE_SLOT_OFFSET                        %lu", manifest->epoch_schedule_params.leader_schedule_slot_offset )); break;
    case STATE_EPOCH_SCHEDULE_WARMUP:                                            FD_LOG_NOTICE(( "STATE_EPOCH_SCHEDULE_WARMUP                                             %d",  manifest->epoch_schedule_params.warmup ));                      break;
    case STATE_INFLATION_INITIAL:                                                FD_LOG_NOTICE(( "STATE_INFLATION_INITIAL                                                 %lf", manifest->inflation_params.initial ));                          break;
    case STATE_INFLATION_TERMINAL:                                               FD_LOG_NOTICE(( "STATE_INFLATION_TERMINAL                                                %lf", manifest->inflation_params.terminal ));                         break;
    case STATE_INFLATION_TAPER:                                                  FD_LOG_NOTICE(( "STATE_INFLATION_TAPER                                                   %lf", manifest->inflation_params.taper ));                            break;
    case STATE_INFLATION_FOUNDATION:                                             FD_LOG_NOTICE(( "STATE_INFLATION_FOUNDATION                                              %lf", manifest->inflation_params.foundation ));                       break;
    case STATE_INFLATION_FOUNDATION_TERM:                                        FD_LOG_NOTICE(( "STATE_INFLATION_FOUNDATION_TERM                                         %lf", manifest->inflation_params.foundation_term ));                  break;
    case STATE_STAKES_VOTE_ACCOUNTS_LENGTH:                                      FD_LOG_NOTICE(( "STATE_STAKES_VOTE_ACCOUNTS_LENGTH                                       %lu", manifest->vote_accounts_len ));                                 break;
    case STATE_STAKES_STAKE_DELEGATIONS_LENGTH:                                  FD_LOG_NOTICE(( "STATE_STAKES_STAKE_DELEGATIONS_LENGTH                                   %lu", parser->length1 ));                                             break;
    case STATE_STAKES_STAKE_HISTORY_LENGTH:                                      FD_LOG_NOTICE(( "STATE_STAKES_STAKE_HISTORY_LENGTH                                       %lu", parser->length1 ));                                             break;
    case STATE_EPOCH_STAKES_LENGTH:                                              FD_LOG_NOTICE(( "STATE_EPOCH_STAKES_LENGTH                                               %lu", parser->length1 ));                                             break;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_LENGTH:                                FD_LOG_NOTICE(( "STATE_EPOCH_STAKES_VOTE_ACCOUNTS_LENGTH                                 %lu", parser->length2 ));                                             break;
    case STATE_EPOCH_STAKES_STAKE_DELEGATIONS_LENGTH:                            FD_LOG_NOTICE(( "STATE_EPOCH_STAKES_STAKE_DELEGATIONS_LENGTH                             %lu", parser->length2 ));                                             break;
    case STATE_EPOCH_STAKES_STAKE_HISTORY_LENGTH:                                FD_LOG_NOTICE(( "STATE_EPOCH_STAKES_STAKE_HISTORY_LENGTH:                                %lu", parser->length2 ));                                             break;
    case STATE_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS_LENGTH:                      FD_LOG_NOTICE(( "STATE_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS_LENGTH                       %lu", parser->length2 ));                                             break;
    case STATE_ACCOUNTS_DB_STORAGES_LENGTH:                                      FD_LOG_NOTICE(( "STATE_ACCOUNTS_DB_STORAGES_LENGTH                                       %lu", parser->length1 ));                                             break;
    case STATE_ACCOUNTS_DB_HISTORICAL_ROOTS_LENGTH:                              FD_LOG_NOTICE(( "STATE_ACCOUNTS_DB_HISTORICAL_ROOTS_LENGTH                               %lu", parser->length1 ));                                             break;
    case STATE_ACCOUNTS_DB_HISTORICAL_WITH_HASH_LENGTH:                          FD_LOG_NOTICE(( "STATE_ACCOUNTS_DB_HISTORICAL_WITH_HASH_LENGTH                           %lu", parser->length1 ));                                             break;
    case STATE_VERSIONED_EPOCH_STAKES_LENGTH:                                    FD_LOG_NOTICE(( "STATE_VERSIONED_EPOCH_STAKES_LENGTH                                     %lu", parser->epoch_stakes_len ));                                    break;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_LENGTH:               FD_LOG_NOTICE(( "STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_LENGTH                %lu", parser->length2 ));                                             break;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_LENGTH:           FD_LOG_NOTICE(( "STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_LENGTH            %lu", parser->length2 ));                                             break;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_HISTORY_LENGTH:               FD_LOG_NOTICE(( "STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_HISTORY_LENGTH                %lu", parser->length2 ));                                             break;
    case STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_LENGTH:           FD_LOG_NOTICE(( "STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_LENGTH            %lu", parser->length2 ));                                             break;
    case STATE_VERSIONED_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS_LENGTH:            FD_LOG_NOTICE(( "STATE_VERSIONED_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS_LENGTH             %lu", parser->length2 ));                                             break;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_VOTES_LENGTH:              FD_LOG_NOTICE(( "STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_VOTES_LENGTH               %lu", parser->length3 ));                                             break;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_VOTES_LENGTH:               FD_LOG_NOTICE(( "STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_VOTES_LENGTH                %lu", parser->length3 ));                                             break;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_ROOT_SLOT_OPTION:          FD_LOG_NOTICE(( "STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_ROOT_SLOT_OPTION            %d", parser->option ));                                              break;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_VARIANT:                          FD_LOG_NOTICE(( "STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_VARIANT:                           %u", parser->variant ));                                             break;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_LENGTH:                           FD_LOG_NOTICE(( "STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_LENGTH:                           %lu", parser->length2 ));                                             break;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_AUTHORIZED_VOTERS_LENGTH: FD_LOG_NOTICE(( "STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_AUTHORIZED_VOTERS_LENGTH: %lu", parser->length3 ));                                             break;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_AUTHORIZED_VOTERS_LENGTH:  FD_LOG_NOTICE(( "STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_AUTHORIZED_VOTERS_LENGTH:  %lu", parser->length3 ));                                             break;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_EPOCH_CREDITS_LENGTH:      FD_LOG_NOTICE(( "STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_EPOCH_CREDITS_LENGTH:      %lu", manifest->vote_accounts[ parser->idx1 ].epoch_credits_history_len )); break;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_LAST_TIMESTAMP_SLOT:       FD_LOG_NOTICE(( "STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_LAST_TIMESTAMP_SLOT:       %lu", manifest->vote_accounts[ parser->idx1 ].last_slot ));           break;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_LAST_TIMESTAMP_TIMESTAMP:  FD_LOG_NOTICE(( "STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_LAST_TIMESTAMP_TIMESTAMP:  %ld", manifest->vote_accounts[ parser->idx1 ].last_timestamp ));      break;
    default: break;
  }
}
#endif

static inline int
state_validate( fd_ssmanifest_parser_t * parser ) {
  fd_snapshot_manifest_t * manifest = parser->manifest;

  /* Option values in bincode must be either 0 or 1 */
  switch( parser->state ) {
    case STATE_EPOCH_SCHEDULE_WARMUP: {
      if( FD_UNLIKELY( manifest->epoch_schedule_params.warmup>1 ) ) {
        FD_LOG_WARNING(( "invalid epoch_schedule_warmup bool %d", manifest->epoch_schedule_params.warmup ));
        return -1;
      }
      break;
    }
    case STATE_HASHES_PER_TICK_OPTION: {
      if( FD_UNLIKELY( parser->option>1 ) ) {
        FD_LOG_WARNING(( "invalid hashes_per_tick option %d", parser->option ));
        return -1;
      }
      break;
    }
    case STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_OPTION: {
      if( FD_UNLIKELY( parser->option>1 ) ) {
        FD_LOG_WARNING(( "invalid bank_incremental_snapshot_persistence option %d", parser->option ));
        return -1;
      }
      break;
    }
    case STATE_EPOCH_ACCOUNT_HASH_OPTION: {
      if( FD_UNLIKELY( parser->option>1 ) ) {
        FD_LOG_WARNING(( "invalid epoch_account_hash option %d", parser->option ));
        return -1;
      }
      break;
    }
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_VARIANT: {
      if( FD_UNLIKELY( parser->variant>2 ) ) {
        FD_LOG_WARNING(( "invalid vote_accounts value data variant %u", parser->variant ));
        return -1;
      }
      break;
    }
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_EXECUTABLE: {
      if( FD_UNLIKELY( parser->option>1 ) ) {
        FD_LOG_WARNING(( "invalid vote_accounts value executable %u", parser->variant ));
        return -1;
      }
      break;
    }
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_ROOT_SLOT_OPTION: {
      if( FD_UNLIKELY( parser->option>1 ) ) {
        FD_LOG_WARNING(( "invalid vote_accounts value data current root slot option %d", parser->option ));
        return -1;
      }
      break;
    }
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_ROOT_SLOT_OPTION: {
      if( FD_UNLIKELY( parser->option>1 ) ) {
        FD_LOG_WARNING(( "invalid vote_accounts value data v11411 root slot option %d", parser->option ));
        return -1;
      }
      break;
    }
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_ROOT_SLOT_OPTION: {
      if( FD_UNLIKELY( parser->option>1 ) ) {
        FD_LOG_WARNING(( "invalid vote_accounts value data v0235 root slot option %d", parser->option ));
        return -1;
      }
      break;
    }
    case STATE_VERSIONED_EPOCH_STAKES_VARIANT: {
      if( FD_UNLIKELY( parser->variant ) ) {
        FD_LOG_WARNING(( "invalid epoch_stakes variant %u", parser->variant ));
        return -1;
      }
      break;
    }
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_ROOT_SLOT_OPTION: {
      if( FD_UNLIKELY( parser->option>1 ) ) {
        FD_LOG_WARNING(( "invalid version_epoch_stakes.vote_accounts value data current root slot option %d", parser->option ));
        return -1;
      }
      break;
    }
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_ROOT_SLOT_OPTION: {
      if( FD_UNLIKELY( parser->option>1 ) ) {
        FD_LOG_WARNING(( "invalid version_epoch_stakes.vote_accounts value data v11411 root slot option %d", parser->option ));
        return -1;
      }
      break;
    }
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_ROOT_SLOT_OPTION: {
      if( FD_UNLIKELY( parser->option>1 ) ) {
        FD_LOG_WARNING(( "invalid version_epoch_stakes.vote_accounts value data v0235 root slot option %d", parser->option ));
        return -1;
      }
      break;
    }
    case STATE_LTHASH_OPTION: {
      if( FD_UNLIKELY( parser->option>1 ) ) {
        FD_LOG_WARNING(( "invalid accounts_lthash option %d", parser->option ));
        return -1;
      }
      break;
    }
    default: break;
  }

  switch( parser->state ) {
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_COMMISSION:
    // TODO: mainnet-308392063-v2.3.0_backtest.toml has a commission of 254 in it
    // case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_COMMISSION:
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_COMMISSION:
      if( FD_UNLIKELY( manifest->vote_accounts[ parser->idx1 ].commission>100 ) ) {
        FD_LOG_WARNING(( "invalid commission %u", manifest->vote_accounts[ parser->idx1 ].commission ));
        return -1;
      }
      break;
    default:
      break;
  }

  /* Lengths must be valid */
  switch( parser->state ) {
    case STATE_BLOCKHASH_QUEUE_AGES_LENGTH: {
      if( FD_UNLIKELY( !manifest->blockhashes_len || manifest->blockhashes_len>sizeof(manifest->blockhashes)/sizeof(manifest->blockhashes[0]) ) ) {
        FD_LOG_WARNING(( "invalid blockhash_queue_ages length %lu", manifest->blockhashes_len ));
        return -1;
      }
      break;
    }
    case STATE_HARD_FORKS_LENGTH: {
      if( FD_UNLIKELY( manifest->hard_forks_len>sizeof(manifest->hard_forks)/sizeof(manifest->hard_forks[0]) ) ) {
        FD_LOG_WARNING(( "invalid hard_forks length %lu", manifest->hard_forks_len ));
        return -1;
      }
      break;
    }
    case STATE_STAKES_VOTE_ACCOUNTS_LENGTH: {
      if( FD_UNLIKELY( manifest->vote_accounts_len>sizeof(manifest->vote_accounts)/sizeof(manifest->vote_accounts[0]) ) ) {
        FD_LOG_WARNING(( "invalid vote_accounts_len %lu", manifest->vote_accounts_len ));
        return -1;
      }
      break;
    }
    case STATE_STAKES_STAKE_DELEGATIONS_LENGTH: {
      if( FD_UNLIKELY( parser->length1>( 1UL<<22UL ) ) ) { /* 2^21 needed, arbitrarily put 2^22 to have some margin */
        FD_LOG_WARNING(( "invalid stakes_stake_delegations length %lu", parser->length1 ));
        return -1;
      }
      break;
    }
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_EPOCH_CREDITS_LENGTH:
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_EPOCH_CREDITS_LENGTH:
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_EPOCH_CREDITS_LENGTH: {
      if( FD_UNLIKELY( manifest->vote_accounts[ parser->idx1 ].epoch_credits_history_len>64UL ) ) {
        FD_LOG_WARNING(( "invalid vote_accounts value data current epoch credits length %lu", manifest->vote_accounts[ parser->idx1 ].epoch_credits_history_len ));
        return -1;
      }
      break;
    }
    case STATE_VERSIONED_EPOCH_STAKES_LENGTH: {
      if( FD_UNLIKELY( parser->epoch_stakes_len>6UL ) ) {
        FD_LOG_WARNING(( "invalid epoch_stakes_len %lu", parser->epoch_stakes_len ));
        return -1;
      }
      break;
    }
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_VOTES_LENGTH: {
      if( FD_UNLIKELY( parser->length3>31 ) ) {
        FD_LOG_WARNING(( "invalid vote_accounts value data current votes length %lu", parser->length3 ));
        return -1;
      }
      break;
    }
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_VOTES_LENGTH: {
      if( FD_UNLIKELY( parser->length3>31 ) ) {
        FD_LOG_WARNING(( "invalid vote_accounts value data v11411 votes length %lu", parser->length3 ));
        return -1;
      }
      break;
    }
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_VOTES_LENGTH: {
      if( FD_UNLIKELY( parser->length3>31 ) ) {
        FD_LOG_WARNING(( "invalid vote_accounts value data v0235 votes length %lu", parser->length3 ));
        return -1;
      }
      break;
    }
    case STATE_ACCOUNTS_DB_STORAGES_LENGTH: {
      if( FD_UNLIKELY( parser->length1>(1UL<<20UL ) ) ) {
        FD_LOG_WARNING(( "invalid accounts_db_storages length %lu", parser->length1 ));
        return -1;
      }
      break;
    }
    case STATE_ACCOUNTS_DB_STORAGES_ACCOUNT_VECS_LENGTH: {
      if( FD_UNLIKELY( parser->length2>(1UL<<16UL ) ) ) {
        FD_LOG_WARNING(( "invalid accounts_db_storages account vecs length %lu", parser->length2 ));
        return -1;
      }
      break;
    }
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_LENGTH: {
      ulong stakes_len = parser->epoch_idx!=ULONG_MAX ? manifest->epoch_stakes[ parser->epoch_idx ].vote_stakes_len : parser->length2;
      ulong stakes_cap = sizeof(manifest->epoch_stakes[ 0UL ].vote_stakes)/sizeof(manifest->epoch_stakes[ 0UL ].vote_stakes[ 0UL ]);
      if( FD_UNLIKELY( stakes_len>stakes_cap ) ) {
        FD_LOG_WARNING(( "invalid versioned epoch stakes vote accounts length %lu", stakes_len ));
        return -1;
      }
      break;
    }
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_LENGTH: {
      if( FD_UNLIKELY( parser->length2>( 1UL<<22UL ) ) ) { /* 2^21 needed, arbitrarily put 2^22 to have some margin */
        FD_LOG_WARNING(( "invalid versioned epoch stakes stake delegation length %lu", parser->length2 ));
        return -1;
      }
      break;
    }
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_LENGTH: {
      if( FD_UNLIKELY( parser->length2>10UL*(1UL<<20UL) ) ) { /* 10 MiB */
        FD_LOG_WARNING(( "invalid vote_accounts value data length %lu", parser->length2 ));
        return -1;
      }
      break;
    }
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_LENGTH: {
      if( FD_UNLIKELY( parser->length3>10UL*(1UL<<20UL) ) ) { /* 10 MiB */
        FD_LOG_WARNING(( "invalid version_epoch_stakes.vote_accounts value data length %lu", parser->length3 ));
        return -1;
      }
      break;
    }
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_EPOCH_CREDITS_LENGTH:
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_EPOCH_CREDITS_LENGTH:
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_EPOCH_CREDITS_LENGTH: {
      if( FD_UNLIKELY( parser->length4>64UL ) ) {
        FD_LOG_WARNING(( "invalid version_epoch_stakes.vote_accounts value data current epoch credits length %lu", parser->length4 ));
        return -1;
      }
      break;
    }
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_VOTES_LENGTH: {
      if( FD_UNLIKELY( parser->length4>31 ) ) {
        FD_LOG_WARNING(( "invalid version_epoch_stakes.vote_accounts value data current votes length %lu", parser->length4 ));
        return -1;
      }
      break;
    }
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_VOTES_LENGTH: {
      if( FD_UNLIKELY( parser->length4>31 ) ) {
        FD_LOG_WARNING(( "invalid version_epoch_stakes.vote_accounts value data v11411 votes length %lu", parser->length4 ));
        return -1;
      }
      break;
    }
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_VOTES_LENGTH: {
      if( FD_UNLIKELY( parser->length4>31 ) ) {
        FD_LOG_WARNING(( "invalid version_epoch_stakes.vote_accounts value data v0235 votes length %lu", parser->length4 ));
        return -1;
      }
      break;
    }
    case STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_LENGTH: {
      if( FD_UNLIKELY( parser->length2>(1UL<<16UL) ) ) {
        FD_LOG_WARNING(( "invalid versioned epoch stakes node id to vote accounts length %lu", parser->length2 ));
        return -1;
      }
      break;
    }
  }

  return 0;
}

static inline int
state_process( fd_ssmanifest_parser_t * parser ) {
  fd_snapshot_manifest_t * manifest = parser->manifest;

  FD_TEST( parser->state!=STATE_DONE );

  if( FD_UNLIKELY( parser->state==STATE_ACCOUNTS_DB_STORAGES_ACCOUNT_VECS_FILE_SZ && parser->acc_vec_map ) ) {
    if( FD_UNLIKELY( !acc_vec_pool_free( parser->acc_vec_pool ) ) ) {
      FD_LOG_WARNING(( "acc_vec_pool is full, cannot insert new account vec" ));
      return -1;
    }

    acc_vec_key_t key = { .slot=parser->acc_vec_slot, .id=parser->acc_vec_id };
    if( FD_UNLIKELY( acc_vec_map_ele_query( parser->acc_vec_map, &key, NULL, parser->acc_vec_pool ) ) ) {
      FD_LOG_WARNING(( "duplicate account vec with slot %lu and id %lu", parser->acc_vec_slot, parser->acc_vec_id ));
      return -1;
    }

    acc_vec_t * acc_vec = acc_vec_pool_ele_acquire( parser->acc_vec_pool );
    acc_vec->key.id = parser->acc_vec_id;
    acc_vec->key.slot = parser->acc_vec_slot;
    acc_vec->file_sz = parser->acc_vec_file_sz;
    acc_vec_map_ele_insert( parser->acc_vec_map, acc_vec, parser->acc_vec_pool );
  }

  if( FD_UNLIKELY( parser->state==STATE_VERSIONED_EPOCH_STAKES_EPOCH ) ) {
    ulong epoch_delta = parser->epoch_stakes_epoch-parser->epoch;
    parser->epoch_idx = epoch_delta<2UL ? epoch_delta : ULONG_MAX;
  }

  /* STATE_STAKES_VOTE_ACCOUNTS */

  if( FD_UNLIKELY( parser->state==STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_LENGTH && !parser->length2 ) ) {
    parser->state = STATE_STAKES_VOTE_ACCOUNTS_VALUE_OWNER;
    return 0;
  }

  if( FD_UNLIKELY( parser->state==STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_VARIANT ) ) {
    switch( parser->variant ) {
      case 2: parser->state = STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_NODE_PUBKEY; return 0;
      case 1: parser->state = STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_NODE_PUBKEY; return 0;
      case 0: parser->state = STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_NODE_PUBKEY; return 0;
    }
  }

  if( FD_UNLIKELY( parser->state==STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_LENGTH ) ) parser->account_data_start = parser->off;

  switch( parser->state ) {
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_LAST_TIMESTAMP_TIMESTAMP:
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_LAST_TIMESTAMP_TIMESTAMP:
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_LAST_TIMESTAMP_TIMESTAMP:
      parser->state = STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_DUMMY;
      return 0;
    default: break;
  }

  /* STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS */

  if( FD_UNLIKELY( parser->state==STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_LENGTH && !parser->length3 ) ) {
    parser->state = STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_OWNER;
    return 0;
  }

  if( FD_UNLIKELY( parser->state==STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_VARIANT ) ) {
    switch( parser->variant ) {
      case 2: parser->state = STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_NODE_PUBKEY; return 0;
      case 1: parser->state = STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_NODE_PUBKEY; return 0;
      case 0: parser->state = STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_NODE_PUBKEY; return 0;
    }
  }

  if( FD_UNLIKELY( parser->state==STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_LENGTH ) ) parser->account_data_start = parser->off;

  if( FD_UNLIKELY( parser->state==STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_OWNER && parser->epoch_idx!=ULONG_MAX ) ) {
    /* We're only interested in vote accounts with stakes>0. When stakes==0, we
       decrement the counters so that we store all vote/stakes in a compact array. */
    fd_snapshot_manifest_vote_stakes_t * vote_stakes = &parser->manifest->epoch_stakes[ parser->epoch_idx ].vote_stakes[ parser->idx2 ];
    if( vote_stakes->stake==0 ) {
      parser->manifest->epoch_stakes[ parser->epoch_idx ].vote_stakes_len--;
      parser->idx2--;
    }
  }

  switch( parser->state ) {
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_LAST_TIMESTAMP_TIMESTAMP:
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_LAST_TIMESTAMP_TIMESTAMP:
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_LAST_TIMESTAMP_TIMESTAMP:
      parser->state = STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_DUMMY;
      return 0;
    default: break;
  }

  switch( parser->state ) {
    case STATE_HASHES_PER_TICK_OPTION:    manifest->has_hashes_per_tick    = !!parser->option; parser->state += 2-!!parser->option; return 0;
    case STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_OPTION: {
      if( FD_LIKELY( !!parser->option ) ) parser->state += 1;
      else                                parser->state = STATE_EPOCH_ACCOUNT_HASH_OPTION;
      return 0;
    }
    case STATE_EPOCH_ACCOUNT_HASH_OPTION: manifest->has_epoch_account_hash = !!parser->option; parser->state += 2-!!parser->option; return 0;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_ROOT_SLOT_OPTION: parser->state += 2-!!parser->option; return 0;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_ROOT_SLOT_OPTION: parser->state += 2-!!parser->option; return 0;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_ROOT_SLOT_OPTION: parser->state += 2-!!parser->option; return 0;
    case STATE_LTHASH_OPTION:             manifest->has_accounts_lthash    = !!parser->option; parser->state += 2-!!parser->option; return 0;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_ROOT_SLOT_OPTION: parser->state += 2-!!parser->option; return 0;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_ROOT_SLOT_OPTION: parser->state += 2-!!parser->option; return 0;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_ROOT_SLOT_OPTION: parser->state += 2-!!parser->option; return 0;
    default: break;
  }

  ulong length = 0UL;
  ulong * idx;
  int next_target = INT_MAX;
  switch( parser->state ) {
    case STATE_BLOCKHASH_QUEUE_AGES_LENGTH:                            length = manifest->blockhashes_len;   idx = &parser->idx1; next_target = STATE_BLOCKHASH_QUEUE_MAX_AGE;                                break;
    case STATE_HARD_FORKS_LENGTH:                                      length = manifest->hard_forks_len;    idx = &parser->idx1; next_target = STATE_TRANSACTION_COUNT;                                      break;
    case STATE_STAKES_VOTE_ACCOUNTS_LENGTH:                            length = manifest->vote_accounts_len; idx = &parser->idx1; next_target = STATE_STAKES_STAKE_DELEGATIONS_LENGTH;                        break;
    case STATE_STAKES_STAKE_DELEGATIONS_LENGTH:                        length = parser->length1;             idx = &parser->idx1; next_target = STATE_STAKES_UNUSED;                                          break;
    case STATE_EPOCH_STAKES_LENGTH:                                    length = parser->length1;             idx = &parser->idx1; next_target = STATE_IS_DELTA;                                               break;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_LENGTH:                      length = parser->length2;             idx = &parser->idx2; next_target = STATE_EPOCH_STAKES_STAKE_DELEGATIONS_LENGTH;                  break;
    case STATE_EPOCH_STAKES_STAKE_DELEGATIONS_LENGTH:                  length = parser->length2;             idx = &parser->idx2; next_target = STATE_EPOCH_STAKES_UNUSED;                                    break;
    case STATE_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_LENGTH:           length = parser->length2;             idx = &parser->idx2; next_target = STATE_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS_LENGTH;            break;
    case STATE_ACCOUNTS_DB_STORAGES_LENGTH:                            length = parser->length1;             idx = &parser->idx1; next_target = STATE_ACCOUNTS_DB_VERSION;                                    break;
    case STATE_ACCOUNTS_DB_STORAGES_ACCOUNT_VECS_LENGTH:               length = parser->length2;             idx = &parser->idx2; next_target = STATE_ACCOUNTS_DB_STORAGES_DUMMY;                             break;
    case STATE_VERSIONED_EPOCH_STAKES_LENGTH:                          length = parser->epoch_stakes_len;    idx = &parser->idx1; next_target = STATE_LTHASH_OPTION;                                          break;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_LENGTH:     length = parser->epoch_idx!=ULONG_MAX ? manifest->epoch_stakes[ parser->epoch_idx ].vote_stakes_len : parser->length2; idx = &parser->idx2; next_target = STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_LENGTH; break;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_LENGTH: length = parser->length2;             idx = &parser->idx2; next_target = STATE_VERSIONED_EPOCH_STAKES_STAKES_UNUSED;                   break;
    case STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_LENGTH: length = parser->length2;             idx = &parser->idx2; next_target = STATE_VERSIONED_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS_LENGTH;  break;
    default: break;
  }

  if( FD_UNLIKELY( next_target!=INT_MAX ) ) {
    *idx = 0UL;
    if( FD_UNLIKELY( !length ) ) {
      parser->state = next_target;
      return 0;
    }
  }

  int iter_target = INT_MAX;
  switch( parser->state ) {
    case STATE_BLOCKHASH_QUEUE_AGES_TIMESTAMP:                                   length = manifest->blockhashes_len;   idx = &parser->idx1; next_target = STATE_BLOCKHASH_QUEUE_MAX_AGE;                                iter_target = STATE_BLOCKHASH_QUEUE_AGES_LENGTH+1UL;                            break;
    case STATE_HARD_FORKS_VAL:                                                   length = manifest->hard_forks_len;    idx = &parser->idx1; next_target = STATE_TRANSACTION_COUNT;                                      iter_target = STATE_HARD_FORKS_LENGTH+1UL;                                      break;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_RENT_EPOCH:                            length = manifest->vote_accounts_len; idx = &parser->idx1; next_target = STATE_STAKES_STAKE_DELEGATIONS_LENGTH;                        iter_target = STATE_STAKES_VOTE_ACCOUNTS_LENGTH+1UL;                            break;
    case STATE_STAKES_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE:                    length = parser->length1;             idx = &parser->idx1; next_target = STATE_STAKES_UNUSED;                                          iter_target = STATE_STAKES_STAKE_DELEGATIONS_LENGTH+1UL;                        break;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_VALUE_RENT_EPOCH:                      length = parser->length2;             idx = &parser->idx2; next_target = STATE_EPOCH_STAKES_STAKE_DELEGATIONS_LENGTH;                  iter_target = STATE_EPOCH_STAKES_VOTE_ACCOUNTS_LENGTH+1UL;                      break;
    case STATE_EPOCH_STAKES_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE:              length = parser->length2;             idx = &parser->idx2; next_target = STATE_EPOCH_STAKES_UNUSED;                                    iter_target = STATE_EPOCH_STAKES_STAKE_DELEGATIONS_LENGTH+1UL;                  break;
    case STATE_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_TOTAL_STAKE:                length = parser->length2;             idx = &parser->idx2; next_target = STATE_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS_LENGTH;            iter_target = STATE_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_LENGTH+1UL;           break;
    case STATE_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS:                             length = parser->length1;             idx = &parser->idx1; next_target = STATE_IS_DELTA;                                               iter_target = STATE_EPOCH_STAKES_LENGTH+1UL;                                    break;
    case STATE_ACCOUNTS_DB_STORAGES_DUMMY:                                       length = parser->length1;             idx = &parser->idx1; next_target = STATE_ACCOUNTS_DB_VERSION;                                    iter_target = STATE_ACCOUNTS_DB_STORAGES_LENGTH+1UL;                            break;
    case STATE_ACCOUNTS_DB_STORAGES_ACCOUNT_VECS_FILE_SZ:                        length = parser->length2;             idx = &parser->idx2; next_target = STATE_ACCOUNTS_DB_STORAGES_DUMMY;                             iter_target = STATE_ACCOUNTS_DB_STORAGES_ACCOUNT_VECS_LENGTH+1UL;               break;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_RENT_EPOCH:     length = parser->epoch_idx!=ULONG_MAX ? manifest->epoch_stakes[ parser->epoch_idx ].vote_stakes_len : parser->length2; idx = &parser->idx2; next_target = STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_LENGTH; iter_target = STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_LENGTH+1UL;     break;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_CREDITS_OBSERVED: length = parser->length2;             idx = &parser->idx2; next_target = STATE_VERSIONED_EPOCH_STAKES_STAKES_UNUSED;                   iter_target = STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_LENGTH+1UL; break;
    case STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_TOTAL_STAKE:      length = parser->length2;             idx = &parser->idx2; next_target = STATE_VERSIONED_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS_LENGTH;  iter_target = STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_LENGTH+1UL; break;
    case STATE_VERSIONED_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS:                   length = parser->epoch_stakes_len;    idx = &parser->idx1; next_target = STATE_LTHASH_OPTION;                                          iter_target = STATE_VERSIONED_EPOCH_STAKES_LENGTH+1UL;                          break;
    default: break;
  }

  if( FD_UNLIKELY( iter_target!=INT_MAX ) ) {
    *idx += 1UL;
    if( FD_LIKELY( *idx<length ) ) parser->state = iter_target;
    else                           parser->state = next_target;
    return 0;
  }

  parser->state += 1;
  return 0;
}

FD_FN_CONST ulong
fd_ssmanifest_parser_align( void ) {
  return 128UL;
}

FD_FN_CONST ulong
fd_ssmanifest_parser_footprint( ulong max_acc_vecs ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_ssmanifest_parser_t), sizeof(fd_ssmanifest_parser_t)         );
  l = FD_LAYOUT_APPEND( l, acc_vec_pool_align(),            acc_vec_pool_footprint( max_acc_vecs ) );
  l = FD_LAYOUT_APPEND( l, acc_vec_map_align(),             acc_vec_map_footprint( max_acc_vecs )  );
  return FD_LAYOUT_FINI( l, alignof(fd_ssmanifest_parser_t) );
}

void *
fd_ssmanifest_parser_new( void * shmem,
                          ulong  max_acc_vecs,
                          ulong  seed ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, alignof(fd_ssmanifest_parser_t) ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_ssmanifest_parser_t * parser = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_ssmanifest_parser_t), sizeof(fd_ssmanifest_parser_t)         );
  void * _acc_vec_pool            = FD_SCRATCH_ALLOC_APPEND( l, acc_vec_pool_align(),            acc_vec_pool_footprint( max_acc_vecs ) );
  void * _acc_vec_map             = FD_SCRATCH_ALLOC_APPEND( l, acc_vec_map_align(),             acc_vec_map_footprint( max_acc_vecs )  );

  parser->acc_vec_pool = acc_vec_pool_join( acc_vec_pool_new( _acc_vec_pool, max_acc_vecs ) );
  FD_TEST( parser->acc_vec_pool );

  parser->acc_vec_map = acc_vec_map_join( acc_vec_map_new( _acc_vec_map, max_acc_vecs, seed ) );
  FD_TEST( parser->acc_vec_map );

  parser->max_acc_vecs = max_acc_vecs;
  parser->seed         = seed;

  return parser;
}

fd_ssmanifest_parser_t *
fd_ssmanifest_parser_join( void * shmem ) {
  return shmem;
}

void
fd_ssmanifest_parser_init( fd_ssmanifest_parser_t * parser,
                           fd_snapshot_manifest_t * manifest ) {
  parser->state    = STATE_BLOCKHASH_QUEUE_LAST_HASH_INDEX;
  parser->off      = 0UL;
  parser->dst      = state_dst( parser );
  parser->dst_sz   = state_size( parser );
  parser->dst_cur  = 0UL;
  parser->manifest = manifest;

  FD_SCRATCH_ALLOC_INIT( l, parser );
                         FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_ssmanifest_parser_t), sizeof(fd_ssmanifest_parser_t)                 );
  void * _acc_vec_pool = FD_SCRATCH_ALLOC_APPEND( l, acc_vec_pool_align(),            acc_vec_pool_footprint( parser->max_acc_vecs ) );
  void * _acc_vec_map  = FD_SCRATCH_ALLOC_APPEND( l, acc_vec_map_align(),             acc_vec_map_footprint( parser->max_acc_vecs )  );

  acc_vec_pool_new( _acc_vec_pool, parser->max_acc_vecs );
  acc_vec_map_new( _acc_vec_map, parser->max_acc_vecs, parser->seed );
}

int
fd_ssmanifest_parser_consume( fd_ssmanifest_parser_t * parser,
                              uchar const *            buf,
                              ulong                    bufsz ) {
#if SSMANIFEST_DEBUG
  int state = parser->state;
#endif

  while( bufsz ) {
#if SSMANIFEST_DEBUG
    if( parser->state>state ) {
      FD_LOG_WARNING(( "State is %d (%lu/%lu)", parser->state, parser->dst_cur, parser->dst_sz ));
      state = parser->state;
    }
#endif

    ulong consume = fd_ulong_min( bufsz, parser->dst_sz-parser->dst_cur );

    if( FD_LIKELY( parser->dst && consume ) ) memcpy( parser->dst+parser->dst_cur, buf, consume );

    parser->off     += consume;
    parser->dst_cur += consume;
    buf             += consume;
    bufsz           -= consume;

#if SSMANIFEST_DEBUG
    // FD_LOG_WARNING(( "Consumed %lu new (%lu/%lu) bytes", consume, parser->dst_cur, parser->dst_sz ));
#endif

    if( FD_LIKELY( parser->dst_cur==parser->dst_sz ) ) {
#if SSMANIFEST_DEBUG
      state_log( parser );
#endif
      if( FD_UNLIKELY( -1==state_validate( parser ) ) ) return -1;
      if( FD_UNLIKELY( -1==state_process( parser ) ) ) return -1;
      parser->dst     = state_dst( parser );
      parser->dst_sz  = state_size( parser );
      parser->dst_cur = 0UL;
    }

    if( FD_UNLIKELY( parser->state==STATE_DONE ) ) break;
    if( FD_UNLIKELY( !bufsz ) ) return 1;
  }

  if( FD_UNLIKELY( bufsz ) ) {
    FD_LOG_WARNING(( "excess data in buffer" ));
    return -1;
  }

  return 0;
}

ulong
fd_ssmanifest_acc_vec_sz( fd_ssmanifest_parser_t const * parser,
                          ulong                          slot,
                          ulong                          id ) {
  acc_vec_key_t key = {
    .slot = slot,
    .id   = id
  };

  acc_vec_t * result = acc_vec_map_ele_query( parser->acc_vec_map, &key, NULL, parser->acc_vec_pool );
  if( FD_UNLIKELY( !result ) ) return ULONG_MAX;

  return result->file_sz;
}
