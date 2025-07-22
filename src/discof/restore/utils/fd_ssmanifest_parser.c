#include "fd_ssmanifest_parser.h"

#include "fd_ssmsg.h"

#include "../../../util/log/fd_log.h"

#define SSMANIFEST_DEBUG 0

#define STATE_BLOCKHASH_QUEUE_LAST_HASH_INDEX                                        (  0)
#define STATE_BLOCKHASH_QUEUE_LAST_HASH_OPTION                                       (  1)
#define STATE_BLOCKHASH_QUEUE_LAST_HASH                                              (  2)
#define STATE_BLOCKHASH_QUEUE_AGES_LENGTH                                            (  3)
#define STATE_BLOCKHASH_QUEUE_AGES                                                   (  4)
#define STATE_BLOCKHASH_QUEUE_MAX_AGE                                                (  5)
#define STATE_ANCESTORS_LENGTH                                                       (  6)
#define STATE_ANCESTORS                                                              (  7)
#define STATE_HASH                                                                   (  8)
#define STATE_PARENT_HASH                                                            (  9)
#define STATE_PARENT_SLOT                                                            ( 10)
#define STATE_HARD_FORKS_LENGTH                                                      ( 11)
#define STATE_HARD_FORKS                                                             ( 12)
#define STATE_TRANSACTION_COUNT                                                      ( 13)
#define STATE_TICK_HEIGHT                                                            ( 14)
#define STATE_SIGNATURE_COUNT                                                        ( 15)
#define STATE_CAPITALIZATION                                                         ( 16)
#define STATE_MAX_TICK_HEIGHT                                                        ( 17)
#define STATE_HASHES_PER_TICK_OPTION                                                 ( 18)
#define STATE_HASHES_PER_TICK                                                        ( 19)
#define STATE_TICKS_PER_SLOT                                                         ( 20)
#define STATE_NS_PER_SLOT                                                            ( 21)
#define STATE_GENSIS_CREATION_TIME                                                   ( 22)
#define STATE_SLOTS_PER_YEAR                                                         ( 23)
#define STATE_ACCOUNTS_DATA_LEN                                                      ( 24)
#define STATE_SLOT                                                                   ( 25)
#define STATE_EPOCH                                                                  ( 26)
#define STATE_BLOCK_HEIGHT                                                           ( 27)
#define STATE_COLLECTOR_ID                                                           ( 28)
#define STATE_COLLECTOR_FEES                                                         ( 29)
#define STATE_FEE_COLLECTOR_LAMPORTS_PER_SIGNATURE                                   ( 30)
#define STATE_FEE_RATE_GOVERNOR_TARGET_LAMPORTS_PER_SIGNATURE                        ( 31)
#define STATE_FEE_RATE_GOVERNOR_TARGET_SIGNATURES_PER_SLOT                           ( 32)
#define STATE_FEE_RATE_GOVERNOR_MIN_LAMPORTS_PER_SIGNATURE                           ( 33)
#define STATE_FEE_RATE_GOVERNOR_MAX_LAMPORTS_PER_SIGNATURE                           ( 34)
#define STATE_FEE_RATE_GOVERNOR_BURN_PERCENT                                         ( 35)
#define STATE_COLLECTED_RENT                                                         ( 36)
#define STATE_RENT_COLLECTOR_EPOCH                                                   ( 37)
#define STATE_RENT_COLLECTOR_EPOCH_SCHEDULE_SLOTS_PER_EPOCH                          ( 38)
#define STATE_RENT_COLLECTOR_EPOCH_SCHEDULE_LEADER_SCHEDULE_SLOT_OFFSET              ( 39)
#define STATE_RENT_COLLECTOR_EPOCH_SCHEDULE_WARMUP                                   ( 40)
#define STATE_RENT_COLLECTOR_EPOCH_SCHEDULE_FIRST_NORMAL_EPOCH                       ( 41)
#define STATE_RENT_COLLECTOR_EPOCH_SCHEDULE_FIRST_NORMAL_SLOT                        ( 42)
#define STATE_RENT_COLLECTOR_SLOTS_PER_YEAR                                          ( 43)
#define STATE_RENT_COLLECTOR_RENT_LAMPORTS_PER_UINT8_YEAR                            ( 44)
#define STATE_RENT_COLLECTOR_RENT_EXEMPTION_THRESHOLD                                ( 45)
#define STATE_RENT_COLLECTOR_RENT_BURN_PERCENT                                       ( 46)
#define STATE_EPOCH_SCHEDULE_SLOTS_PER_EPOCH                                         ( 47)
#define STATE_EPOCH_SCHEDULE_LEADER_SCHEDULE_SLOT_OFFSET                             ( 48)
#define STATE_EPOCH_SCHEDULE_WARMUP                                                  ( 49)
#define STATE_EPOCH_SCHEDULE_FIRST_NORMAL_EPOCH                                      ( 50)
#define STATE_EPOCH_SCHEDULE_FIRST_NORMAL_SLOT                                       ( 51)
#define STATE_INFLATION_INITIAL                                                      ( 52)
#define STATE_INFLATION_TERMINAL                                                     ( 53)
#define STATE_INFLATION_TAPER                                                        ( 54)
#define STATE_INFLATION_FOUNDATION                                                   ( 55)
#define STATE_INFLATION_FOUNDATION_TERM                                              ( 56)
#define STATE_INFLATION_UNUSED                                                       ( 57)
#define STATE_STAKES_VOTE_ACCOUNTS_LENGTH                                            ( 58)
#define STATE_STAKES_VOTE_ACCOUNTS_KEY                                               ( 59)
#define STATE_STAKES_VOTE_ACCOUNTS_STAKE                                             ( 60)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_LAMPORTS                                    ( 61)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_LENGTH                                 ( 62)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_VARIANT                                ( 63)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_NODE_PUBKEY                    ( 64)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_AUTHORIZED_WITHDRAWER          ( 65)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_COMMISSION                     ( 66)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_VOTES_LENGTH                   ( 67)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_VOTES                          ( 68)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_ROOT_SLOT_OPTION               ( 69)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_ROOT_SLOT                      ( 70)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_AUTHORIZED_VOTERS_LENGTH       ( 71)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_AUTHORIZED_VOTERS              ( 72)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_PRIOR_VOTERS                   ( 73)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_EPOCH_CREDITS_LENGTH           ( 74)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_EPOCH_CREDITS                  ( 75)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_LAST_TIMESTAMP_SLOT            ( 76)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_LAST_TIMESTAMP_TIMESTAMP       ( 77)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_NODE_PUBKEY                     ( 78)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_AUTHORIZED_WITHDRAWER           ( 79)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_COMMISSION                      ( 80)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_VOTES_LENGTH                    ( 81)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_VOTES                           ( 82)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_ROOT_SLOT_OPTION                ( 83)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_ROOT_SLOT                       ( 84)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_AUTHORIZED_VOTERS_LENGTH        ( 85)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_AUTHORIZED_VOTERS               ( 86)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_PRIOR_VOTERS                    ( 87)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_EPOCH_CREDITS_LENGTH            ( 88)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_EPOCH_CREDITS                   ( 89)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_LAST_TIMESTAMP_SLOT             ( 90)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_LAST_TIMESTAMP_TIMESTAMP        ( 91)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_NODE_PUBKEY                      ( 92)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_AUTHORIZED_VOTER                 ( 93)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_AUTHORIZED_VOTER_EPOCH           ( 94)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_PRIOR_VOTERS                     ( 95)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_AUTHORIZED_WITHDRAWER            ( 96)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_COMMISSION                       ( 97)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_VOTES_LENGTH                     ( 98)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_VOTES                            ( 99)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_ROOT_SLOT_OPTION                 (100)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_ROOT_SLOT                        (101)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_EPOCH_CREDITS_LENGTH             (102)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_EPOCH_CREDITS                    (103)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_LAST_TIMESTAMP_SLOT              (104)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_LAST_TIMESTAMP_TIMESTAMP         (105)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_OWNER                                       (106)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_EXECUTABLE                                  (107)
#define STATE_STAKES_VOTE_ACCOUNTS_VALUE_RENT_EPOCH                                  (108)
#define STATE_STAKES_STAKE_DELEGATIONS_LENGTH                                        (109)
#define STATE_STAKES_STAKE_DELEGATIONS_KEY                                           (110)
#define STATE_STAKES_STAKE_DELEGATIONS_VOTER_PUBKEY                                  (111)
#define STATE_STAKES_STAKE_DELEGATIONS_STAKE                                         (112)
#define STATE_STAKES_STAKE_DELEGATIONS_ACTIVATION_EPOCH                              (113)
#define STATE_STAKES_STAKE_DELEGATIONS_DEACTIVATION_EPOCH                            (114)
#define STATE_STAKES_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE                          (115)
#define STATE_STAKES_UNUSED                                                          (116)
#define STATE_STAKES_EPOCH                                                           (117)
#define STATE_STAKES_STAKE_HISTORY_LENGTH                                            (118)
#define STATE_STAKES_STAKE_HISTORY                                                   (119)
#define STATE_UNUSED_ACCOUNTS1_LENGTH                                                (120)
#define STATE_UNUSED_ACCOUNTS1_UNUSED                                                (121)
#define STATE_UNUSED_ACCOUNTS2_LENGTH                                                (122)
#define STATE_UNUSED_ACCOUNTS2_UNUSED                                                (123)
#define STATE_UNUSED_ACCOUNTS3_LENGTH                                                (124)
#define STATE_UNUSED_ACCOUNTS3_UNUSED                                                (125)
#define STATE_EPOCH_STAKES_LENGTH                                                    (126)
#define STATE_EPOCH_STAKES_KEY                                                       (127)
#define STATE_EPOCH_STAKES_VOTE_ACCOUNTS_LENGTH                                      (128)
#define STATE_EPOCH_STAKES_VOTE_ACCOUNTS_KEY                                         (129)
#define STATE_EPOCH_STAKES_VOTE_ACCOUNTS_STAKE                                       (130)
#define STATE_EPOCH_STAKES_VOTE_ACCOUNTS_VALUE_LAMPORTS                              (131)
#define STATE_EPOCH_STAKES_VOTE_ACCOUNTS_VALUE_DATA_LENGTH                           (132)
#define STATE_EPOCH_STAKES_VOTE_ACCOUNTS_VALUE_DATA                                  (133)
#define STATE_EPOCH_STAKES_VOTE_ACCOUNTS_VALUE_OWNER                                 (134)
#define STATE_EPOCH_STAKES_VOTE_ACCOUNTS_VALUE_EXECUTABLE                            (135)
#define STATE_EPOCH_STAKES_VOTE_ACCOUNTS_VALUE_RENT_EPOCH                            (136)
#define STATE_EPOCH_STAKES_STAKE_DELEGATIONS_LENGTH                                  (137)
#define STATE_EPOCH_STAKES_STAKE_DELEGATIONS_KEY                                     (138)
#define STATE_EPOCH_STAKES_STAKE_DELEGATIONS_VOTER_PUBKEY                            (139)
#define STATE_EPOCH_STAKES_STAKE_DELEGATIONS_STAKE                                   (140)
#define STATE_EPOCH_STAKES_STAKE_DELEGATIONS_ACTIVATION_EPOCH                        (141)
#define STATE_EPOCH_STAKES_STAKE_DELEGATIONS_DEACTIVATION_EPOCH                      (142)
#define STATE_EPOCH_STAKES_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE                    (143)
#define STATE_EPOCH_STAKES_UNUSED                                                    (144)
#define STATE_EPOCH_STAKES_EPOCH                                                     (145)
#define STATE_EPOCH_STAKES_STAKE_HISTORY_LENGTH                                      (146)
#define STATE_EPOCH_STAKES_STAKE_HISTORY                                             (147)
#define STATE_EPOCH_STAKES_TOTAL_STAKE                                               (148)
#define STATE_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_LENGTH                           (149)
#define STATE_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_KEY                              (150)
#define STATE_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_VOTE_ACCOUNTS_LENGTH             (151)
#define STATE_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_VOTE_ACCOUNTS                    (152)
#define STATE_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_TOTAL_STAKE                      (153)
#define STATE_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS_LENGTH                            (154)
#define STATE_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS                                   (155)
#define STATE_IS_DELTA                                                               (156)
#define STATE_ACCOUNTS_DB_STORAGES_LENGTH                                            (157)
#define STATE_ACCOUNTS_DB_STORAGES_SLOT                                              (158)
#define STATE_ACCOUNTS_DB_STORAGES_ACCOUNT_VECS_LENGTH                               (159)
#define STATE_ACCOUNTS_DB_STORAGES_ACCOUNT_VECS                                      (160)
#define STATE_ACCOUNTS_DB_VERSION                                                    (161)
#define STATE_ACCOUNTS_DB_SLOT                                                       (162)
#define STATE_ACCOUNTS_DB_BANK_HASH_INFO_ACCOUNTS_DELTA_HASH                         (163)
#define STATE_ACCOUNTS_DB_BANK_HASH_INFO_ACCOUNTS_HASH                               (164)
#define STATE_ACCOUNTS_DB_BANK_HASH_INFO_STATS_NUM_UPDATED_ACCOUNTS                  (165)
#define STATE_ACCOUNTS_DB_BANK_HASH_INFO_STATS_NUM_REMOVED_ACCOUNTS                  (166)
#define STATE_ACCOUNTS_DB_BANK_HASH_INFO_STATS_NUM_LAMPORTS_STORED                   (167)
#define STATE_ACCOUNTS_DB_BANK_HASH_INFO_STATS_TOTAL_DATA_LEN                        (168)
#define STATE_ACCOUNTS_DB_BANK_HASH_INFO_STATS_NUM_EXECUTABLE_ACCOUNTS               (169)
#define STATE_ACCOUNTS_DB_HISTORICAL_ROOTS_LENGTH                                    (170)
#define STATE_ACCOUNTS_DB_HISTORICAL_ROOTS                                           (171)
#define STATE_ACCOUNTS_DB_HISTORICAL_WITH_HASH_LENGTH                                (172)
#define STATE_ACCOUNTS_DB_HISTORICAL_WITH_HASH                                       (173)
#define STATE_LAMPORTS_PER_SIGNATURE                                                 (174)
#define STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_OPTION                           (175)
#define STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_FULL_SLOT                        (176)
#define STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_FULL_HASH                        (177)
#define STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_FULL_CAPITALIZATION              (178)
#define STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_INCREMENTAL_HASH                 (179)
#define STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_INCREMENTAL_CAPITALIZATION       (180)
#define STATE_EPOCH_ACCOUNT_HASH_OPTION                                              (181)
#define STATE_EPOCH_ACCOUNT_HASH                                                     (182)
#define STATE_VERSIONED_EPOCH_STAKES_LENGTH                                          (183)
#define STATE_VERSIONED_EPOCH_STAKES_EPOCH                                           (184)
#define STATE_VERSIONED_EPOCH_STAKES_VARIANT                                         (185)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_LENGTH                     (186)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_KEY                        (187)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_STAKE                      (188)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_LAMPORTS             (189)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_LENGTH          (190)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA                 (191)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_OWNER                (192)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_EXECUTABLE           (193)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_RENT_EPOCH           (194)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_LENGTH                 (195)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_KEY                    (196)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_VOTER_PUBKEY           (197)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_STAKE                  (198)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_ACTIVATION_EPOCH       (199)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_DEACTIVATION_EPOCH     (200)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE   (201)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_CREDITS_OBSERVED       (202)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_UNUSED                                   (203)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_EPOCH                                    (204)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_HISTORY_LENGTH                     (205)
#define STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_HISTORY                            (206)
#define STATE_VERSIONED_EPOCH_STAKES_TOTAL_STAKE                                     (207)
#define STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_LENGTH                 (208)
#define STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_KEY                    (209)
#define STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_VOTE_ACCOUNTS_LENGTH   (210)
#define STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_VOTE_ACCOUNTS          (211)
#define STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_TOTAL_STAKE            (212)
#define STATE_VERSIONED_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS_LENGTH                  (213)
#define STATE_VERSIONED_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS                         (214)
#define STATE_LTHASH_OPTION                                                          (215)
#define STATE_LTHASH                                                                 (216)
#define STATE_DONE                                                                   (217)

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

  ulong   epoch_stakes_len;
  ulong   epoch;
  ulong   epoch_stakes_epoch;
  ulong   epoch_idx;

  ulong   account_data_start;

  long    genesis_creation_time_millis;

  fd_snapshot_manifest_t * manifest;
};

static inline ulong
state_size( fd_ssmanifest_parser_t * parser ) {
  ulong length1 = parser->length1;
  ulong length2 = parser->length2;
  ulong length3 = parser->length3;

  switch( parser->state ) {
    case STATE_BLOCKHASH_QUEUE_LAST_HASH_INDEX:                                        return 8UL         ;
    case STATE_BLOCKHASH_QUEUE_LAST_HASH_OPTION:                                       return 1UL         ;
    case STATE_BLOCKHASH_QUEUE_LAST_HASH:                                              return 32UL        ;
    case STATE_BLOCKHASH_QUEUE_AGES_LENGTH:                                            return 8UL         ;
    case STATE_BLOCKHASH_QUEUE_AGES:                                                   return 56UL*length1;
    case STATE_BLOCKHASH_QUEUE_MAX_AGE:                                                return 8UL         ;
    case STATE_ANCESTORS_LENGTH:                                                       return 8UL         ;
    case STATE_ANCESTORS:                                                              return 16UL*length1;
    case STATE_HASH:                                                                   return 32UL        ;
    case STATE_PARENT_HASH:                                                            return 32UL        ;
    case STATE_PARENT_SLOT:                                                            return 8UL         ;
    case STATE_HARD_FORKS_LENGTH:                                                      return 8UL         ;
    case STATE_HARD_FORKS:                                                             return 16UL*length1;
    case STATE_TRANSACTION_COUNT:                                                      return 8UL         ;
    case STATE_TICK_HEIGHT:                                                            return 8UL         ;
    case STATE_SIGNATURE_COUNT:                                                        return 8UL         ;
    case STATE_CAPITALIZATION:                                                         return 8UL         ;
    case STATE_MAX_TICK_HEIGHT:                                                        return 8UL         ;
    case STATE_HASHES_PER_TICK_OPTION:                                                 return 1UL         ;
    case STATE_HASHES_PER_TICK:                                                        return 8UL         ;
    case STATE_TICKS_PER_SLOT:                                                         return 8UL         ;
    case STATE_NS_PER_SLOT:                                                            return 16UL        ;
    case STATE_GENSIS_CREATION_TIME:                                                   return 8UL         ;
    case STATE_SLOTS_PER_YEAR:                                                         return 8UL         ;
    case STATE_ACCOUNTS_DATA_LEN:                                                      return 8UL         ;
    case STATE_SLOT:                                                                   return 8UL         ;
    case STATE_EPOCH:                                                                  return 8UL         ;
    case STATE_BLOCK_HEIGHT:                                                           return 8UL         ;
    case STATE_COLLECTOR_ID:                                                           return 32UL        ;
    case STATE_COLLECTOR_FEES:                                                         return 8UL         ;
    case STATE_FEE_COLLECTOR_LAMPORTS_PER_SIGNATURE:                                   return 8UL         ;
    case STATE_FEE_RATE_GOVERNOR_TARGET_LAMPORTS_PER_SIGNATURE:                        return 8UL         ;
    case STATE_FEE_RATE_GOVERNOR_TARGET_SIGNATURES_PER_SLOT:                           return 8UL         ;
    case STATE_FEE_RATE_GOVERNOR_MIN_LAMPORTS_PER_SIGNATURE:                           return 8UL         ;
    case STATE_FEE_RATE_GOVERNOR_MAX_LAMPORTS_PER_SIGNATURE:                           return 8UL         ;
    case STATE_FEE_RATE_GOVERNOR_BURN_PERCENT:                                         return 1UL         ;
    case STATE_COLLECTED_RENT:                                                         return 8UL         ;
    case STATE_RENT_COLLECTOR_EPOCH:                                                   return 8UL         ;
    case STATE_RENT_COLLECTOR_EPOCH_SCHEDULE_SLOTS_PER_EPOCH:                          return 8UL         ;
    case STATE_RENT_COLLECTOR_EPOCH_SCHEDULE_LEADER_SCHEDULE_SLOT_OFFSET:              return 8UL         ;
    case STATE_RENT_COLLECTOR_EPOCH_SCHEDULE_WARMUP:                                   return 1UL         ;
    case STATE_RENT_COLLECTOR_EPOCH_SCHEDULE_FIRST_NORMAL_EPOCH:                       return 8UL         ;
    case STATE_RENT_COLLECTOR_EPOCH_SCHEDULE_FIRST_NORMAL_SLOT:                        return 8UL         ;
    case STATE_RENT_COLLECTOR_SLOTS_PER_YEAR:                                          return 8UL         ;
    case STATE_RENT_COLLECTOR_RENT_LAMPORTS_PER_UINT8_YEAR:                            return 8UL         ;
    case STATE_RENT_COLLECTOR_RENT_EXEMPTION_THRESHOLD:                                return 8UL         ;
    case STATE_RENT_COLLECTOR_RENT_BURN_PERCENT:                                       return 1UL         ;
    case STATE_EPOCH_SCHEDULE_SLOTS_PER_EPOCH:                                         return 8UL         ;
    case STATE_EPOCH_SCHEDULE_LEADER_SCHEDULE_SLOT_OFFSET:                             return 8UL         ;
    case STATE_EPOCH_SCHEDULE_WARMUP:                                                  return 1UL         ;
    case STATE_EPOCH_SCHEDULE_FIRST_NORMAL_EPOCH:                                      return 8UL         ;
    case STATE_EPOCH_SCHEDULE_FIRST_NORMAL_SLOT:                                       return 8UL         ;
    case STATE_INFLATION_INITIAL:                                                      return 8UL         ;
    case STATE_INFLATION_TERMINAL:                                                     return 8UL         ;
    case STATE_INFLATION_TAPER:                                                        return 8UL         ;
    case STATE_INFLATION_FOUNDATION:                                                   return 8UL         ;
    case STATE_INFLATION_FOUNDATION_TERM:                                              return 8UL         ;
    case STATE_INFLATION_UNUSED:                                                       return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_LENGTH:                                            return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_KEY:                                               return 32UL        ;
    case STATE_STAKES_VOTE_ACCOUNTS_STAKE:                                             return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_LAMPORTS:                                    return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_LENGTH:                                 return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_VARIANT:                                return 4UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_NODE_PUBKEY:                    return 32UL        ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_AUTHORIZED_WITHDRAWER:          return 32UL        ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_COMMISSION:                     return 1UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_VOTES_LENGTH:                   return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_VOTES:                          return 13UL*length3;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_ROOT_SLOT_OPTION:               return 1UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_ROOT_SLOT:                      return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_AUTHORIZED_VOTERS_LENGTH:       return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_AUTHORIZED_VOTERS:              return 40UL*length3;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_PRIOR_VOTERS:                   return 9UL+48UL*32UL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_EPOCH_CREDITS_LENGTH:           return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_EPOCH_CREDITS:                  return 24UL*length3;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_LAST_TIMESTAMP_SLOT:            return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_LAST_TIMESTAMP_TIMESTAMP:       return /*8UL+*/parser->length2-(parser->off-parser->account_data_start);
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_NODE_PUBKEY:                     return 32UL        ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_AUTHORIZED_WITHDRAWER:           return 32UL        ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_COMMISSION:                      return 1UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_VOTES_LENGTH:                    return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_VOTES:                           return 12UL*length3;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_ROOT_SLOT_OPTION:                return 1UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_ROOT_SLOT:                       return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_AUTHORIZED_VOTERS_LENGTH:        return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_AUTHORIZED_VOTERS:               return 40UL*length3;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_PRIOR_VOTERS:                    return 9UL+48UL*32UL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_EPOCH_CREDITS_LENGTH:            return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_EPOCH_CREDITS:                   return 24UL*length3;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_LAST_TIMESTAMP_SLOT:             return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_LAST_TIMESTAMP_TIMESTAMP:        return /*8UL+*/parser->length2-(parser->off-parser->account_data_start);
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_NODE_PUBKEY:                      return 32UL        ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_AUTHORIZED_VOTER:                 return 32UL        ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_AUTHORIZED_VOTER_EPOCH:           return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_PRIOR_VOTERS:                     return 1800UL      ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_AUTHORIZED_WITHDRAWER:            return 32UL        ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_COMMISSION:                       return 1UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_VOTES_LENGTH:                     return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_VOTES:                            return 12UL*length3;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_ROOT_SLOT_OPTION:                 return 1UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_ROOT_SLOT:                        return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_EPOCH_CREDITS_LENGTH:             return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_EPOCH_CREDITS:                    return 24UL*length3;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_LAST_TIMESTAMP_SLOT:              return 8UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_LAST_TIMESTAMP_TIMESTAMP:         return /*8UL+*/parser->length2-(parser->off-parser->account_data_start);
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_OWNER:                                       return 32UL        ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_EXECUTABLE:                                  return 1UL         ;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_RENT_EPOCH:                                  return 8UL         ;
    case STATE_STAKES_STAKE_DELEGATIONS_LENGTH:                                        return 8UL         ;
    case STATE_STAKES_STAKE_DELEGATIONS_KEY:                                           return 32UL        ;
    case STATE_STAKES_STAKE_DELEGATIONS_VOTER_PUBKEY:                                  return 32UL        ;
    case STATE_STAKES_STAKE_DELEGATIONS_STAKE:                                         return 8UL         ;
    case STATE_STAKES_STAKE_DELEGATIONS_ACTIVATION_EPOCH:                              return 8UL         ;
    case STATE_STAKES_STAKE_DELEGATIONS_DEACTIVATION_EPOCH:                            return 8UL         ;
    case STATE_STAKES_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE:                          return 8UL         ;
    case STATE_STAKES_UNUSED:                                                          return 8UL         ;
    case STATE_STAKES_EPOCH:                                                           return 8UL         ;
    case STATE_STAKES_STAKE_HISTORY_LENGTH:                                            return 8UL         ;
    case STATE_STAKES_STAKE_HISTORY:                                                   return 32UL*length1;
    case STATE_UNUSED_ACCOUNTS1_LENGTH:                                                return 8UL         ;
    case STATE_UNUSED_ACCOUNTS1_UNUSED:                                                return 32UL*length1;
    case STATE_UNUSED_ACCOUNTS2_LENGTH:                                                return 8UL         ;
    case STATE_UNUSED_ACCOUNTS2_UNUSED:                                                return 32UL*length1;
    case STATE_UNUSED_ACCOUNTS3_LENGTH:                                                return 8UL         ;
    case STATE_UNUSED_ACCOUNTS3_UNUSED:                                                return 40UL*length1;
    case STATE_EPOCH_STAKES_LENGTH:                                                    return 8UL         ;
    case STATE_EPOCH_STAKES_KEY:                                                       return 8UL         ;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_LENGTH:                                      return 8UL         ;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_KEY:                                         return 32UL        ;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_STAKE:                                       return 8UL         ;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_VALUE_LAMPORTS:                              return 8UL         ;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_VALUE_DATA_LENGTH:                           return 8UL         ;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_VALUE_DATA:                                  return length2     ;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_VALUE_OWNER:                                 return 32UL        ;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_VALUE_EXECUTABLE:                            return 1UL         ;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_VALUE_RENT_EPOCH:                            return 8UL         ;
    case STATE_EPOCH_STAKES_STAKE_DELEGATIONS_LENGTH:                                  return 8UL         ;
    case STATE_EPOCH_STAKES_STAKE_DELEGATIONS_KEY:                                     return 32UL        ;
    case STATE_EPOCH_STAKES_STAKE_DELEGATIONS_VOTER_PUBKEY:                            return 32UL        ;
    case STATE_EPOCH_STAKES_STAKE_DELEGATIONS_STAKE:                                   return 8UL         ;
    case STATE_EPOCH_STAKES_STAKE_DELEGATIONS_ACTIVATION_EPOCH:                        return 8UL         ;
    case STATE_EPOCH_STAKES_STAKE_DELEGATIONS_DEACTIVATION_EPOCH:                      return 8UL         ;
    case STATE_EPOCH_STAKES_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE:                    return 8UL         ;
    case STATE_EPOCH_STAKES_UNUSED:                                                    return 8UL         ;
    case STATE_EPOCH_STAKES_EPOCH:                                                     return 8UL         ;
    case STATE_EPOCH_STAKES_STAKE_HISTORY_LENGTH:                                      return 8UL         ;
    case STATE_EPOCH_STAKES_STAKE_HISTORY:                                             return 32UL*length2;
    case STATE_EPOCH_STAKES_TOTAL_STAKE:                                               return 8UL         ;
    case STATE_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_LENGTH:                           return 8UL         ;
    case STATE_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_KEY:                              return 32UL        ;
    case STATE_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_VOTE_ACCOUNTS_LENGTH:             return 8UL         ;
    case STATE_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_VOTE_ACCOUNTS:                    return 32UL*length3;
    case STATE_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_TOTAL_STAKE:                      return 8UL         ;
    case STATE_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS_LENGTH:                            return 8UL         ;
    case STATE_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS:                                   return 64UL*length1;
    case STATE_IS_DELTA:                                                               return 1UL         ;
    case STATE_ACCOUNTS_DB_STORAGES_LENGTH:                                            return 8UL         ;
    case STATE_ACCOUNTS_DB_STORAGES_SLOT:                                              return 8UL         ;
    case STATE_ACCOUNTS_DB_STORAGES_ACCOUNT_VECS_LENGTH:                               return 8UL         ;
    case STATE_ACCOUNTS_DB_STORAGES_ACCOUNT_VECS:                                      return 16UL*length2;
    case STATE_ACCOUNTS_DB_VERSION:                                                    return 8UL         ;
    case STATE_ACCOUNTS_DB_SLOT:                                                       return 8UL         ;
    case STATE_ACCOUNTS_DB_BANK_HASH_INFO_ACCOUNTS_DELTA_HASH:                         return 32UL        ;
    case STATE_ACCOUNTS_DB_BANK_HASH_INFO_ACCOUNTS_HASH:                               return 32UL        ;
    case STATE_ACCOUNTS_DB_BANK_HASH_INFO_STATS_NUM_UPDATED_ACCOUNTS:                  return 8UL         ;
    case STATE_ACCOUNTS_DB_BANK_HASH_INFO_STATS_NUM_REMOVED_ACCOUNTS:                  return 8UL         ;
    case STATE_ACCOUNTS_DB_BANK_HASH_INFO_STATS_NUM_LAMPORTS_STORED:                   return 8UL         ;
    case STATE_ACCOUNTS_DB_BANK_HASH_INFO_STATS_TOTAL_DATA_LEN:                        return 8UL         ;
    case STATE_ACCOUNTS_DB_BANK_HASH_INFO_STATS_NUM_EXECUTABLE_ACCOUNTS:               return 8UL         ;
    case STATE_ACCOUNTS_DB_HISTORICAL_ROOTS_LENGTH:                                    return 8UL         ;
    case STATE_ACCOUNTS_DB_HISTORICAL_ROOTS:                                           return 8UL*length1 ;
    case STATE_ACCOUNTS_DB_HISTORICAL_WITH_HASH_LENGTH:                                return 8UL         ;
    case STATE_ACCOUNTS_DB_HISTORICAL_WITH_HASH:                                       return 40UL*length1;
    case STATE_LAMPORTS_PER_SIGNATURE:                                                 return 8UL         ;
    case STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_OPTION:                           return 1UL         ;
    case STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_FULL_SLOT:                        return 8UL         ;
    case STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_FULL_HASH:                        return 32UL        ;
    case STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_FULL_CAPITALIZATION:              return 8UL         ;
    case STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_INCREMENTAL_HASH:                 return 32UL        ;
    case STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_INCREMENTAL_CAPITALIZATION:       return 8UL         ;
    case STATE_EPOCH_ACCOUNT_HASH_OPTION:                                              return 1UL         ;
    case STATE_EPOCH_ACCOUNT_HASH:                                                     return 32UL        ;
    case STATE_VERSIONED_EPOCH_STAKES_LENGTH:                                          return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_EPOCH:                                           return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_VARIANT:                                         return 4UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_LENGTH:                     return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_KEY:                        return 32UL        ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_STAKE:                      return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_LAMPORTS:             return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_LENGTH:          return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA:                 return length3     ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_OWNER:                return 32UL        ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_EXECUTABLE:           return 1UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_RENT_EPOCH:           return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_LENGTH:                 return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_KEY:                    return 32UL        ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_VOTER_PUBKEY:           return 32UL        ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_STAKE:                  return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_ACTIVATION_EPOCH:       return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_DEACTIVATION_EPOCH:     return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE:   return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_CREDITS_OBSERVED:       return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_UNUSED:                                   return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_EPOCH:                                    return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_HISTORY_LENGTH:                     return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_HISTORY:                            return 32UL*length2;
    case STATE_VERSIONED_EPOCH_STAKES_TOTAL_STAKE:                                     return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_LENGTH:                 return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_KEY:                    return 32UL        ;
    case STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_VOTE_ACCOUNTS_LENGTH:   return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_VOTE_ACCOUNTS:          return 32UL*length3;
    case STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_TOTAL_STAKE:            return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS_LENGTH:                  return 8UL         ;
    case STATE_VERSIONED_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS:                         return 64UL*length2;
    case STATE_LTHASH_OPTION:                                                          return 1UL         ;
    case STATE_LTHASH:                                                                 return 2048UL      ;
    case STATE_DONE:                                                                   return 0UL         ;
    default: FD_LOG_ERR(( "unknown state %d", parser->state ));
  }
}

static inline uchar *
state_dst( fd_ssmanifest_parser_t * parser ) {
  ulong idx1 = parser->idx1;
  fd_snapshot_manifest_t * manifest = parser->manifest;

  switch( parser->state ) {
    case STATE_BLOCKHASH_QUEUE_LAST_HASH_INDEX:                                        return NULL;
    case STATE_BLOCKHASH_QUEUE_LAST_HASH_OPTION:                                       return NULL;
    case STATE_BLOCKHASH_QUEUE_LAST_HASH:                                              return NULL;
    case STATE_BLOCKHASH_QUEUE_AGES_LENGTH:                                            return (uchar*)&parser->length1;
    case STATE_BLOCKHASH_QUEUE_AGES:                                                   return NULL;
    case STATE_BLOCKHASH_QUEUE_MAX_AGE:                                                return NULL;
    case STATE_ANCESTORS_LENGTH:                                                       return (uchar*)&parser->length1;
    case STATE_ANCESTORS:                                                              return NULL;
    case STATE_HASH:                                                                   return manifest->bank_hash;
    case STATE_PARENT_HASH:                                                            return manifest->parent_bank_hash;
    case STATE_PARENT_SLOT:                                                            return (uchar*)&manifest->parent_slot;
    case STATE_HARD_FORKS_LENGTH:                                                      return (uchar*)&parser->length1;
    case STATE_HARD_FORKS:                                                             return NULL;
    case STATE_TRANSACTION_COUNT:                                                      return NULL;
    case STATE_TICK_HEIGHT:                                                            return NULL;
    case STATE_SIGNATURE_COUNT:                                                        return NULL;
    case STATE_CAPITALIZATION:                                                         return (uchar*)&manifest->capitalization;
    case STATE_MAX_TICK_HEIGHT:                                                        return NULL;
    case STATE_HASHES_PER_TICK_OPTION:                                                 return &parser->option;
    case STATE_HASHES_PER_TICK:                                                        return (uchar*)&manifest->hashes_per_tick;
    case STATE_TICKS_PER_SLOT:                                                         return (uchar*)&manifest->ticks_per_slot;
    case STATE_NS_PER_SLOT:                                                            return NULL;
    case STATE_GENSIS_CREATION_TIME:                                                   return (uchar*)&parser->genesis_creation_time_millis;
    case STATE_SLOTS_PER_YEAR:                                                         return NULL;
    case STATE_ACCOUNTS_DATA_LEN:                                                      return NULL;
    case STATE_SLOT:                                                                   return (uchar*)&manifest->slot;
    case STATE_EPOCH:                                                                  return (uchar*)&parser->epoch;
    case STATE_BLOCK_HEIGHT:                                                           return (uchar*)&manifest->block_height;
    case STATE_COLLECTOR_ID:                                                           return NULL;
    case STATE_COLLECTOR_FEES:                                                         return NULL;
    case STATE_FEE_COLLECTOR_LAMPORTS_PER_SIGNATURE:                                   return NULL;
    case STATE_FEE_RATE_GOVERNOR_TARGET_LAMPORTS_PER_SIGNATURE:                        return (uchar*)&manifest->fee_rate_governor.target_lamports_per_signature;
    case STATE_FEE_RATE_GOVERNOR_TARGET_SIGNATURES_PER_SLOT:                           return (uchar*)&manifest->fee_rate_governor.target_signatures_per_slot;
    case STATE_FEE_RATE_GOVERNOR_MIN_LAMPORTS_PER_SIGNATURE:                           return (uchar*)&manifest->fee_rate_governor.min_lamports_per_signature;
    case STATE_FEE_RATE_GOVERNOR_MAX_LAMPORTS_PER_SIGNATURE:                           return (uchar*)&manifest->fee_rate_governor.max_lamports_per_signature;
    case STATE_FEE_RATE_GOVERNOR_BURN_PERCENT:                                         return (uchar*)&manifest->fee_rate_governor.burn_percent;
    case STATE_COLLECTED_RENT:                                                         return NULL;
    case STATE_RENT_COLLECTOR_EPOCH:                                                   return NULL;
    case STATE_RENT_COLLECTOR_EPOCH_SCHEDULE_SLOTS_PER_EPOCH:                          return NULL;
    case STATE_RENT_COLLECTOR_EPOCH_SCHEDULE_LEADER_SCHEDULE_SLOT_OFFSET:              return NULL;
    case STATE_RENT_COLLECTOR_EPOCH_SCHEDULE_WARMUP:                                   return NULL;
    case STATE_RENT_COLLECTOR_EPOCH_SCHEDULE_FIRST_NORMAL_EPOCH:                       return NULL;
    case STATE_RENT_COLLECTOR_EPOCH_SCHEDULE_FIRST_NORMAL_SLOT:                        return NULL;
    case STATE_RENT_COLLECTOR_SLOTS_PER_YEAR:                                          return NULL;
    case STATE_RENT_COLLECTOR_RENT_LAMPORTS_PER_UINT8_YEAR:                            return NULL;
    case STATE_RENT_COLLECTOR_RENT_EXEMPTION_THRESHOLD:                                return NULL;
    case STATE_RENT_COLLECTOR_RENT_BURN_PERCENT:                                       return NULL;
    case STATE_EPOCH_SCHEDULE_SLOTS_PER_EPOCH:                                         return (uchar*)&manifest->epoch_schedule_params.slots_per_epoch;
    case STATE_EPOCH_SCHEDULE_LEADER_SCHEDULE_SLOT_OFFSET:                             return (uchar*)&manifest->epoch_schedule_params.leader_schedule_slot_offset;
    case STATE_EPOCH_SCHEDULE_WARMUP:                                                  return (uchar*)&manifest->epoch_schedule_params.warmup;
    case STATE_EPOCH_SCHEDULE_FIRST_NORMAL_EPOCH:                                      return NULL;
    case STATE_EPOCH_SCHEDULE_FIRST_NORMAL_SLOT:                                       return NULL;
    case STATE_INFLATION_INITIAL:                                                      return (uchar*)&manifest->inflation_params.initial;
    case STATE_INFLATION_TERMINAL:                                                     return (uchar*)&manifest->inflation_params.terminal;
    case STATE_INFLATION_TAPER:                                                        return (uchar*)&manifest->inflation_params.taper;
    case STATE_INFLATION_FOUNDATION:                                                   return (uchar*)&manifest->inflation_params.foundation;
    case STATE_INFLATION_FOUNDATION_TERM:                                              return (uchar*)&manifest->inflation_params.foundation_term;
    case STATE_INFLATION_UNUSED:                                                       return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_LENGTH:                                            return (uchar*)&manifest->vote_accounts_len;
    case STATE_STAKES_VOTE_ACCOUNTS_KEY:                                               return manifest->vote_accounts[ idx1 ].vote_account_pubkey;
    case STATE_STAKES_VOTE_ACCOUNTS_STAKE:                                             return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_LAMPORTS:                                    return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_LENGTH:                                 return (uchar*)&parser->length2;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_VARIANT:                                return (uchar*)&parser->variant;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_NODE_PUBKEY:                    return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_AUTHORIZED_WITHDRAWER:          return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_COMMISSION:                     return (uchar*)&manifest->vote_accounts[ idx1 ].commission;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_VOTES_LENGTH:                   return (uchar*)&parser->length3;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_VOTES:                          return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_ROOT_SLOT_OPTION:               return &parser->option;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_ROOT_SLOT:                      return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_AUTHORIZED_VOTERS_LENGTH:       return (uchar*)&parser->length3;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_AUTHORIZED_VOTERS:              return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_PRIOR_VOTERS:                   return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_EPOCH_CREDITS_LENGTH:           return (uchar*)&manifest->vote_accounts[ idx1 ].epoch_credits_history_len;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_EPOCH_CREDITS:                  return (uchar*)manifest->vote_accounts[ idx1 ].epoch_credits;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_LAST_TIMESTAMP_SLOT:            return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_LAST_TIMESTAMP_TIMESTAMP:       return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_NODE_PUBKEY:                     return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_AUTHORIZED_WITHDRAWER:           return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_COMMISSION:                      return (uchar*)&manifest->vote_accounts[ idx1 ].commission;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_VOTES_LENGTH:                    return (uchar*)&parser->length3;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_VOTES:                           return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_ROOT_SLOT_OPTION:                return &parser->option;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_ROOT_SLOT:                       return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_AUTHORIZED_VOTERS_LENGTH:        return (uchar*)&parser->length3;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_AUTHORIZED_VOTERS:               return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_PRIOR_VOTERS:                    return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_EPOCH_CREDITS_LENGTH:            return (uchar*)&manifest->vote_accounts[ idx1 ].epoch_credits_history_len;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_EPOCH_CREDITS:                   return (uchar*)manifest->vote_accounts[ idx1 ].epoch_credits;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_LAST_TIMESTAMP_SLOT:             return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_LAST_TIMESTAMP_TIMESTAMP:        return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_NODE_PUBKEY:                      return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_AUTHORIZED_VOTER:                 return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_AUTHORIZED_VOTER_EPOCH:           return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_PRIOR_VOTERS:                     return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_AUTHORIZED_WITHDRAWER:            return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_COMMISSION:                       return (uchar*)&manifest->vote_accounts[ idx1 ].commission;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_VOTES_LENGTH:                     return (uchar*)&parser->length3;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_VOTES:                            return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_ROOT_SLOT_OPTION:                 return &parser->option;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_ROOT_SLOT:                        return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_EPOCH_CREDITS_LENGTH:             return (uchar*)&manifest->vote_accounts[ idx1 ].epoch_credits_history_len;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_EPOCH_CREDITS:                    return (uchar*)manifest->vote_accounts[ idx1 ].epoch_credits;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_LAST_TIMESTAMP_SLOT:              return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_LAST_TIMESTAMP_TIMESTAMP:         return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_OWNER:                                       return NULL;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_EXECUTABLE:                                  return (uchar*)&parser->option;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_RENT_EPOCH:                                  return NULL;
    case STATE_STAKES_STAKE_DELEGATIONS_LENGTH:                                        return (uchar*)&parser->length1;
    case STATE_STAKES_STAKE_DELEGATIONS_KEY:                                           return NULL;
    case STATE_STAKES_STAKE_DELEGATIONS_VOTER_PUBKEY:                                  return NULL;
    case STATE_STAKES_STAKE_DELEGATIONS_STAKE:                                         return NULL;
    case STATE_STAKES_STAKE_DELEGATIONS_ACTIVATION_EPOCH:                              return NULL;
    case STATE_STAKES_STAKE_DELEGATIONS_DEACTIVATION_EPOCH:                            return NULL;
    case STATE_STAKES_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE:                          return NULL;
    case STATE_STAKES_UNUSED:                                                          return NULL;
    case STATE_STAKES_EPOCH:                                                           return NULL;
    case STATE_STAKES_STAKE_HISTORY_LENGTH:                                            return (uchar*)&parser->length1;
    case STATE_STAKES_STAKE_HISTORY:                                                   return NULL;
    case STATE_UNUSED_ACCOUNTS1_LENGTH:                                                return (uchar*)&parser->length1;
    case STATE_UNUSED_ACCOUNTS1_UNUSED:                                                return NULL;
    case STATE_UNUSED_ACCOUNTS2_LENGTH:                                                return (uchar*)&parser->length1;
    case STATE_UNUSED_ACCOUNTS2_UNUSED:                                                return NULL;
    case STATE_UNUSED_ACCOUNTS3_LENGTH:                                                return (uchar*)&parser->length1;
    case STATE_UNUSED_ACCOUNTS3_UNUSED:                                                return NULL;
    case STATE_EPOCH_STAKES_LENGTH:                                                    return (uchar*)&parser->length1;
    case STATE_EPOCH_STAKES_KEY:                                                       return NULL;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_LENGTH:                                      return (uchar*)&parser->length2;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_KEY:                                         return NULL;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_STAKE:                                       return NULL;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_VALUE_LAMPORTS:                              return NULL;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_VALUE_DATA_LENGTH:                           return NULL;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_VALUE_DATA:                                  return NULL;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_VALUE_OWNER:                                 return NULL;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_VALUE_EXECUTABLE:                            return NULL;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_VALUE_RENT_EPOCH:                            return NULL;
    case STATE_EPOCH_STAKES_STAKE_DELEGATIONS_LENGTH:                                  return (uchar*)&parser->length2;
    case STATE_EPOCH_STAKES_STAKE_DELEGATIONS_KEY:                                     return NULL;
    case STATE_EPOCH_STAKES_STAKE_DELEGATIONS_VOTER_PUBKEY:                            return NULL;
    case STATE_EPOCH_STAKES_STAKE_DELEGATIONS_STAKE:                                   return NULL;
    case STATE_EPOCH_STAKES_STAKE_DELEGATIONS_ACTIVATION_EPOCH:                        return NULL;
    case STATE_EPOCH_STAKES_STAKE_DELEGATIONS_DEACTIVATION_EPOCH:                      return NULL;
    case STATE_EPOCH_STAKES_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE:                    return NULL;
    case STATE_EPOCH_STAKES_UNUSED:                                                    return NULL;
    case STATE_EPOCH_STAKES_EPOCH:                                                     return NULL;
    case STATE_EPOCH_STAKES_STAKE_HISTORY_LENGTH:                                      return (uchar*)&parser->length2;
    case STATE_EPOCH_STAKES_STAKE_HISTORY:                                             return NULL;
    case STATE_EPOCH_STAKES_TOTAL_STAKE:                                               return NULL;
    case STATE_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_LENGTH:                           return (uchar*)&parser->length2;
    case STATE_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_KEY:                              return NULL;
    case STATE_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_VOTE_ACCOUNTS_LENGTH:             return (uchar*)&parser->length3;
    case STATE_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_VOTE_ACCOUNTS:                    return NULL;
    case STATE_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_TOTAL_STAKE:                      return NULL;
    case STATE_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS_LENGTH:                            return (uchar*)&parser->length1;
    case STATE_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS:                                   return NULL;
    case STATE_IS_DELTA:                                                               return NULL;
    case STATE_ACCOUNTS_DB_STORAGES_LENGTH:                                            return (uchar*)&parser->length1;
    case STATE_ACCOUNTS_DB_STORAGES_SLOT:                                              return NULL;
    case STATE_ACCOUNTS_DB_STORAGES_ACCOUNT_VECS_LENGTH:                               return (uchar*)&parser->length2;
    case STATE_ACCOUNTS_DB_STORAGES_ACCOUNT_VECS:                                      return NULL;
    case STATE_ACCOUNTS_DB_VERSION:                                                    return NULL;
    case STATE_ACCOUNTS_DB_SLOT:                                                       return NULL;
    case STATE_ACCOUNTS_DB_BANK_HASH_INFO_ACCOUNTS_DELTA_HASH:                         return manifest->accounts_delta_hash;
    case STATE_ACCOUNTS_DB_BANK_HASH_INFO_ACCOUNTS_HASH:                               return manifest->accounts_hash;
    case STATE_ACCOUNTS_DB_BANK_HASH_INFO_STATS_NUM_UPDATED_ACCOUNTS:                  return NULL;
    case STATE_ACCOUNTS_DB_BANK_HASH_INFO_STATS_NUM_REMOVED_ACCOUNTS:                  return NULL;
    case STATE_ACCOUNTS_DB_BANK_HASH_INFO_STATS_NUM_LAMPORTS_STORED:                   return NULL;
    case STATE_ACCOUNTS_DB_BANK_HASH_INFO_STATS_TOTAL_DATA_LEN:                        return NULL;
    case STATE_ACCOUNTS_DB_BANK_HASH_INFO_STATS_NUM_EXECUTABLE_ACCOUNTS:               return NULL;
    case STATE_ACCOUNTS_DB_HISTORICAL_ROOTS_LENGTH:                                    return (uchar*)&parser->length1;
    case STATE_ACCOUNTS_DB_HISTORICAL_ROOTS:                                           return NULL;
    case STATE_ACCOUNTS_DB_HISTORICAL_WITH_HASH_LENGTH:                                return (uchar*)&parser->length1;
    case STATE_ACCOUNTS_DB_HISTORICAL_WITH_HASH:                                       return NULL;
    case STATE_LAMPORTS_PER_SIGNATURE:                                                 return NULL;
    case STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_OPTION:                           return &parser->option;
    case STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_FULL_SLOT:                        return NULL;
    case STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_FULL_HASH:                        return NULL;
    case STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_FULL_CAPITALIZATION:              return NULL;
    case STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_INCREMENTAL_HASH:                 return NULL;
    case STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_INCREMENTAL_CAPITALIZATION:       return NULL;
    case STATE_EPOCH_ACCOUNT_HASH_OPTION:                                              return &parser->option;
    case STATE_EPOCH_ACCOUNT_HASH:                                                     return manifest->epoch_account_hash;
    case STATE_VERSIONED_EPOCH_STAKES_LENGTH:                                          return (uchar*)&parser->epoch_stakes_len;
    case STATE_VERSIONED_EPOCH_STAKES_EPOCH:                                           return (uchar*)&parser->epoch_stakes_epoch;
    case STATE_VERSIONED_EPOCH_STAKES_VARIANT:                                         return (uchar*)&parser->variant;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_LENGTH:                     return (uchar*)&parser->length2;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_KEY:                        return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_STAKE:                      return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_LAMPORTS:             return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA_LENGTH:          return (uchar*)&parser->length3;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_DATA:                 return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_OWNER:                return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_EXECUTABLE:           return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_RENT_EPOCH:           return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_LENGTH:                 return parser->epoch_idx!=ULONG_MAX ? (uchar*)&manifest->epoch_stakes[ parser->epoch_idx ].stakes_len : (uchar*)&parser->length2;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_KEY:                    return parser->epoch_idx!=ULONG_MAX ? manifest->epoch_stakes[ parser->epoch_idx ].stakes[ idx1 ].stake_account_pubkey : NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_VOTER_PUBKEY:           return parser->epoch_idx!=ULONG_MAX ? manifest->epoch_stakes[ parser->epoch_idx ].stakes[ idx1 ].vote_account_pubkey : NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_STAKE:                  return parser->epoch_idx!=ULONG_MAX ? (uchar*)&manifest->epoch_stakes[ parser->epoch_idx ].stakes[ idx1 ].stake : NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_ACTIVATION_EPOCH:       return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_DEACTIVATION_EPOCH:     return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE:   return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_CREDITS_OBSERVED:       return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_UNUSED:                                   return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_EPOCH:                                    return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_HISTORY_LENGTH:                     return (uchar*)&parser->length2;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_HISTORY:                            return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_TOTAL_STAKE:                                     return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_LENGTH:                 return (uchar*)&parser->length2;
    case STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_KEY:                    return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_VOTE_ACCOUNTS_LENGTH:   return (uchar*)&parser->length3;
    case STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_VOTE_ACCOUNTS:          return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_TOTAL_STAKE:            return NULL;
    case STATE_VERSIONED_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS_LENGTH:                  return (uchar*)&parser->length2;
    case STATE_VERSIONED_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS:                         return NULL;
    case STATE_LTHASH_OPTION:                                                          return &parser->option;
    case STATE_LTHASH:                                                                 return manifest->accounts_lthash;
    case STATE_DONE:                                                                   return NULL;
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
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_COMMISSION:
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
    case STATE_STAKES_VOTE_ACCOUNTS_LENGTH: {
      if( FD_UNLIKELY( manifest->vote_accounts_len>sizeof(manifest->vote_accounts)/sizeof(manifest->vote_accounts[0]) ) ) {
        FD_LOG_WARNING(( "invalid vote_accounts_len %lu", manifest->vote_accounts_len ));
        return -1;
      }
      break;
    }
    case STATE_STAKES_STAKE_DELEGATIONS_LENGTH: {
      ulong stakes_cap = sizeof(manifest->epoch_stakes[ 0UL ].stakes)/sizeof(manifest->epoch_stakes[ 0UL ].stakes[ 0UL ]);
      if( FD_UNLIKELY( parser->length1>stakes_cap ) ) {
        FD_LOG_WARNING(( "invalid stakes_stake_delegations length %lu", parser->length1 ));
        return -1;
      }
      break;
    }
    case STATE_EPOCH_STAKES_LENGTH: {
      if( FD_UNLIKELY( parser->length1 ) ) {
        FD_LOG_WARNING(( "invalid epoch_stakes length %lu", parser->length1 ));
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
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_LENGTH: {
      if( FD_UNLIKELY( parser->length2>(1UL<<16UL ) ) ) {
        FD_LOG_WARNING(( "invalid versioned epoch stakes vote accounts length %lu", parser->length2 ));
        return -1;
      }
      break;
    }
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_LENGTH: {
      ulong stakes_len = parser->epoch_idx!=ULONG_MAX ? manifest->epoch_stakes[ parser->epoch_idx ].stakes_len : parser->length2;
      ulong stakes_cap = sizeof(manifest->epoch_stakes[ 0UL ].stakes)/sizeof(manifest->epoch_stakes[ 0UL ].stakes[ 0UL ]);
      if( FD_UNLIKELY( stakes_len>stakes_cap ) ) {
        FD_LOG_WARNING(( "invalid versioned epoch stakes stake delegation length %lu", stakes_len ));
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
        FD_LOG_WARNING(( "invalid vote_accounts value data length %lu", parser->length3 ));
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

static inline void
state_process( fd_ssmanifest_parser_t * parser ) {
  fd_snapshot_manifest_t * manifest = parser->manifest;

  FD_TEST( parser->state!=STATE_DONE );

  if( FD_UNLIKELY( parser->state==STATE_VERSIONED_EPOCH_STAKES_EPOCH ) ) {
    ulong epoch_delta = parser->epoch-parser->epoch_stakes_epoch;
    parser->epoch_idx = epoch_delta<3UL ? epoch_delta : ULONG_MAX;
  }

  if( FD_UNLIKELY( parser->state==STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_LENGTH && !parser->length2 ) ) {
    parser->state = STATE_STAKES_VOTE_ACCOUNTS_VALUE_OWNER;
    return;
  }

  if( FD_UNLIKELY( parser->state==STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_VARIANT ) ) {
    switch( parser->variant ) {
      case 2: parser->state = STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_NODE_PUBKEY; return;
      case 1: parser->state = STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_NODE_PUBKEY; return;
      case 0: parser->state = STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_NODE_PUBKEY; return;
    }
  }

  if( FD_UNLIKELY( parser->state==STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_LENGTH ) ) parser->account_data_start = parser->off;

  switch( parser->state ) {
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_LAST_TIMESTAMP_TIMESTAMP:
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_LAST_TIMESTAMP_TIMESTAMP:
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_LAST_TIMESTAMP_TIMESTAMP:
      parser->state = STATE_STAKES_VOTE_ACCOUNTS_VALUE_OWNER;
      return;
    default: break;
  }

  switch( parser->state ) {
    case STATE_HASHES_PER_TICK_OPTION:    manifest->has_hashes_per_tick    = !!parser->option; parser->state += 2-!!parser->option; return;
    case STATE_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_OPTION: {
      if( FD_LIKELY( !!parser->option ) ) parser->state += 1;
      else                                parser->state = STATE_EPOCH_ACCOUNT_HASH_OPTION;
      return;
    }
    case STATE_EPOCH_ACCOUNT_HASH_OPTION: manifest->has_epoch_account_hash = !!parser->option; parser->state += 2-!!parser->option; return;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_CURRENT_ROOT_SLOT_OPTION: parser->state += 2-!!parser->option; return;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V11411_ROOT_SLOT_OPTION: parser->state += 2-!!parser->option; return;
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_DATA_V0235_ROOT_SLOT_OPTION: parser->state += 2-!!parser->option; return;
    case STATE_LTHASH_OPTION:             manifest->has_accounts_lthash    = !!parser->option; parser->state += 2-!!parser->option; return;
    default: break;
  }

  ulong length = 0UL;
  ulong * idx;
  int next_target = INT_MAX;
  switch( parser->state ) {
    case STATE_STAKES_VOTE_ACCOUNTS_LENGTH:                            length = manifest->vote_accounts_len; idx = &parser->idx1; next_target = STATE_STAKES_STAKE_DELEGATIONS_LENGTH;                        break;
    case STATE_STAKES_STAKE_DELEGATIONS_LENGTH:                        length = parser->length1;             idx = &parser->idx1; next_target = STATE_STAKES_UNUSED;                                          break;
    case STATE_EPOCH_STAKES_LENGTH:                                    length = parser->length1;             idx = &parser->idx1; next_target = STATE_IS_DELTA;                                               break;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_LENGTH:                      length = parser->length2;             idx = &parser->idx2; next_target = STATE_EPOCH_STAKES_STAKE_DELEGATIONS_LENGTH;                  break;
    case STATE_EPOCH_STAKES_STAKE_DELEGATIONS_LENGTH:                  length = parser->length2;             idx = &parser->idx2; next_target = STATE_EPOCH_STAKES_UNUSED;                                    break;
    case STATE_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_LENGTH:           length = parser->length2;             idx = &parser->idx2; next_target = STATE_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS_LENGTH;            break;
    case STATE_ACCOUNTS_DB_STORAGES_LENGTH:                            length = parser->length1;             idx = &parser->idx1; next_target = STATE_ACCOUNTS_DB_VERSION;                                    break;
    case STATE_VERSIONED_EPOCH_STAKES_LENGTH:                          length = parser->epoch_stakes_len;    idx = &parser->idx1; next_target = STATE_LTHASH_OPTION;                                          break;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_LENGTH:     length = parser->length2;             idx = &parser->idx2; next_target = STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_LENGTH; break;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_LENGTH: length = parser->epoch_idx!=ULONG_MAX ? manifest->epoch_stakes[ parser->epoch_idx ].stakes_len : parser->length2; idx = &parser->idx2; next_target = STATE_VERSIONED_EPOCH_STAKES_STAKES_UNUSED; break;
    case STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_LENGTH: length = parser->length2;             idx = &parser->idx2; next_target = STATE_VERSIONED_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS_LENGTH;  break;
    default: break;
  }

  if( FD_UNLIKELY( next_target!=INT_MAX ) ) {
    *idx = 0UL;
    if( FD_UNLIKELY( !length ) ) {
      parser->state = next_target;
      return;
    }
  }

  int iter_target = INT_MAX;
  switch( parser->state ) {
    case STATE_STAKES_VOTE_ACCOUNTS_VALUE_RENT_EPOCH:                            length = manifest->vote_accounts_len; idx = &parser->idx1; next_target = STATE_STAKES_STAKE_DELEGATIONS_LENGTH;                        iter_target = STATE_STAKES_VOTE_ACCOUNTS_LENGTH+1UL;                            break;
    case STATE_STAKES_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE:                    length = parser->length1;             idx = &parser->idx1; next_target = STATE_STAKES_UNUSED;                                          iter_target = STATE_STAKES_STAKE_DELEGATIONS_LENGTH+1UL;                        break;
    case STATE_EPOCH_STAKES_VOTE_ACCOUNTS_VALUE_RENT_EPOCH:                      length = parser->length2;             idx = &parser->idx2; next_target = STATE_EPOCH_STAKES_STAKE_DELEGATIONS_LENGTH;                  iter_target = STATE_EPOCH_STAKES_VOTE_ACCOUNTS_LENGTH+1UL;                      break;
    case STATE_EPOCH_STAKES_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE:              length = parser->length2;             idx = &parser->idx2; next_target = STATE_EPOCH_STAKES_UNUSED;                                    iter_target = STATE_EPOCH_STAKES_STAKE_DELEGATIONS_LENGTH+1UL;                  break;
    case STATE_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_TOTAL_STAKE:                length = parser->length2;             idx = &parser->idx2; next_target = STATE_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS_LENGTH;            iter_target = STATE_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_LENGTH+1UL;           break;
    case STATE_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS:                             length = parser->length1;             idx = &parser->idx1; next_target = STATE_IS_DELTA;                                               iter_target = STATE_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS_LENGTH+1UL;            break;
    case STATE_ACCOUNTS_DB_STORAGES_ACCOUNT_VECS:                                length = parser->length1;             idx = &parser->idx1; next_target = STATE_ACCOUNTS_DB_VERSION;                                    iter_target = STATE_ACCOUNTS_DB_STORAGES_LENGTH+1UL;                            break;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_VALUE_RENT_EPOCH:     length = parser->length2;             idx = &parser->idx2; next_target = STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_LENGTH; iter_target = STATE_VERSIONED_EPOCH_STAKES_STAKES_VOTE_ACCOUNTS_LENGTH+1UL;     break;
    case STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_CREDITS_OBSERVED: length = parser->epoch_idx!=ULONG_MAX ? manifest->epoch_stakes[ parser->epoch_idx ].stakes_len : parser->length2; idx = &parser->idx2; next_target = STATE_VERSIONED_EPOCH_STAKES_STAKES_UNUSED;                   iter_target = STATE_VERSIONED_EPOCH_STAKES_STAKES_STAKE_DELEGATIONS_LENGTH+1UL; break;
    case STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_TOTAL_STAKE:      length = parser->length2;             idx = &parser->idx2; next_target = STATE_VERSIONED_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS_LENGTH;  iter_target = STATE_VERSIONED_EPOCH_STAKES_NODE_ID_TO_VOTE_ACCOUNTS_LENGTH+1UL; break;
    case STATE_VERSIONED_EPOCH_STAKES_EPOCH_AUTHORIZED_VOTERS:                   length = parser->epoch_stakes_len;    idx = &parser->idx1; next_target = STATE_LTHASH_OPTION;                                          iter_target = STATE_VERSIONED_EPOCH_STAKES_LENGTH+1UL;                          break;
    default: break;
  }
  
  if( FD_UNLIKELY( iter_target!=INT_MAX ) ) {
    *idx += 1UL;
    if( FD_LIKELY( *idx<length ) ) parser->state = iter_target;
    else                           parser->state = next_target;
    return;
  }

  parser->state += 1;
}

FD_FN_CONST ulong
fd_ssmanifest_parser_align( void ) {
  return alignof(fd_ssmanifest_parser_t);
}

FD_FN_CONST ulong
fd_ssmanifest_parser_footprint( void ) {
  return sizeof(fd_ssmanifest_parser_t);
}

void *
fd_ssmanifest_parser_new( void * shmem ) {
  fd_ssmanifest_parser_t * parser = (fd_ssmanifest_parser_t *)shmem;

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, alignof(fd_ssmanifest_parser_t) ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

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

    if( FD_LIKELY( parser->dst && consume ) ) fd_memcpy( parser->dst+parser->dst_cur, buf, consume );

    parser->off     += consume;
    parser->dst_cur += consume;
    buf             += consume;
    bufsz           -= consume;

    // FD_LOG_WARNING(( "Consumed %lu new (%lu/%lu) bytes", consume, parser->dst_cur, parser->dst_sz ));

    if( FD_LIKELY( parser->dst_cur==parser->dst_sz ) ) {
#if SSMANIFEST_DEBUG
      state_log( parser );
#endif
      if( FD_UNLIKELY( -1==state_validate( parser ) ) ) return -1;
      state_process( parser );
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
