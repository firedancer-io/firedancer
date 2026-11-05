#include "fd_integer_inflation.c"
#include "fd_rewards.c"

#include <float.h>

#define DECAY_SCALE FD_INTEGER_INFLATION_DECAY_SCALE
#define RATE_SCALE  FD_INTEGER_INFLATION_RATE_SCALE
#define YEAR_NS     FD_INTEGER_INFLATION_YEAR_NS
#define TEST_RATE   (80000000000000UL)

#define U128( hi, lo ) ( ( ( (uint128)(hi) )<<64 ) | (uint128)(lo) )

static fd_bank_t bank[1];

/* https://github.com/anza-xyz/agave/blob/9bcf93e368b5fb52c21677ed8c7f0360eb93b5b7/math-utils/src/inflation.rs#L154-L163 */
static void
check_decay_matches_float( ulong ns,
                           uint  taper ) {
  uint128 factor;
  FD_TEST( !decay_per_slot( ns, taper, 100U, &factor ) );
  double actual   = (double)factor / (double)DECAY_SCALE;
  double expected = pow( 1.0-( (double)taper/100.0 ), (double)ns/(double)YEAR_NS );
  FD_TEST( fabs( actual-expected )<=( 2.0*DBL_EPSILON ) );
}

/* https://github.com/anza-xyz/agave/blob/9bcf93e368b5fb52c21677ed8c7f0360eb93b5b7/math-utils/src/inflation.rs#L166-L183 */
static void
test_factor_approximates_float( void ) {
  ulong const ns[] = { 400000000UL, 350000000UL, 300000000UL, 250000000UL, 200000000UL, 1000000UL, 6400001UL, 2000000000UL };
  for( ulong i=0UL; i<sizeof(ns)/sizeof(ns[0]); i++ ) {
    check_decay_matches_float( ns[i], 15U );
    check_decay_matches_float( ns[i], 30U );
  }
}

/* https://github.com/anza-xyz/agave/blob/9bcf93e368b5fb52c21677ed8c7f0360eb93b5b7/math-utils/src/inflation.rs#L186-L200 */
static void
test_invalid_inputs_and_overflow( void ) {
  uint128 out;
  FD_TEST(  decay_per_slot( 0UL,         15U,  100U, &out ) );
  FD_TEST(  decay_per_slot( 400000000UL, 0U,   0U,   &out ) );
  FD_TEST(  decay_per_slot( 400000000UL, 100U, 100U, &out ) );
  FD_TEST(  decay_per_slot( 400000000UL, 101U, 100U, &out ) );
  FD_TEST(  decay_per_slot( ULONG_MAX,   15U,  100U, &out ) );
  FD_TEST(  approximate_logarithm( 1U, 0U, &out ) );
  FD_TEST(  approximate_logarithm( 1U, 2U, &out ) );
  FD_TEST( !approximate_logarithm( UINT_MAX, 1U, &out ) && out==U128( 0x5UL, 0x6de5b9b70b18a7eeUL ) );
  FD_TEST( !approximate_logarithm( UINT_MAX, UINT_MAX, &out ) && out==0 );
  FD_TEST( !decay_per_slot( 400000000UL, 0U, 100U, &out ) && out==DECAY_SCALE );
  FD_TEST(  approximate_exponential( DECAY_SCALE, &out ) );
}

/* https://github.com/anza-xyz/agave/blob/9bcf93e368b5fb52c21677ed8c7f0360eb93b5b7/math-utils/src/inflation.rs#L203-L221 */
static void
test_accumulated_decay( void ) {
  FD_TEST( mul_decay_floor( DECAY_SCALE, DECAY_SCALE )==DECAY_SCALE );
  FD_TEST( mul_decay_floor( DECAY_SCALE, 0           )==0           );
  FD_TEST( mul_decay_floor( 0,           DECAY_SCALE )==0           );
  FD_TEST( mul_decay_floor( U128( 0UL, ULONG_MAX ), U128( 0UL, ULONG_MAX ) )==U128( 0UL, ULONG_MAX-1UL ) );

  uint128 out;
  FD_TEST( !pow_decay_floor( 0, 0UL, &out ) && out==DECAY_SCALE );
  FD_TEST( !pow_decay_floor( DECAY_SCALE, ULONG_MAX, &out ) && out==DECAY_SCALE );
  FD_TEST(  pow_decay_floor( DECAY_SCALE+1, 0UL, &out ) );

  uint128 factor;
  FD_TEST( !decay_per_slot( 400000000UL, 15U, 100U, &factor ) );
  FD_TEST( !pow_decay_floor( factor, 432000UL, &out ) && out==U128( 0UL, 0xffc5b4310aec1600UL ) );
  FD_TEST( !pow_decay_floor( factor, ULONG_MAX, &out ) && out==0 );
}

/* https://github.com/anza-xyz/agave/blob/9bcf93e368b5fb52c21677ed8c7f0360eb93b5b7/math-utils/src/inflation.rs#L224-L261 */
static void
test_rates_and_rewards( void ) {
  ulong out;
  FD_TEST( !decayed_rate( TEST_RATE, 15U, 100U, 400000000UL, 0UL,      &out ) && out==TEST_RATE );
  FD_TEST( !decayed_rate( TEST_RATE, 15U, 100U, 400000000UL, 432000UL, &out ) && out==79928837736000UL );
  FD_TEST(  decayed_rate( TEST_RATE, 15U, 0U,   400000000UL, 0UL,      &out ) );
  FD_TEST(  decayed_rate( RATE_SCALE+1UL, 15U, 100U, 400000000UL, 0UL, &out ) );

  FD_TEST( !epoch_reward( 100UL, RATE_SCALE/10UL, 11UL, YEAR_NS/2UL, &out ) && out==55UL );
  FD_TEST( !epoch_reward( 3UL,   RATE_SCALE/2UL,  3UL,  YEAR_NS/2UL, &out ) && out==1UL );

  FD_TEST( !apply_decay_floor( TEST_RATE, DECAY_SCALE, &out ) && out==TEST_RATE );
  FD_TEST( !apply_decay_floor( TEST_RATE, 0,           &out ) && out==0UL       );
  FD_TEST(  apply_decay_floor( TEST_RATE, DECAY_SCALE+1, &out ) );
  ulong anchor;
  FD_TEST( !apply_decay_floor( TEST_RATE, U128( 0UL, 0xffc5b4310ae58008UL ), &anchor ) && anchor==79928837735998UL );
  FD_TEST( !decayed_rate( anchor, 30U, 100U, 400000000UL, 0UL, &out ) && out==anchor );

  FD_TEST(  epoch_reward( ULONG_MAX, RATE_SCALE,      ULONG_MAX, ULONG_MAX,   &out ) );
  FD_TEST(  epoch_reward( ULONG_MAX, RATE_SCALE,      2UL,       ULONG_MAX,   &out ) );
  FD_TEST(  epoch_reward( 100UL,     TEST_RATE,       432000UL,  0UL,         &out ) );
  FD_TEST(  epoch_reward( 100UL,     RATE_SCALE+1UL,  432000UL,  400000000UL, &out ) );
}

static void
reset_bank( ulong                    slots_per_epoch,
            int                      warmup,
            ulong                    first_normal_epoch,
            ulong                    first_normal_slot,
            fd_slot_params_t const * base ) {
  memset( bank, 0, sizeof(fd_bank_t) );
  bank->f.epoch_schedule = (fd_epoch_schedule_t){
    .slots_per_epoch             = slots_per_epoch,
    .leader_schedule_slot_offset = slots_per_epoch,
    .warmup                      = !!warmup,
    .first_normal_epoch          = first_normal_epoch,
    .first_normal_slot           = first_normal_slot,
  };
  bank->f.slot_params_default = *base;
  fd_features_disable_all( &bank->f.features );
  bank->f.features.remove_runtime_float_ops = 0UL;
}

static void
set_epoch( ulong epoch ) {
  bank->f.epoch = epoch;
  bank->f.slot  = fd_epoch_slot0( &bank->f.epoch_schedule, epoch );
}

/* https://github.com/anza-xyz/agave/blob/9bcf93e368b5fb52c21677ed8c7f0360eb93b5b7/runtime/src/bank/tests.rs#L6982-L7025 */
static void
test_historical_slot_time_decay( void ) {
  reset_bank( 32UL, 0, 0UL, 0UL, &FD_SLOT_PARAMS_400MS );
  bank->f.features.reduce_slot_time_to_200ms = 1UL;

  FD_TEST( fd_slot_params_at_slot( bank, 31UL ).ns_per_slot==FD_SLOT_PARAMS_400MS.ns_per_slot );
  FD_TEST( fd_slot_params_at_slot( bank, 32UL ).ns_per_slot==FD_SLOT_PARAMS_200MS.ns_per_slot );

  ulong at_transition, expected, split, joined;
  FD_TEST( !decayed_rate( FD_INTEGER_INFLATION_INITIAL_RATE, 15U, 100U, 400000000UL, 32UL, &at_transition ) );
  FD_TEST( !decayed_rate( at_transition,                     15U, 100U, 200000000UL, 32UL, &expected      ) );
  FD_TEST( integer_inflation_rate_between( bank, FD_INTEGER_INFLATION_INITIAL_RATE, 0UL, 64UL, 15U )==expected );
  FD_TEST( integer_inflation_rate_between( bank, FD_INTEGER_INFLATION_INITIAL_RATE, 0UL, 0UL,  15U )==FD_INTEGER_INFLATION_INITIAL_RATE );

  reset_bank( 32UL, 0, 0UL, 0UL, &FD_SLOT_PARAMS_400MS );
  FD_TEST( !decayed_rate( FD_INTEGER_INFLATION_INITIAL_RATE, 15U, 100U, 400000000UL, 64UL, &joined ) );
  FD_TEST( !decayed_rate( FD_INTEGER_INFLATION_INITIAL_RATE, 15U, 100U, 400000000UL, 32UL, &split  ) );
  FD_TEST( !decayed_rate( split,                             15U, 100U, 400000000UL, 32UL, &split  ) );
  FD_TEST( integer_inflation_rate_between( bank, FD_INTEGER_INFLATION_INITIAL_RATE, 0UL, 64UL, 15U )==joined );
}

struct scenario {
  ulong                    slots_per_epoch;
  int                      warmup;
  ulong                    first_normal_epoch;
  ulong                    first_normal_slot;
  fd_slot_params_t const * base;
  ulong                    act_cnt;
  struct { ulong off; ulong slot; } act[ 8 ];
};
typedef struct scenario scenario_t;

#define OFF( name ) offsetof( fd_features_t, name )
#define F350 OFF( reduce_slot_time_to_350ms )
#define F300 OFF( reduce_slot_time_to_300ms )
#define F250 OFF( reduce_slot_time_to_250ms )
#define F200 OFF( reduce_slot_time_to_200ms )
#define FDD  OFF( double_disinflation_rate  )
#define FDT  OFF( devnet_and_testnet        )
#define E( n ) ( (n)*432000UL )

static scenario_t const scenarios[] = {
  {     32UL, 0, 0UL,  0UL, &FD_SLOT_PARAMS_400MS, 0UL, {{0}} },
  {     32UL, 0, 0UL,  0UL, &FD_SLOT_PARAMS_400MS, 4UL, { {F350,40UL}, {F300,70UL}, {F250,100UL}, {F200,130UL} } },
  {     32UL, 0, 0UL,  0UL, &FD_SLOT_PARAMS_400MS, 5UL, { {F350,40UL}, {F300,70UL}, {F250,100UL}, {F200,130UL}, {FDD,131UL} } },
  {     32UL, 0, 0UL,  0UL, &FD_SLOT_PARAMS_400MS, 5UL, { {F350,40UL}, {F300,70UL}, {F250,100UL}, {F200,130UL}, {FDD,64UL} } },
  {     32UL, 0, 0UL,  0UL, &FD_SLOT_PARAMS_400MS, 4UL, { {F250,40UL}, {F300,70UL}, {F200,200UL}, {FDD,100UL} } },
  {     32UL, 0, 0UL,  0UL, &FD_SLOT_PARAMS_400MS, 6UL, { {F350,40UL}, {F300,70UL}, {F250,100UL}, {F200,130UL}, {FDT,70UL}, {FDD,150UL} } },
  {     32UL, 0, 0UL,  0UL, &FD_SLOT_PARAMS_400MS, 2UL, { {FDT,200UL}, {FDD,40UL} } },
  {     32UL, 0, 0UL,  0UL, &FD_SLOT_PARAMS_250MS, 2UL, { {F250,10UL}, {F200,100UL} } },
  {     32UL, 0, 0UL,  0UL, &FD_SLOT_PARAMS_250MS, 3UL, { {F350,10UL}, {F200,40UL}, {FDD,70UL} } },
  {    128UL, 1, 2UL, 96UL, &FD_SLOT_PARAMS_400MS, 4UL, { {F350,40UL}, {F300,300UL}, {FDD,500UL}, {F200,700UL} } },
  {     32UL, 0, 0UL,  0UL, &FD_SLOT_PARAMS_400MS, 2UL, { {FDD,0UL}, {F200,0UL} } },
  { 432000UL, 0, 0UL,  0UL, &FD_SLOT_PARAMS_400MS, 1UL, { {FDT,E(150)+5UL} } },
  { 432000UL, 0, 0UL,  0UL, &FD_SLOT_PARAMS_400MS, 6UL, { {FDT,E(150)+5UL}, {F350,E(900)}, {F300,E(910)+7UL}, {F250,E(920)}, {F200,E(940)+1UL}, {FDD,E(1070)+3UL} } },
};

struct scenario_vector {
  ulong scenario;
  ulong epoch;
  ulong rate;
  ulong reward;
  ulong prev_reward;
};
typedef struct scenario_vector scenario_vector_t;

static scenario_vector_t const scenario_vectors[] = {
{  0,    0UL, 80000000000000UL, 20280809357UL, ULONG_MAX },
  {  0,    1UL, 79999994726375UL, 20280808021UL, 20280808021UL },
  {  0,    2UL, 79999989452751UL, 20280806684UL, 20280806684UL },
  {  0,    3UL, 79999984179127UL, 20280805347UL, 20280805347UL },
  {  0,    4UL, 79999978905504UL, 20280804010UL, 20280804010UL },
  {  0,    5UL, 79999973631880UL, 20280802673UL, 20280802673UL },
  {  0,    6UL, 79999968358258UL, 20280801336UL, 20280801336UL },
  {  0,    7UL, 79999963084635UL, 20280799999UL, 20280799999UL },
  {  0,    8UL, 79999957811013UL, 20280798662UL, 20280798662UL },
  {  0,    9UL, 79999952537391UL, 20280797325UL, 20280797325UL },
  {  1,    0UL, 80000000000000UL, 20280809357UL, ULONG_MAX },
  {  1,    1UL, 79999994726375UL, 20280808021UL, 20280808021UL },
  {  1,    2UL, 79999989452751UL, 17745705848UL, 20280806684UL },
  {  1,    3UL, 79999984838330UL, 15210604135UL, 17745704825UL },
  {  1,    4UL, 79999980883112UL, 12675502819UL, 15210603383UL },
  {  1,    5UL, 79999977587097UL, 10140401838UL, 12675502297UL },
  {  1,    6UL, 79999974950285UL, 10140401503UL, 10140401503UL },
  {  1,    7UL, 79999972313473UL, 10140401169UL, 10140401169UL },
  {  1,    8UL, 79999969676662UL, 10140400835UL, 10140400835UL },
  {  1,    9UL, 79999967039851UL, 10140400501UL, 10140400501UL },
  {  2,    0UL, 80000000000000UL, 20280809357UL, ULONG_MAX },
  {  2,    1UL, 79999994726375UL, 20280808021UL, 20280808021UL },
  {  2,    2UL, 79999989452751UL, 17745705848UL, 20280806684UL },
  {  2,    3UL, 79999984838330UL, 15210604135UL, 17745704825UL },
  {  2,    4UL, 79999980883112UL, 12675502819UL, 15210603383UL },
  {  2,    5UL, 79999974018610UL, 10140401385UL, 12675501732UL },
  {  2,    6UL, 79999968231686UL, 10140400652UL, 10140400652UL },
  {  2,    7UL, 79999962444764UL, 10140399918UL, 10140399918UL },
  {  2,    8UL, 79999956657841UL, 10140399185UL, 10140399185UL },
  {  2,    9UL, 79999950870919UL, 10140398451UL, 10140398451UL },
  {  3,    0UL, 80000000000000UL, 20280809357UL, ULONG_MAX },
  {  3,    1UL, 79999994726375UL, 20280808021UL, 20280808021UL },
  {  3,    2UL, 79999989452751UL, 17745705848UL, 20280806684UL },
  {  3,    3UL, 79999979325633UL, 15210603087UL, 17745703602UL },
  {  3,    4UL, 79999970645247UL, 12675501197UL, 15210601437UL },
  {  3,    5UL, 79999963411593UL, 10140400041UL, 12675500051UL },
  {  3,    6UL, 79999957624670UL, 10140399307UL, 10140399307UL },
  {  3,    7UL, 79999951837748UL, 10140398574UL, 10140398574UL },
  {  3,    8UL, 79999946050827UL, 10140397840UL, 10140397840UL },
  {  3,    9UL, 79999940263906UL, 10140397107UL, 10140397107UL },
  {  4,    0UL, 80000000000000UL, 20280809357UL, ULONG_MAX },
  {  4,    1UL, 79999994726375UL, 20280808021UL, 20280808021UL },
  {  4,    2UL, 79999989452751UL, 12675504177UL, 20280806684UL },
  {  4,    3UL, 79999986156736UL, 12675503655UL, 12675503655UL },
  {  4,    4UL, 79999979415285UL, 12675502587UL, 12675502587UL },
  {  4,    5UL, 79999972181631UL, 12675501441UL, 12675501441UL },
  {  4,    6UL, 79999964947977UL, 12675500294UL, 12675500294UL },
  {  4,    7UL, 79999957714324UL, 10140399319UL, 12675499148UL },
  {  4,    8UL, 79999951927402UL, 10140398585UL, 10140398585UL },
  {  4,    9UL, 79999946140480UL, 10140397852UL, 10140397852UL },
  {  5,    0UL, 80000000000000UL, 20280809357UL, ULONG_MAX },
  {  5,    1UL, 79999994726375UL, 20280808021UL, 20280808021UL },
  {  5,    2UL, 79999989452751UL, 17745705848UL, 20280806684UL },
  {  5,    3UL, 79999990111953UL, 15210605138UL, 17745705994UL },
  {  5,    4UL, 79999986156735UL, 12675503655UL, 15210604386UL },
  {  5,    5UL, 79999981630206UL, 10140402350UL, 12675502938UL },
  {  5,    6UL, 79999975843282UL, 10140401617UL, 10140401617UL },
  {  5,    7UL, 79999970056359UL, 10140400883UL, 10140400883UL },
  {  5,    8UL, 79999964269436UL, 10140400149UL, 10140400149UL },
  {  5,    9UL, 79999958482513UL, 10140399416UL, 10140399416UL },
  {  6,    0UL, 80000000000000UL, 20280809357UL, ULONG_MAX },
  {  6,    1UL, 79999994726375UL, 20280808021UL, 20280808021UL },
  {  6,    2UL, 79999984727582UL, 20280805486UL, 20280805486UL },
  {  6,    3UL, 79999973153734UL, 20280802552UL, 20280802552UL },
  {  6,    4UL, 79999961579889UL, 20280799618UL, 20280799618UL },
  {  6,    5UL, 79999950006045UL, 20280796684UL, 20280796684UL },
  {  6,    6UL, 79999938432202UL, 20280793749UL, 20280793749UL },
  {  7,    0UL, 80000000000000UL, 12675505848UL, ULONG_MAX },
  {  7,    1UL, 79999996703984UL, 12675505326UL, 12675505326UL },
  {  7,    2UL, 79999993407968UL, 12675504804UL, 12675504804UL },
  {  7,    3UL, 79999990111953UL, 12675504282UL, 12675504282UL },
  {  7,    4UL, 79999986815938UL, 10140403007UL, 12675503759UL },
  {  7,    5UL, 79999984179126UL, 10140402673UL, 10140402673UL },
  {  7,    6UL, 79999981542314UL, 10140402339UL, 10140402339UL },
  {  7,    7UL, 79999978905502UL, 10140402005UL, 10140402005UL },
  {  7,    8UL, 79999976268691UL, 10140401670UL, 10140401670UL },
  {  7,    9UL, 79999973631879UL, 10140401336UL, 10140401336UL },
  {  8,    0UL, 80000000000000UL, 12675505848UL, ULONG_MAX },
  {  8,    1UL, 79999996703984UL, 12675505326UL, 12675505326UL },
  {  8,    2UL, 79999993407969UL, 10140403843UL, 12675504804UL },
  {  8,    3UL, 79999988211689UL, 10140403184UL, 10140403184UL },
  {  8,    4UL, 79999982424765UL, 10140402451UL, 10140402451UL },
  {  8,    5UL, 79999976637841UL, 10140401717UL, 10140401717UL },
  {  8,    6UL, 79999970850918UL, 10140400984UL, 10140400984UL },
  {  8,    7UL, 79999965063995UL, 10140400250UL, 10140400250UL },
  {  8,    8UL, 79999959277073UL, 10140399517UL, 10140399517UL },
  {  8,    9UL, 79999953490151UL, 10140398783UL, 10140398783UL },
  {  9,    0UL, 80000000000000UL, 20280809357UL, ULONG_MAX },
  {  9,    1UL, 79999994726375UL, 40561616042UL, 20280808021UL },
  {  9,    2UL, 79999984179127UL, 70982818715UL, 40561610694UL },
  {  9,    3UL, 79999965721446UL, 70982802338UL, 70982802338UL },
  {  9,    4UL, 79999947263770UL, 60842387966UL, 70982785960UL },
  {  9,    5UL, 79999931442907UL, 60842375934UL, 60842375934UL },
  {  9,    6UL, 79999899674620UL, 60842351773UL, 60842351773UL },
  {  9,    7UL, 79999864953120UL, 40561550244UL, 60842325366UL },
  {  9,    8UL, 79999841805461UL, 40561538508UL, 40561538508UL },
  {  9,    9UL, 79999818657809UL, 40561526771UL, 40561526771UL },
  { 10,    0UL, 80000000000000UL, 20280809357UL, ULONG_MAX },
  { 10,    1UL, 79999988426150UL, 10140403211UL, 20280806423UL },
  { 10,    2UL, 79999982639225UL, 10140402478UL, 10140402478UL },
  { 10,    3UL, 79999976852302UL, 10140401744UL, 10140401744UL },
  { 10,    4UL, 79999971065378UL, 10140401011UL, 10140401011UL },
  { 10,    5UL, 79999965278455UL, 10140400277UL, 10140400277UL },
  { 10,    6UL, 79999959491533UL, 10140399544UL, 10140399544UL },
  { 10,    7UL, 79999953704611UL, 10140398810UL, 10140398810UL },
  { 10,    8UL, 79999947917689UL, 10140398077UL, 10140398077UL },
  { 10,    9UL, 79999942130768UL, 10140397343UL, 10140397343UL },
  { 11,  150UL, 70002993814565UL, 239577306531894UL, 239577306531894UL },
  { 11,  151UL, 79857738772848UL, 273304053418153UL, 273304053418153UL },
  { 11,  500UL, 58537247014749UL, 200337088564172UL, 200337088564172UL },
  { 11,  900UL, 41004982623010UL, 140334902207623UL, 140334902207623UL },
  { 11,  901UL, 40968507530527UL, 140210070340636UL, 140210070340636UL },
  { 11,  902UL, 40932064883670UL, 140085349515124UL, 140085349515124UL },
  { 11,  911UL, 40605536361520UL, 138967842683205UL, 138967842683205UL },
  { 11,  921UL, 40245781030176UL, 137736620865432UL, 137736620865432UL },
  { 11,  941UL, 39535804166701UL, 135306805576362UL, 135306805576362UL },
  { 11, 1000UL, 37513511329553UL, 128385737711378UL, 128385737711378UL },
  { 11, 1069UL, 35279300463685UL, 120739404429021UL, 120739404429021UL },
  { 11, 1070UL, 35247918527518UL, 120632003311855UL, 120632003311855UL },
  { 11, 1071UL, 35216564506472UL, 120524697731025UL, 120524697731025UL },
  { 11, 1072UL, 35185238375715UL, 120417487601545UL, 120417487601545UL },
  { 11, 1100UL, 34319330048511UL, 117454014563740UL, 117454014563740UL },
  { 11, 1200UL, 31397125281917UL, 107453100188996UL, 107453100188996UL },
  { 11, 1500UL, 24040480276053UL, 82275817053292UL, 82275817053292UL },
  { 11, 1870UL, 17295859655674UL, 59193117960590UL, 59193117960590UL },
  { 11, 1880UL, 17142622479692UL, 58668681106081UL, 58668681106081UL },
  { 11, 1890UL, 16990742948404UL, 58148890636552UL, 58148890636552UL },
  { 11, 1900UL, 16840209033404UL, 57633705386148UL, 57633705386148UL },
  { 11, 2000UL, 15406307525470UL, 52726340109559UL, 52726340109559UL },
  { 11, 2050UL, 15000000000000UL, 51335798687380UL, 51335798687380UL },
  { 11, 2100UL, 15000000000000UL, 51335798687380UL, 51335798687380UL },
  { 11, 2500UL, 15000000000000UL, 51335798687380UL, 51335798687380UL },
  { 11, 3000UL, 15000000000000UL, 51335798687380UL, 51335798687380UL },
  { 12,  150UL, 70002993814565UL, 239577306531894UL, 239577306531894UL },
  { 12,  151UL, 79857738772848UL, 273304053418153UL, 273304053418153UL },
  { 12,  500UL, 58537247014749UL, 200337088564172UL, 200337088564172UL },
  { 12,  900UL, 41004982623010UL, 140334902207623UL, 140334902207623UL },
  { 12,  901UL, 40968507530527UL, 122683811548056UL, 140210070340636UL },
  { 12,  902UL, 40936618441141UL, 122588316855462UL, 122588316855462UL },
  { 12,  911UL, 40650731304441UL, 104341887936978UL, 121732202593141UL },
  { 12,  921UL, 40380314237517UL, 86373153442929UL, 103647784131515UL },
  { 12,  941UL, 39933610702701UL, 68334126663135UL, 85417658328919UL },
  { 12, 1000UL, 38898884725959UL, 66563510515181UL, 66563510515181UL },
  { 12, 1069UL, 37722743794832UL, 64550906046237UL, 64550906046237UL },
  { 12, 1070UL, 37705962338027UL, 64522189729962UL, 64522189729962UL },
  { 12, 1071UL, 37669158932694UL, 64459211989723UL, 64459211989723UL },
  { 12, 1072UL, 37632391310893UL, 64396295482023UL, 64396295482023UL },
  { 12, 1100UL, 36617341103916UL, 62659348379258UL, 62659348379258UL },
  { 12, 1200UL, 33210548971241UL, 56829668542833UL, 56829668542833UL },
  { 12, 1500UL, 24776719331471UL, 42397755857803UL, 42397755857803UL },
  { 12, 1870UL, 17263308123103UL, 29540857016194UL, 29540857016194UL },
  { 12, 1880UL, 17095544860717UL, 29253781647361UL, 29253781647361UL },
  { 12, 1890UL, 16929411906497UL, 28969496050922UL, 28969496050922UL },
  { 12, 1900UL, 16764893417256UL, 28687973116121UL, 28687973116121UL },
  { 12, 2000UL, 15205126779997UL, 26018910913133UL, 26018910913133UL },
  { 12, 2050UL, 15000000000000UL, 25667899343690UL, 25667899343690UL },
  { 12, 2100UL, 15000000000000UL, 25667899343690UL, 25667899343690UL },
  { 12, 2500UL, 15000000000000UL, 25667899343690UL, 25667899343690UL },
  { 12, 3000UL, 15000000000000UL, 25667899343690UL, 25667899343690UL },
};

#define CAPITALIZATION (625000000000000000UL)

static void
setup_scenario( scenario_t const * s ) {
  reset_bank( s->slots_per_epoch, s->warmup, s->first_normal_epoch, s->first_normal_slot, s->base );
  for( ulong i=0UL; i<s->act_cnt; i++ ) bank->f.features.f[ s->act[i].off>>3 ] = s->act[i].slot;
}

static void
test_scenarios( void ) {
  for( ulong i=0UL; i<sizeof(scenario_vectors)/sizeof(scenario_vectors[0]); i++ ) {
    scenario_vector_t const * v = &scenario_vectors[i];
    scenario_t const *        s = &scenarios[ v->scenario ];
    setup_scenario( s );
    set_epoch( v->epoch );

    FD_TEST( integer_inflation_rate( bank, inflation_start_slot_aligned_to_rewards( bank, &bank->f.epoch_schedule ) )==v->rate );
    FD_TEST( calculate_epoch_inflation_rewards( bank, CAPITALIZATION, v->epoch )==v->reward );
    if( v->epoch ) FD_TEST( calculate_epoch_inflation_rewards( bank, CAPITALIZATION, v->epoch-1UL )==v->prev_reward );

    ulong epoch_end = fd_epoch_slot0( &bank->f.epoch_schedule, v->epoch+1UL );
    for( ulong j=0UL; j<s->act_cnt; j++ ) {
      ulong slot = s->act[j].slot;
      if( s->act[j].off!=FDD || slot<=bank->f.slot || slot>=epoch_end ) continue;
      bank->f.slot = slot;
      FD_TEST( integer_inflation_rate( bank, inflation_start_slot_aligned_to_rewards( bank, &bank->f.epoch_schedule ) )==v->rate );
      bank->f.slot = fd_epoch_slot0( &bank->f.epoch_schedule, v->epoch );
    }
  }
}

/* https://github.com/anza-xyz/agave/blob/9bcf93e368b5fb52c21677ed8c7f0360eb93b5b7/runtime/src/bank/tests.rs#L7198-L7237
   https://github.com/anza-xyz/agave/blob/9bcf93e368b5fb52c21677ed8c7f0360eb93b5b7/runtime/src/bank/tests.rs#L7240-L7295 */
static void
test_feature_activation( void ) {
  fd_inflation_t const legacy = {
    .initial         = 0.15,
    .terminal        = 0.015,
    .taper           = 0.15,
    .foundation      = 0.05,
    .foundation_term = 7.0,
  };

  memset( bank, 0, sizeof(fd_bank_t) );
  bank->f.inflation = legacy;
  fd_apply_integer_inflation_initial_rate( bank );
  FD_TEST( bank->f.inflation.initial        ==0.08                    );
  FD_TEST( bank->f.inflation.terminal       ==legacy.terminal         );
  FD_TEST( bank->f.inflation.taper          ==legacy.taper            );
  FD_TEST( bank->f.inflation.foundation     ==legacy.foundation       );
  FD_TEST( bank->f.inflation.foundation_term==legacy.foundation_term  );

  bank->f.inflation = legacy;
  fd_apply_double_disinflation_rate( bank );
  FD_TEST( bank->f.inflation.initial        ==legacy.initial          );
  FD_TEST( bank->f.inflation.terminal       ==legacy.terminal         );
  FD_TEST( bank->f.inflation.taper          ==0.30                    );
  FD_TEST( bank->f.inflation.foundation     ==legacy.foundation       );
  FD_TEST( bank->f.inflation.foundation_term==legacy.foundation_term  );
}

static void
test_float_path_unchanged( void ) {
  reset_bank( 32UL, 0, 0UL, 0UL, &FD_SLOT_PARAMS_400MS );
  bank->f.features.remove_runtime_float_ops = FD_FEATURE_DISABLED;
  bank->f.inflation = (fd_inflation_t){ .initial = 0.08, .terminal = 0.015, .taper = 0.15 };
  set_epoch( 3UL );
  double year     = slot_in_year_for_inflation( bank );
  double duration = epoch_duration_in_years( bank, 2UL );
  ulong  expected = (ulong)( ( validator( &bank->f.inflation, year ) * (double)CAPITALIZATION ) * duration );
  FD_TEST( calculate_epoch_inflation_rewards( bank, CAPITALIZATION, 2UL )==expected );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_factor_approximates_float();
  test_invalid_inputs_and_overflow();
  test_accumulated_decay();
  test_rates_and_rewards();
  test_historical_slot_time_decay();
  test_scenarios();
  test_feature_activation();
  test_float_path_unchanged();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
