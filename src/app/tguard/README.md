# Turbine Guard

## Why Turbine Guard?

### Analogous answer for the intuitively minded
- You are tasked to deliver a batch (**slot or block**) of boxes (**FEC sets**) of cookies (**shreds**)
  across a corridor (**Internet**) pestered by a cookie monster (network glitches) that likes to spoil your delivery for fun.
  - Your cookie boxes have the magic power to reproduce the lost cookies if the loss is less than 1/2 (**roughly**) box.
  - Luckily the cookie monster is lazy, it only takes a bite once in a while.
  - Unfortunately the cookie monster has a mouth that can chew up over 1/2 box of cookies at a time.
    - so if you are unlucky (alas it is likely) the cookie monster landed just one big-mouth bite on your batch of cookies, then the delivery is considered as failed.
- But you are smart, you will outmaneuver the cookie monster by using turbine guard to:
  - re-mix all the cookies, making the cookies from the same box seperated as far as possible
  - so when the cookie monster takes an occassional bite, even a big one that gobbles up more than 1 box of cookies, you can rest for sure that:
    - You eggs are not in one basket, atually cookies from the same box are not all in the mouth of the cookie monster
    - You have a much much (orders of magnitude) better chance that each box has more than 1/2 of the cookies survived 
    - Hence you will make good deliveries with much much higher probability
      - So you can be sure you will get paid (**SOL reward**) for your delvery effort
### Analytical answer for the numerically minded
- Optimization Objective: minimize the odds of the loss of shreds from the same FEC set that exceeds the capability of the FEC recovery capablity.
  - This can be achieved by ***maximizing the minimum spacing betweeen any two originally adjacent shreds*** in a new transmission sequence that Turbine Guard produces.
- Optimal ***Stride*** = $\sqrt{N}$ with ***N*** being the total number of shreds in one slot.
  - For typical 5000 TPS:
    - 2000 T per slot
    - 500 Data Shreds per slot
    - ***N*** = 1000 Data+Code Shreds per slot
    - $\sqrt{1000}$ = 31.62
    - Use ***Stride*** = 32 in practice
- Improvemet of robustness against packet loss of 32 adjacent shreds with ***p*** being the probability of single packet/shred loss:
  - Probability of such loss from stride of 1: $P_{S1}$ = p<sup>32</sup>
  - Probability of such loss from stride of 32: $P_{S32}$ = p<sup>(N/32x31)</sup> 
  - Improvement as ratio of: $P_{S1}$ / $P_{S32}$ = p<sup>(32-N/32x31)</sup> = (1/p)<sup>(N/32x31-32)</sup>  ~= (1/p)<sup>N</sup>
  - Tablization of $P_{S1}$ / $P_{S32}$ for cases of ***p*** = $10^{-10}$, $10^{-30}$, and $10^{-50}$ below shows it is imperative to make use of Turbine Guard for high TPS operations which intrinsically have ***many more FEC sets*** in a slot/block and making the ***block delivery*** much more susceptible to the loss of just one FEC set and causing the corresponding slot unable to land on-chain, worst yet, causing chaining decision forks that impact overall network:
    | ***p*** | ***N***=1000 | ***N***=10,000 | ***N***=100,000 |
    | ----------- | ----------- | ----------- | ----------- |
    | 10<sup>-1</sup> | $10^{1,000}$ | $10^{10,000}$ | $10^{100,000}$ |
    | 10<sup>-3</sup> | $10^{3,000}$ | $10^{30,000}$ | $10^{300,000}$ |
    | 10<sup>-5</sup> | $10^{5,000}$ | $10^{50,000}$ | $10^{500,000}$ |
## How to make use of Turbine Guard to enhance my validator?
Turbine Guard is a [BITW](https://en.wikipedia.org/wiki/Bump-in-the-wire) that is to run alongside the validators to be protected against shred FEC set loss, just like a body guard, hence the name Turbine Guard. 

Moreover, this is a body guard with high capacity, one Turbine Guard can have multiple validators under its protection umbrella.

Running Turnine Guard is as simple as typing in 1,2,3..., literally. First let's lauch the command-n-control panel:
```
  $ cd firedancer                 # the root of repo if you are not there already
  $ src/app/tguard/fd_tguard_cnc  # cnc stands for command-n-control
```
Then you will be presented a set of choices to pick and run repeatedly:
```
     Choices available to run:
        0:  Cancel/None         : exit command-n-control  
        1:  edit_tguide_cfg     : vi review/edit config   
        2:  build_firedancer    : gen/updt executables    
        3:  setup_wksp          : setup data stores       
        4:  reset_wksp          : refresh data stores     
        5:  report_wksp_stats   : shm/wksp stats               
        6:  run_tguard_monitor  : tguard activities       
        7:  run_tguard          : run tmon & tqos         
        8:  halt_tmon           : halt turbine monitor    
        9:  halt_tqos           : halt turbine qos daemon 
        10: halt_main           : halt fd_tguard_run.bin  
        11: stress_test         : blast pcaps at tguide
     Enter choice id to run:
```
Alternatively, you can make **one-shot run** of fd_tguard_cnc like:
```
  $ src/app/tguard/fd_tguard_cnc <your choice ids>

  # example to edit config and then recompile:
  #   $ src/app/tguard/fd_tguard_cnc 1 2

  # example to halt tmon, tqos, and fd_tguard_run.bin :
  #   $ src/app/tguard/fd_tguard_cnc 8 9 10

```

When starting from scratch, you can just run through 1 to 7 in that order.

Cheers and have fun!