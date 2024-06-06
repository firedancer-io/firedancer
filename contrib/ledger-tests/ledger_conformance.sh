#!/bin/bash

# ledger_conformance is a CLI tool that provides a command line interface to consolidate bank hash mismatch debugging operations
# It currently manages operations like fetching, minimizing, replaying and uploading ledgers
# Refer to the README or usage() for detailed information

fetch-recent() {
  source ./fetch.sh
}

minify() {
  source ./minify.sh
}

replay() {
  source ./replay.sh
}

solcap() {
  source ./solcap.sh
}

one_repetition() {
  local rooted_start_slot=$(find_rooted_slot $START_SLOT "+")
  local rooted_end_slot=$(find_rooted_slot $END_SLOT "-")
  START_SLOT=$rooted_start_slot
  END_SLOT=$rooted_end_slot

  echo "running one repetition. current rooted repetition [$START_SLOT, $END_SLOT]"
  source $ROOT_DIR/minify.sh
  source $ROOT_DIR/replay.sh
}

all_repetition() {
  echo "running multiple repetitions. current maybe rooted repetition [$START_SLOT, $END_SLOT]"
  while [ $START_SLOT -le $END_SLOT ]; do
    # todo if it enters the second loop, there must have been a mismatch on (START_SLOT-1)
    # call the solcap diff here
    one_repetition
  done
}

all() {
  ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

  # Call the fetch script
  if [[ "$NO_FETCH" == "false" ]]; then
    source $ROOT_DIR/fetch.sh
  fi

  # Verify and set start and end slots
  source $ROOT_DIR/utils.sh
  set_default_slots

  # If --repetitions multiple, we run the pipeline continuously until the whole ledger is searched for BHMs
  if [ "$MODE" = "exact" ] && [ "$REPETITIONS" = "multiple" ]; then
    # If $REP_SZ is not specified, execute the pipeline from START_SLOT to END_SLOT in one go
    if [ -z "$REP_SZ" ]; then
      all_repetition

    # If $REP_SIZE is specified, divide the bounds START_SLOT-END_SLOT into chunks of REP_SIZE
    else
      original_start_slot=$START_SLOT
      original_end_slot=$END_SLOT

      for ((start_chunk = $original_start_slot; start_chunk <= $original_end_slot; start_chunk += $REP_SZ)); do
        end_chunk=$((start_chunk + REP_SZ - 1))
        if [[ $end_chunk -gt $original_end_slot ]]; then
          end_chunk=$original_end_slot
        fi

        START_SLOT=$start_chunk
        END_SLOT=$end_chunk
        all_repetition

        if [[ $end_chunk -ge $original_end_slot ]]; then
          break
        fi
      done
    fi
  # For all other modes, the pipeline is just ran once to find the first bank hash mismatch
  else
    one_repetition
  fi
}

usage() {
  if [[ $1 == "fetch-recent" ]]; then
    echo -e "Usage: $0 fetch-recent \n\
                --network -n             : Solana network to download the ledger from. Choose: mainnet|testnet|internal. \n\
                --ledger -l              : Directory to place the downloaded ledger in. \n\
                --solana-build-dir -d    : Path to the solana build directory. E.g. /home/fd_user/solana/target/debug"

  elif [[ $1 == "minify" ]]; then
    echo -e "Usage: $0 minify \n\
                --network -n                    : Solana network to download the ledger from. Choose: mainnet|testnet|internal. \n\
                --mode -m                       : Method to minimize the ledger. Either as an offset around an epoch edge, or defined as an exact start and end slot. Choose: edge|exact. \n\
                --ledger -l                     : Directory where the initial ledger can be found. \n\
                --ledger-min -z                 : Directory where the minimized ledger should be placed. \n\
                --edge-offset -o                : Required if the mode is edge, this defines the  number of slots to minimize on each side of the epoch boundary. \n\
                --start-slot -s                 : Required if the mode is exact, this defines the slot to start minimization. \n\
                --end-slot -e                   : Required if the mode is exact, this defines the slot to end minimization. \n\
                --solana-build-dir -d           : Path to the solana build directory. E.g. /home/fd_user/solana/target/debug \n\
                --firedancer-root-dir -f        : Path to the firedancer root directory. E.g. /home/fd_user/firedancer \n\
                --is-verify -v [Optional]       : If passed, use solana-ledger-tool to verify created ledgers. Default: false. \n\
                --slots-in-epoch -i [Optional]  : Slot count for an epoch in the defined network. Default: 432_000. \n\
                --gigantic-pages -g [Optional]  : Number of gigantic pages. Default: 128 \n\
                --index-max -x [Optional]       : Maximum index. Default: 100_000_000"
    echo "Note: This will remove the existing directory at <ledger_min_dir>"

  elif [[ $1 == "replay" ]]; then
    echo -e "Usage: $0 replay \n\
                --network -n                    : Solana network to download the ledger from. Choose: mainnet|testnet|internal. \n\
                --ledger -l                     : Directory where the ledger to be replayed can be found. \n\
                --start-slot -s                 : The slot to start replay. \n\
                --end-slot -e                   : The slot to end replay. \n\
                --firedancer-root-dir -f        : Path to the firedancer root directory. \n\
                --solana-build-dir -d           : Path to the solana build directory. E.g. /home/fd_user/solana/target/debug \n\
                --slots-in-epoch -i [Optional]  : Slot count for an epoch in the defined network. Default: 432_000. \n\
                --gigantic-pages -g [Optional]  : Number of gigantic pages. Default: 128 \n\
                --index-max -x [Optional]       : Maximum index. Default: 100_000_000 \n\
                --upload -u [Optional]          : Gcloud storage url for minimized ledger to be stored"
    echo "Note: This will remove the override the existing firedancer/dump directory"

  elif [[ $1 == "solcap" ]]; then
    echo -e "Usage: $0 solcap \n\
                --ledger -l                         : Directory where the ledger can be used for the solcap diff \n\
                --end-slot -e                       : End slot for the diff. \n\
                --firedancer-root-dir -f            : Path to the firedancer root directory. \n\
                --solana-build-dir -d               : Path to the solana build directory. E.g. /home/fd_user/solana/target/debug. \n\
                --checkpoint -c                     : Load from a checkpoint. \n\
                --solana-solcap -a [Optional]       : Path to the solana solcap. \n\
                --firedancer-solcap -b [Optional]   : Path to the firedancer solcap. \n\
                --verbosity -v [Optional]           : Verbosity level. Default: 4."

  elif [[ $1 == "all" ]]; then
    echo -e "Usage: $0 all \n\
                --network -n                    : Solana network to download the ledger from. Choose: mainnet|testnet|internal. \n\
                --mode -m                       : Method to minimize the ledger. Either as an offset around an epoch edge, or defined as an exact start and end slot. Choose: edge|exact. \n\
                --ledger -l                     : Directory where the initial ledger can be found. \n\
                --ledger-min -z                 : Directory where the minimized ledger should be placed. \n\
                --edge-offset -o                : Required if the mode is edge, this defines the number of slots to minimize on each side of the epoch boundary. \n\
                --start-slot -s                 : Required if the mode is exact and repetitions is once, this defines the slot to start minimization. \n\
                --end-slot -e                   : Required if the mode is exact and repetitions is once, this defines the slot to end minimization. \n\
                --repetitions -r                : Required if the mode is exact, running with multiple repetitions repeats the minify and replay for new slot ranges until the entire ledger is checked. Choose: once|multiple. \n\
                --rep-sz -w [Optional]          : Maximum size of each repetition \n\
                --solana-build-dir -d           : Path to the solana build directory. E.g. /home/fd_user/solana/target/debug \n\
                --firedancer-root-dir -f        : Path to the firedancer root directory. \n\
                --no-fetch [Optional]           : Run all the commands excluding fetch-recent. Just pass in the ledger directories. \n\
                --is-verify -v [Optional]       : If passed, use solana-ledger-tool to verify created ledgers. Default: false. \n\
                --slots-in-epoch -i [Optional]  : Slot count for an epoch in the defined network. Default: 432_000. \n\
                --gigantic-pages -g [Optional]  : Number of gigantic pages. Default: 128 \n\
                --index-max -x [Optional]       : Maximum index. Default: 100_000_000 \n\
                --upload -u [Optional]          : Gcloud storage url for minimized ledger to be stored. Default: None"
  else
    echo "General Usage: $0 <command> [options]"
    cat <<'EOF'
            SUBCOMMANDS:
                fetch-recent                            : Initialize the ledger tests by fetching a recent ledger
                minify                                  : Minimize a recent ledger snapshots and rocksdb
                    --mode edge                         : Minimize around an epoch edge with some offset
                    --mode exact                        : Minimize around a specific [start_slot, end_slot]
                replay                                  : Replay the minimized ledger to check for bank hash mismatches 
                                                            and upload the minimized one block ledger to the cloud storage
                solcap                                  : Produce a diff between firedancer and solana labs solcaps                                                            
                all                                     : Run all commands - fetch-recent, minify, replay in sequence
                                                          In the `all` subcommand, bounds are checked if rooted, if not it searches for a bound that is rooted.
                    --no-fetch                          : Run all the commands excluding fetch-recent. Just pass in the ledger directories.
                    --repetitions once --mode edge|exact: Run the full cycle of commands once
                    --repetitions multiple --mode exact : Replay the entire ledger in multiple iterations 
                                                        --start-slot and --end-slot define the absolute bounds to replay the ledger
                                                        If they are not specified (recommended), the check range is [first_rooted(max(snap, rocksdb_min)), last_rooted(rocksdb_max)] 
                                                        The replay looks for a mismatch from start_slot toward end_slot, until it encounters a mismatch. 
                                                        Then, it would start again from mismatch+1, repeating the cycle.
                                                        Depending on where these bank hash mismatches are encountered, 
                                                        a possible list of snapshots might look like [rocksdb_min, Abhm, rocksdb_max], (Abhm, Bbhm, rocksdb_max], ... (Ybhm, Zbhm, rocksdb_max]
                                                        which translates into the uploads [Abhm-1, Abhm+1], [Bbhm-1, Bbhm+1], ..., [Zbhm-1, Zbhm+1]
                    --repetitions multiple --mode exact --rep-sz 100: Breaks the ledger up into multiple repetitions of the specified size
                                                                    This has the same output as running without --rep-sz, but breaks the process up into multiple iterations of some rep size 
                                                                    Passing --rep-sz is only recommended if the ledger is too large, since this takes additional time to run
                                                                    (re: solana-ledger-tool possibly has some issues with minimizing larger ledgers?)
                                                                    For example, running this against a ledger with rocskdb bounds of size S, 
                                                                    will break into chunks [first_rooted(start_slot), last_rooted(start_slot + S/n - 1)], [first_rooted(start_slot + S/n), last_rooted(start_slot + 2S/n - 1)] ...
                                                                    Following, each of these chunks might have their own set of bank hash mismatches
                                                                    [first_rooted(start_slot), ABhm, Bbhm, Cbhm .... last_rooted(start_slot + S/n - 1)] 
EOF
  fi
  exit 1
}

parse_fetch_options() {
  TEMP=$(getopt -o n:l:d: --long network:,ledger:,solana-build-dir: -- "$@")
  if [ $? != 0 ]; then
    echo "Terminating..." >&2
    exit 1
  fi
  eval set -- "$TEMP"

  while true; do
    case "$1" in
      -n | --network)
        NETWORK="$2"
        shift 2
        ;;
      -l | --ledger)
        LEDGER="$2"
        shift 2
        ;;
      -d | --solana-build-dir)
        SOLANA_BUILD_DIR="$2"
        shift 2
        ;;
      --)
        shift
        break
        ;;
      *)
        echo "Internal error!"
        exit 1
        ;;
    esac
  done

  # Validation
  if [ -z "$NETWORK" ] || [ -z "$LEDGER" ] || [ -z "$SOLANA_BUILD_DIR" ]; then
    usage "fetch-recent"
    exit 1
  fi

  if [ "$NETWORK" != "mainnet" ] && [ "$NETWORK" != "testnet" ] && [ "$NETWORK" != "internal" ]; then
    echo "Invalid network: $NETWORK. Choose: mainnet|testnet|internal."
    exit 1
  fi

  if [ ! -d "$LEDGER" ]; then
    echo "error $LEDGER does not exist"
    exit 1
  fi

  SOLANA_LEDGER_TOOL="$SOLANA_BUILD_DIR/solana-ledger-tool"
  if [ ! -f "$SOLANA_LEDGER_TOOL" ]; then
    echo "error $SOLANA_LEDGER_TOOL does not exist"
    exit 1
  fi
}

parse_minify_options() {
  TEMP=$(getopt -o n:m:l:z:v:i:g:x:o:s:e:d:f: \
    --long network:,mode:,ledger:,ledger-min:,is-verify:,slots-in-epoch:,gigantic-pages:,index-max:,edge-offset:,start-slot:,end-slot:,solana-build-dir:,firedancer-root-dir: \
    -- "$@")

  if [ $? != 0 ]; then
    echo "Incorrect options provided" >&2
    exit 1
  fi

  eval set -- "$TEMP"

  # Defaults
  IS_VERIFY="false"
  SLOTS_IN_EPOCH=432000
  GIGANTIC_PAGES=128
  INDEX_MAX=100000000

  while true; do
    case "$1" in
      -n | --network)
        NETWORK="$2"
        shift 2
        ;;
      -m | --mode)
        MODE="$2"
        shift 2
        ;;
      -l | --ledger)
        LEDGER="$2"
        shift 2
        ;;
      -z | --ledger-min)
        LEDGER_MIN="$2"
        shift 2
        ;;
      -v | --is-verify)
        IS_VERIFY="true"
        shift 2
        ;;
      -i | --slots-in-epoch)
        SLOTS_IN_EPOCH="$2"
        shift 2
        ;;
      -g | --gigantic-pages)
        GIGANTIC_PAGES="$2"
        shift 2
        ;;
      -x | --index-max)
        INDEX_MAX="$2"
        shift 2
        ;;
      -o | --edge-offset)
        EDGE_OFFSET="$2"
        shift 2
        ;;
      -s | --start-slot)
        START_SLOT="$2"
        shift 2
        ;;
      -e | --end-slot)
        END_SLOT="$2"
        shift 2
        ;;
      -d | --solana-build-dir)
        SOLANA_BUILD_DIR="$2"
        shift 2
        ;;
      -f | --firedancer-root-dir)
        FIREDANCER="$2"
        shift 2
        ;;
      --)
        shift
        break
        ;;
      *)
        echo "Internal error! Option processing failed: $1" >&2
        exit 1
        ;;
    esac
  done

  if [ "$MODE" = "exact" ]; then
    if [ -z "$NETWORK" ] || [ -z "$MODE" ] \
      || [ -z "$LEDGER" ] || [ -z "$LEDGER_MIN" ] \
      || [ -z "$START_SLOT" ] || [ -z "$END_SLOT" ] \
      || [ -z "$SOLANA_BUILD_DIR" ] || [ -z "$FIREDANCER" ]; then
      echo "Missing required arguments for mode 'exact'."
      echo -e "required --mode exact flags are:\n\
                    --network -n,\n\
                    --mode -m,\n\
                    --ledger -l,\n\
                    --ledger-min -z,\n\
                    --start-slot -s,\n\
                    --end-slot -e,\n\
                    --solana-build-dir -d,\n\
                    --firedancer-root-dir -f."
      exit 1
    fi
  elif [ "$MODE" = "edge" ]; then
    if [ -z "$NETWORK" ] || [ -z "$MODE" ] \
      || [ -z "$LEDGER" ] || [ -z "$LEDGER_MIN" ] \
      || [ -z "$EDGE_OFFSET" ] || [ -z "$SOLANA_BUILD_DIR" ] \
      || [ -z "$FIREDANCER" ]; then
      echo "Missing required arguments for mode 'edge'."
      echo -e "required --mode edge flags are:\n\
                    --network -n,\n\
                    --mode -m,\n\
                    --ledger -l,\n\
                    --ledger-min -z,\n\
                    --edge-offset -o,\n\
                    --solana-build-dir -d,\n\
                    --firedancer-root-dir -f."
      exit 1
    fi
  else
    echo "Invalid mode: $MODE. Choose '--mode exact' or '--mode edge'."
    usage "minify"
    exit 1
  fi

  if [ "$NETWORK" != "mainnet" ] && [ "$NETWORK" != "testnet" ] && [ "$NETWORK" != "internal" ]; then
    echo "Invalid network: $NETWORK. Choose: mainnet|testnet|internal."
    exit 1
  fi

  if [ ! -d "$LEDGER" ]; then
    echo "error $LEDGER does not exist"
    exit 1
  fi

  SOLANA_LEDGER_TOOL="$SOLANA_BUILD_DIR/solana-ledger-tool"
  if [ ! -f "$SOLANA_LEDGER_TOOL" ]; then
    echo "error $SOLANA_LEDGER_TOOL does not exist"
    exit 1
  fi
}

parse_replay_options() {
  TEMP=$(getopt -o n:l:s:e:i:g:x:f:d:u: --long network:,ledger:,start-slot:,end-slot:,slots-in-epoch:,gigantic-pages:,index-max:,firedancer-root-dir:,solana-build-dir:,upload: -- "$@")
  if [ $? != 0 ]; then
    echo "Incorrect options provided" >&2
    exit 1
  fi
  eval set -- "$TEMP"

  # Defaults
  UPLOAD_URL=""
  GIGANTIC_PAGES=128
  INDEX_MAX=100000000
  SLOTS_IN_EPOCH=432000

  while true; do
    case "$1" in
      -n | --network)
        NETWORK="$2"
        shift 2
        ;;
      -l | --ledger)
        LEDGER_MIN="$2"
        shift 2
        ;;
      -s | --start-slot)
        START_SLOT="$2"
        shift 2
        ;;
      -e | --end-slot)
        END_SLOT="$2"
        shift 2
        ;;
      -i | --slots-in-epoch)
        SLOTS_IN_EPOCH="$2"
        shift 2
        ;;
      -g | --gigantic-pages)
        GIGANTIC_PAGES="$2"
        shift 2
        ;;
      -x | --index-max)
        INDEX_MAX="$2"
        shift 2
        ;;
      -f | --firedancer-root-dir)
        FIREDANCER="$2"
        shift 2
        ;;
      -d | --solana-build-dir)
        SOLANA_BUILD_DIR="$2"
        shift 2
        ;;
      -u | --upload)
        UPLOAD_URL="$2"
        shift 2
        ;;
      --)
        shift
        break
        ;;
      *)
        echo "Internal error! Option processing failed: $1" >&2
        exit 1
        ;;
    esac
  done

  if [ -z "$NETWORK" ] || [ -z "$LEDGER_MIN" ] || [ -z "$FIREDANCER" ] || [ -z "$SOLANA_BUILD_DIR" ] || [ -z "$START_SLOT" ] || [ -z "$END_SLOT" ]; then
    echo "Missing required arguments." >&2
    usage "replay"
    exit 1
  fi

  if [ "$NETWORK" != "mainnet" ] && [ "$NETWORK" != "testnet" ] && [ "$NETWORK" != "internal" ]; then
    echo "Invalid network: $NETWORK. Choose: mainnet|testnet|internal."
    exit 1
  fi

  if [ ! -d "$LEDGER_MIN" ]; then
    echo "error $LEDGER_MIN does not exist"
    exit 1
  fi

  SOLANA_LEDGER_TOOL="$SOLANA_BUILD_DIR/solana-ledger-tool"
  if [ ! -f "$SOLANA_LEDGER_TOOL" ]; then
    echo "error $SOLANA_LEDGER_TOOL does not exist"
    exit 1
  fi
}

parse_solcap_options() {
  TEMP=$(getopt -o l:e:f:d:c:a:b:v: --long ledger:,end-slot:,firedancer-root-dir:,solana-build-dir:,checkpoint:,solana-solcap:,firedancer-solcap:,verbosity: -- "$@")
  if [ $? != 0 ]; then
    echo "Incorrect options provided" >&2
    exit 1
  fi
  eval set -- "$TEMP"

  while true; do
    case "$1" in
      -l | --ledger)
        LEDGER_MIN="$2"
        shift 2
        ;;
      -e | --end-slot)
        END_SLOT="$2"
        shift 2
        ;;
      -f | --firedancer-root-dir)
        FIREDANCER="$2"
        shift 2
        ;;
      -d | --solana-build-dir)
        SOLANA_BUILD_DIR="$2"
        shift 2
        ;;
      -c | --checkpoint)
        CHECKPOINT="$2"
        shift 2
        ;;
      -a | --solana-solcap)
        SOLANA_SOLCAP="$2"
        shift 2
        ;;
      -b | --firedancer-solcap)
        FIREDANCER_SOLCAP="$2"
        shift 2
        ;;
      -v | --verbosity)
        VERBOSITY="$2"
        shift 2
        ;;
      --)
        shift
        break
        ;;
      *)
        echo "Internal error! Option processing failed: $1" >&2
        exit 1
        ;;
    esac
  done

  if [ -z "$LEDGER_MIN" ] || [ -z "$END_SLOT" ] || [ -z "$FIREDANCER" ] || [ -z "$SOLANA_BUILD_DIR" ] || [ -z "$CHECKPOINT" ]; then
    echo "Missing required arguments." >&2
    usage "solcap"
    exit 1
  fi
}

parse_all_options() {
  TEMP=$(getopt -o n:m:l:z:v:q:i:g:x:o:s:e:d:f:u:r:w: \
    --long network:,mode:,ledger:,ledger-min:,is-verify:,no-fetch,slots-in-epoch:,gigantic-pages:,index-max:,edge-offset:,start-slot:,end-slot:,solana-build-dir:,firedancer-root-dir:,upload:,repetitions:,rep-sz: \
    -- "$@")

  if [ $? != 0 ]; then
    echo "Incorrect options provided" >&2
    exit 1
  fi

  eval set -- "$TEMP"

  # Defaults
  IS_VERIFY="false"
  NO_FETCH="false"
  SLOTS_IN_EPOCH=432000
  UPLOAD_URL=""
  GIGANTIC_PAGES=128
  INDEX_MAX=100000000

  while true; do
    case "$1" in
      -n | --network)
        NETWORK="$2"
        shift 2
        ;;
      -m | --mode)
        MODE="$2"
        shift 2
        ;;
      -l | --ledger)
        LEDGER="$2"
        shift 2
        ;;
      -z | --ledger-min)
        LEDGER_MIN="$2"
        shift 2
        ;;
      -v | --is-verify)
        IS_VERIFY="true"
        shift 2
        ;;
      -q | --no-fetch)
        NO_FETCH="true"
        shift 1
        ;;
      -i | --slots-in-epoch)
        SLOTS_IN_EPOCH="$2"
        shift 2
        ;;
      -g | --gigantic-pages)
        GIGANTIC_PAGES="$2"
        shift 2
        ;;
      -x | --index-max)
        INDEX_MAX="$2"
        shift 2
        ;;
      -o | --edge-offset)
        EDGE_OFFSET="$2"
        shift 2
        ;;
      -s | --start-slot)
        START_SLOT="$2"
        shift 2
        ;;
      -e | --end-slot)
        END_SLOT="$2"
        shift 2
        ;;
      -d | --solana-build-dir)
        SOLANA_BUILD_DIR="$2"
        shift 2
        ;;
      -f | --firedancer-root-dir)
        FIREDANCER="$2"
        shift 2
        ;;
      -u | --upload)
        UPLOAD_URL="$2"
        shift 2
        ;;
      -r | --repetitions)
        REPETITIONS="$2"
        shift 2
        ;;
      -w | --rep-sz)
        REP_SZ="$2"
        shift 2
        ;;
      --)
        shift
        break
        ;;
      *)
        echo "Internal error! Option processing failed: $1" >&2
        exit 1
        ;;
    esac
  done

  if [ "$MODE" = "exact" ]; then
    if [ -z "$NETWORK" ] || [ -z "$MODE" ] \
      || [ -z "$LEDGER" ] || [ -z "$LEDGER_MIN" ] \
      || [ -z "$SOLANA_BUILD_DIR" ] || [ -z "$FIREDANCER" ] \
      || [ -z "$REPETITIONS" ]; then
      echo "Missing required arguments for mode 'exact'."
      echo -e "required --mode exact flags are:\n\
                    --network -n,\n\
                    --mode -m,\n\
                    --ledger -l,\n\
                    --ledger-min -z,\n\                                        
                    --solana-build-dir -d,\n\
                    --firedancer-root-dir -f,\n\                    
                    --repetitions -r."
      exit 1
    fi
  elif [ "$MODE" = "edge" ]; then
    if [ -z "$NETWORK" ] || [ -z "$MODE" ] \
      || [ -z "$LEDGER" ] || [ -z "$LEDGER_MIN" ] \
      || [ -z "$EDGE_OFFSET" ] || [ -z "$SOLANA_BUILD_DIR" ] \
      || [ -z "$FIREDANCER" ] || [ -z "$REPETITIONS" ]; then
      echo "Missing required arguments for mode 'edge'."
      echo -e "required --mode edge flags are:\n\
                    --network -n,\n\
                    --mode -m,\n\
                    --ledger -l,\n\
                    --ledger-min -z,\n\
                    --edge-offset -o,\n\
                    --solana-build-dir -d,\n\
                    --firedancer-root-dir -f,\n\                    
                    --repetitions -r."
      exit 1
    fi
  else
    echo "Invalid mode: $MODE. Choose '--mode exact' or '--mode edge'."
    usage "all"
    exit 1
  fi

  if [ "$REPETITIONS" != "once" ] && [ "$REPETITIONS" != "multiple" ]; then
    echo "Invalid repetitions: $REPETITIONS. Choose: once|multiple."
    exit 1
  fi

  if [ "$MODE" = "edge" ] && [ "$REPETITIONS" = "multiple" ]; then
    echo -e "Invalid combination --mode edge --repetitions multiple. \n\
                There is only one edge - multiple repetitions are not supported for this mode."
  fi

  if [ "$NETWORK" != "mainnet" ] && [ "$NETWORK" != "testnet" ] && [ "$NETWORK" != "internal" ]; then
    echo "Invalid network: $NETWORK. Choose: mainnet|testnet|internal."
    exit 1
  fi

  if [ ! -d "$LEDGER_MIN" ]; then
    echo "error $LEDGER_MIN does not exist"
    exit 1
  fi

  SOLANA_LEDGER_TOOL="$SOLANA_BUILD_DIR/solana-ledger-tool"
  if [ ! -f "$SOLANA_LEDGER_TOOL" ]; then
    echo "error $SOLANA_LEDGER_TOOL does not exist"
    exit 1
  fi
}

# execution starts here
COMMAND=$1

if [ -z "$COMMAND" ]; then
  echo "Error: Command not specified."
  usage
fi

shift

case $COMMAND in
  fetch-recent)
    parse_fetch_options "$@"
    echo "running cmd=fetch-recent with network=$NETWORK, ledger=$LEDGER, solana-build-dir=$SOLANA_BUILD_DIR"
    fetch-recent
    ;;
  minify)
    parse_minify_options "$@"
    echo -e "running cmd=minify with\n" \
      " network=$NETWORK,\n" \
      " mode=$MODE,\n" \
      " ledger=$LEDGER,\n" \
      " ledger-min=$LEDGER_MIN,\n" \
      " is-verify=$IS_VERIFY,\n" \
      " slots-in-epoch=$SLOTS_IN_EPOCH,\n" \
      " edge-offset=$EDGE_OFFSET,\n" \
      " start-slot=$START_SLOT,\n" \
      " end-slot=$END_SLOT,\n" \
      " solana-build-dir=$SOLANA_BUILD_DIR,\n" \
      " firedancer-root-dir=$FIREDANCER,\n" \
      " gigantic-pages=$GIGANTIC_PAGES,\n" \
      " index-max=$INDEX_MAX"
    minify
    ;;
  replay)
    parse_replay_options "$@"
    echo -e "running cmd=replay with\n" \
      " network=$NETWORK,\n" \
      " ledger=$LEDGER_MIN,\n" \
      " start-slot=$START_SLOT,\n" \
      " end-slot=$END_SLOT,\n" \
      " firedancer-root-dir=$FIREDANCER,\n" \
      " solana-build-dir=$SOLANA_BUILD_DIR,\n" \
      " upload=$UPLOAD_URL,\n" \
      " slots-in-epoch=$SLOTS_IN_EPOCH,\n" \
      " gigantic-pages=$GIGANTIC_PAGES,\n" \
      " index-max=$INDEX_MAX"
    replay
    ;;
  solcap)
    parse_solcap_options "$@"
    echo -e "running cmd=solcap with\n" \
      " ledger=$LEDGER_MIN,\n" \
      " end-slot=$END_SLOT,\n" \
      " firedancer-root-dir=$FIREDANCER,\n" \
      " solana-build-dir=$SOLANA_BUILD_DIR,\n" \
      " checkpoint=$CHECKPOINT,\n" \
      " solana-solcap=$SOLANA_SOLCAP,\n" \
      " firedancer-solcap=$FIREDANCER_SOLCAP,\n" \
      " verbosity=$VERBOSITY"
    solcap
    ;;
  all)
    parse_all_options "$@"
    echo -e "running cmd=all with\n" \
      " network=$NETWORK,\n" \
      " mode=$MODE,\n" \
      " ledger=$LEDGER,\n" \
      " ledger-min=$LEDGER_MIN,\n" \
      " is-verify=$IS_VERIFY,\n" \
      " no-fetch=$NO_FETCH,\n" \
      " slots-in-epoch=$SLOTS_IN_EPOCH,\n" \
      " edge-offset=$EDGE_OFFSET,\n" \
      " start-slot=$START_SLOT,\n" \
      " end-slot=$END_SLOT,\n" \
      " solana-build-dir=$SOLANA_BUILD_DIR,\n" \
      " firedancer-root-dir=$FIREDANCER,\n" \
      " upload=$UPLOAD_URL,\n" \
      " repetitions=$REPETITIONS,\n" \
      " rep-sz=$REP_SZ,\n" \
      " gigantic-pages=$GIGANTIC_PAGES,\n" \
      " index-max=$INDEX_MAX"
    all
    ;;
  *)
    echo "error: invalid command '$COMMAND'"
    usage
    ;;
esac
