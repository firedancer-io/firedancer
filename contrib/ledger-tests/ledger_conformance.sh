#!/bin/bash

# ledger_conformance is a CLI tool that provides a command line interface to consolidate bank hash mismatch debugging operations
# It currently manages operations like fetching, minimizing, replaying and uploading ledgers
# Refer to the README or usage() for detailed information

setup() {
  source ./setup.sh 
}

fetch-recent() {
  ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
  source $ROOT_DIR/utils.sh
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

mismatch-txn() {
  source ./txn.sh
}

one_repetition() {
  local rep_idx=$1

  # Call the fetch script
  if [[ "$NO_FETCH" == "false" ]]; then
    if [ $rep_idx -ne 0 ]; then
      MIN_SNAPSHOT_SLOT=$START_SLOT
    fi
    source $ROOT_DIR/fetch.sh
  fi

  # Find start and end slots and the next root
  set_default_slots
  echo "[~] current rooted repetition [$START_SLOT, $END_SLOT]"
  
  rm -rf $LEDGER_MIN && mkdir $LEDGER_MIN
  local last_modified_snapshot=$(find "$LEDGER" -maxdepth 1 -name 'snapshot-*.tar.zst' -print0 | xargs -0 ls -t | head -n 1)
  local last_modified_snapshot_basename=$(basename "$last_modified_snapshot")
  ln -s "$last_modified_snapshot" "$LEDGER_MIN/$last_modified_snapshot_basename"
  ln -s $LEDGER/genesis.bin "$LEDGER_MIN/genesis.bin"
  ln -s $LEDGER/genesis.tar.bz2 "$LEDGER_MIN/genesis.tar.bz2"    
  ln -s "$LEDGER/rocksdb" "$LEDGER_MIN/rocksdb"

  source $ROOT_DIR/replay.sh
}

all_repetition() {
  echo "running multiple repetitions. current maybe rooted repetition [$START_SLOT, $END_SLOT]"
  local rep_idx=0
  while [ $START_SLOT -le $END_SLOT ]; do
    # todo if it enters the second loop, there must have been a mismatch on (START_SLOT-1)
    # call the solcap diff here
    one_repetition $rep_idx
    ((rep_idx++))
  done
}

all() {  
  ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
  source $ROOT_DIR/utils.sh

  # If --repetitions multiple, we run the pipeline continuously until the whole ledger is searched for BHMs
  if [ "$MODE" = "exact" ] && [ "$REPETITIONS" = "multiple" ]; then
    all_repetition
  else
    one_repetition 0
  fi
}

usage() {
  if [[ $1 == "setup" ]]; then
    echo -e "Usage: $0 setup \n\
                --directory -d : Path to the root directory where the firedancer, solfuzz-agave and solana-conformance repositories will be cloned."

  elif [[ $1 == "fetch-recent" ]]; then
    echo -e "Usage: $0 fetch-recent \n\
                --network -n             : Solana network to download the ledger from. Choose: mainnet|testnet|internal. \n\
                --ledger -l              : Directory to place the downloaded ledger in. \n\
                --solana-build-dir -d    : Path to the solana build directory. E.g. /home/fd_user/solana/target/debug"

  elif [[ $1 == "minify" ]]; then
    echo -e "Usage: $0 minify \n\
                --network -n                    : Solana network to download the ledger from. Choose: mainnet|testnet|internal. \n\                
                --ledger -l                     : Directory where the initial ledger can be found. \n\
                --ledger-min -z                 : Directory where the minimized ledger should be placed. \n\
                --solana-build-dir -d           : Path to the solana|agave build directory. E.g. /home/fd_user/solana|agave/target/debug \n\
                --firedancer-root-dir -f        : Path to the firedancer root directory. E.g. /home/fd_user/firedancer \n\
                --edge-offset -o                : Required if the mode is edge, this defines the number of slots to minimize the initial ledger on each side of the epoch boundary. \n\
                --start-slot -s                 : Required if the mode is exact, this defines the slot to start reading from. \n\
                --end-slot -e                   : Required if the mode is exact, this defines the slot to end reading. \n\
                --mode -m                       : Method to minimize the initial ledger. Either as an offset around an epoch edge, or defined as an exact start and end slot. Default: exact. Choose: edge|exact. \n\
                --is-verify -v [Optional]       : If passed, use solana|agave-ledger-tool to verify created ledgers. Default: false. \n\
                --slots-in-epoch -i [Optional]  : Slot count for an epoch in the defined network. Default: 432_000. \n\
                --gigantic-pages -g [Optional]  : Number of gigantic pages. Default: 700 \n\
                --index-max -x [Optional]       : Maximum index. Default: 600_000_000"
    echo "Note: This will remove the existing directory at <ledger_min_dir>"

  elif [[ $1 == "replay" ]]; then
    echo -e "Usage: $0 replay \n\
                --network -n                    : Solana network to download the ledger from. Choose: mainnet|testnet|internal. \n\
                --ledger -l                     : Directory where the ledger to be replayed can be found. \n\
                --start-slot -s                 : The slot to start replay. \n\
                --end-slot -e                   : The slot to end replay. \n\
                --firedancer-root-dir -f        : Path to the firedancer root directory. \n\
                --solana-build-dir -d           : Path to the solana|agave build directory. E.g. /home/fd_user/solana|agave/target/debug \n\
                --slots-in-epoch -i [Optional]  : Slot count for an epoch in the defined network. Default: 432_000. \n\
                --gigantic-pages -g [Optional]  : Number of gigantic pages. Default: 700 \n\
                --index-max -x [Optional]       : Maximum index. Default: 600_000_000 \n\
                --upload -u [Optional]          : Gcloud storage url for minimized ledger to be stored"
    echo "Note: This will remove the override the existing firedancer/dump directory"

  elif [[ $1 == "solcap" ]]; then
    echo -e "Usage: $0 solcap \n\
                --directory -d                  : Path to the root directory containing firedancer, solana, solfuzz-agave and solana-conformance repos. \n\
                --solana-build-dir -b           : Path to the solana|agave build directory. E.g. /home/fd_user/solana|agave/target/debug \n\
                --index-max -x [Optional]       : Maximum index. Default: 600_000_000 \n\
                --pages -p [Optional]           : Number of pages. Default: 75 \n\
                --funk-pages -f [Optional]      : Number of funk pages. Default: 550"

  elif [[ $1 == "all" ]]; then
    echo -e "Usage: $0 all \n\
                --network -n                    : Solana network to download the ledger from. Choose: mainnet|testnet|internal. \n\                
                --ledger -l                     : Directory where the initial ledger can be found. \n\
                --ledger-min -z                 : Directory where the minimized ledger should be placed. \n\
                --solana-build-dir -d           : Path to the solana|agave build directory. E.g. /home/fd_user/solana|agave/target/debug \n\
                --firedancer-root-dir -f        : Path to the firedancer root directory. \n\
                --edge-offset -o                : Required if the mode is edge, this defines the number of slots to minimize the initial ledger on each side of the epoch boundary. \n\
                --start-slot -s                 : Defines the slot to start reading from. \n\
                --end-slot -e                   : Defines the slot to end reading. \n\
                --repetitions -r                : Required if the mode is exact, running with multiple repetitions repeats the minify and replay for new slot ranges until the entire ledger is checked. Choose: once|multiple. \n\
                --no-fetch [Optional]           : Run all the commands excluding fetch-recent. Just pass in the ledger directories. \n\
                --mode -m [Optional]            : Method to minimize the initial ledger. Either as an offset around an epoch edge, or defined as an exact start and end slot. Default: exact. Choose: edge|exact. \n\
                --is-verify -v [Optional]       : If passed, use solana|agave-ledger-tool to verify created ledgers. Default: false. \n\
                --slots-in-epoch -i [Optional]  : Slot count for an epoch in the defined network. Default: 432_000. \n\
                --gigantic-pages -g [Optional]  : Number of gigantic pages. Default: 700 \n\
                --index-max -x [Optional]       : Maximum index. Default: 600_000_000 \n\
                --upload -u [Optional]          : Gcloud storage url for minimized ledger to be stored. Default: None"
  
  elif [[ $1 == "mismatch-txn" ]]; then
  echo -e "Usage: $0 mismatch-txn \n\
                --directory -d                  : Path to the root directory containing firedancer, solana, solfuzz-agave and solana-conformance repos. \n\
                --index-max -x [Optional]       : Maximum index. Default: 600_000_000 \n\
                --pages -p [Optional]           : Number of pages. Default: 75 \n\
                --funk-pages -f [Optional]      : Number of funk pages. Default: 550"

  else
    echo "General Usage: $0 <command> [options]"
    cat <<'EOF'
            SUBCOMMANDS:
                setup                                   : Setup all repositories if they dont exist, and updates the latest branches
                fetch-recent                            : Initialize the ledger tests by fetching a recent ledger
                minify                                  : Minimize a recent ledger snapshots and rocksdb
                    --mode edge                         : Minimize around an epoch edge with some offset
                    --mode exact                        : Minimize around a specific [start_slot, end_slot]
                replay                                  : Replay the minimized ledger to check for bank hash mismatches 
                                                            and upload the minimized one block ledger to the cloud storage
                solcap                                  : Produce a diff between firedancer and solana labs solcaps                                                            
                mismatch-txn                            : Produce the mismatching transaction
                all                                     : Run all commands - fetch-recent, minify, replay in sequence
                                                          In the `all` subcommand, bounds are checked if rooted, if not it searches for a bound that is rooted.
                    --no-fetch                          : Run all the commands excluding fetch-recent. Just pass in the ledger directories.
                    --repetitions once --mode edge|exact: Run the full cycle of commands once
                    --repetitions multiple --mode exact : Replay the entire ledger in multiple iterations.
                                                          If start_slot and end_slot are not specified (recommended), the check range is `[first_rooted(max(snap, rocksdb_min)), last_rooted(rocksdb_max)]` 
                                                          The replay looks for a mismatch from `start_slot` toward `end_slot`, until it encounters a mismatch. 
                                                          Then it would repeat the cycle, starting from the next hourly snapshot after mismatch+1. The snapshot is skipped if the first slot is not rooted.
EOF
  fi
  exit 1
}

parse_setup_options() {
  TEMP=$(getopt -o d: --long directory: -- "$@")
  if [ $? != 0 ]; then
    echo "Incorrect options provided" >&2
    exit 1
  fi
  eval set -- "$TEMP"

  while true; do
    case "$1" in
      -d | --directory)
        REPO_ROOT="$2"
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

  if [ -z "$REPO_ROOT" ]; then
    usage "setup"
    exit 1
  fi
}

parse_fetch_options() {
  TEMP=$(getopt -o n:l:d: --long network:,ledger:,solana-build-dir: -- "$@")
  if [ $? != 0 ]; then
    echo "Incorrect options provided" >&2
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
        echo "Internal error! Option processing failed: $1" >&2
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

  SOLANA_LEDGER_TOOL="$SOLANA_BUILD_DIR/*-ledger-tool"
  if [ -z "$(ls $SOLANA_LEDGER_TOOL 2>/dev/null)" ]; then
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
  MODE="exact"
  SLOTS_IN_EPOCH=432000
  GIGANTIC_PAGES=550
  INDEX_MAX=600000000

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

  SOLANA_LEDGER_TOOL="$SOLANA_BUILD_DIR/*-ledger-tool"
  if [ -z "$(ls $SOLANA_LEDGER_TOOL 2>/dev/null)" ]; then
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
  GIGANTIC_PAGES=550
  INDEX_MAX=600000000
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

  SOLANA_LEDGER_TOOL="$SOLANA_BUILD_DIR/*-ledger-tool"
  if [ -z "$(ls $SOLANA_LEDGER_TOOL 2>/dev/null)" ]; then
    echo "error $SOLANA_LEDGER_TOOL does not exist"
    exit 1
  fi
}

parse_solcap_options() {
  TEMP=$(getopt -o d:b:x:p:f: --long directory:,solana-build-dir:,index-max:,pages:,funk-pages: -- "$@")
  if [ $? != 0 ]; then
    echo "Incorrect options provided" >&2
    exit 1
  fi

  eval set -- "$TEMP"

  # Defaults for a full ledger
  # Typically mismatch snapshots should be minimized and require less pages
  PAGES=75
  FUNK_PAGES=550
  INDEX_MAX=600000000

  while true; do
    case "$1" in
      -d | --directory)
        REPO_ROOT="$2"
        shift 2
        ;;
      -b | --solana-build-dir)
        SOLANA_BUILD_DIR="$2"
        shift 2
        ;;
      -x | --index-max)
        INDEX_MAX="$2"
        shift 2
        ;;
      -p | --pages)
        PAGES="$2"
        shift 2
        ;;
      -f | --funk-pages)
        FUNK_PAGES="$2"
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

  if [ -z "$REPO_ROOT" ] || [ -z "$SOLANA_BUILD_DIR" ]; then
    usage "solcap"
    exit 1
  fi

  SOLANA_LEDGER_TOOL="$SOLANA_BUILD_DIR/*-ledger-tool"
  if [ -z "$(ls $SOLANA_LEDGER_TOOL 2>/dev/null)" ]; then
    echo "error $SOLANA_LEDGER_TOOL does not exist"
    exit 1
  fi
}

parse_mismatch_txn_options() {
  TEMP=$(getopt -o d:x:p:f: --long directory:,index-max:,pages:,funk-pages: -- "$@")
  if [ $? != 0 ]; then
    echo "Incorrect options provided" >&2
    exit 1
  fi

  eval set -- "$TEMP"

  # Defaults for a full ledger
  # Typically mismatch snapshots should be minimized and require less pages
  PAGES=75
  FUNK_PAGES=550
  INDEX_MAX=600000000

  while true; do
    case "$1" in
      -d | --directory)
        REPO_ROOT="$2"
        shift 2
        ;;
      -x | --index-max)
        INDEX_MAX="$2"
        shift 2
        ;;
      -p | --pages)
        PAGES="$2"
        shift 2
        ;;
      -f | --funk-pages)
        FUNK_PAGES="$2"
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


  if [ -z "$REPO_ROOT" ]; then
    usage "mismatch-txn"
    exit 1
  fi

  if [ ! -d "$REPO_ROOT/firedancer" ] || [ ! -d "$REPO_ROOT/solana" ] || [ ! -d "$REPO_ROOT/solfuzz-agave" ] || [ ! -d "$REPO_ROOT/solana-conformance" ]; then
    echo "error: $REPO_ROOT/firedancer || $REPO_ROOT/solana || $REPO_ROOT/solfuzz-agave || $REPO_ROOT/solana-conformance do not exist.\n\
          Run `./ledger_conformance.sh setup` to set up and update to the latest branch in these repositories"
    exit 1
  fi

  if [ ! -d "$REPO_ROOT/firedancer/build/native/gcc" ] || [ ! -d "$REPO_ROOT/solana/target/release" ] || [ ! -d "$REPO_ROOT/solfuzz-agave/target/debug" ]; then
    echo "error: $REPO_ROOT/firedancer/build/native/gcc || $REPO_ROOT/solana/target/release || $REPO_ROOT/solfuzz-agave/target/debug do not exist.\n\
          Run `./ledger_conformance.sh setup` to set up and build these repositories"
    exit 1
  fi
}

parse_all_options() {
  TEMP=$(getopt -o n:m:l:z:v:q:i:g:x:o:s:e:d:f:u:r: \
    --long network:,mode:,ledger:,ledger-min:,is-verify:,no-fetch,slots-in-epoch:,gigantic-pages:,index-max:,edge-offset:,start-slot:,end-slot:,solana-build-dir:,firedancer-root-dir:,upload:,repetitions: \
    -- "$@")

  if [ $? != 0 ]; then
    echo "Incorrect options provided" >&2
    exit 1
  fi

  eval set -- "$TEMP"

  # Defaults
  IS_VERIFY="false"
  NO_FETCH="false"
  MODE="exact"
  SLOTS_IN_EPOCH=432000
  UPLOAD_URL=""
  GIGANTIC_PAGES=550
  INDEX_MAX=600000000

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

  SOLANA_LEDGER_TOOL="$SOLANA_BUILD_DIR/*-ledger-tool"
  if [ -z "$(ls $SOLANA_LEDGER_TOOL 2>/dev/null)" ]; then
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
  setup)
    parse_setup_options "$@"
    echo "running cmd=setup with repo_root=$REPO_ROOT"
    setup
    ;;
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
      " repo-root=$REPO_ROOT,\n" \
      " solana-build-dir=$SOLANA_BUILD_DIR,\n" \
      " index-max=$INDEX_MAX,\n" \
      " pages=$PAGES,\n" \
      " funk-pages=$FUNK_PAGES"
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
      " gigantic-pages=$GIGANTIC_PAGES,\n" \
      " index-max=$INDEX_MAX"
    all
    ;;
  mismatch-txn)
    parse_mismatch_txn_options "$@"
    echo -e "running cmd=mismatch-txn with\n" \
      " repo-root=$REPO_ROOT,\n" \
      " index-max=$INDEX_MAX,\n" \
      " gigantic-pages=$PAGES\n" \
      " funk-pages=$FUNK_PAGES"
    mismatch-txn
    ;;
  *)
    echo "error: invalid command '$COMMAND'"
    usage
    ;;
esac
