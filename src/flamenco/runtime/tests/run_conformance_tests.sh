#!/bin/bash -f

# This script is used to run the conformance tests for the solana-conformance
# suite given a set of test inputs. It sets up the required dependencies and runs the tests.

# Usage:
# ./run_conformance_tests.sh -i <test_inputs> [-r <run_directory>] [-fdr <firedancer_repo>] [-fdb <firedancer_branch>] [-ar <solfuzz_agave_repo>] [-ab <solfuzz_agave_branch>] [-scr <solana_conformance_repo>] [-scb <solana_conformance_branch>] [-o <output_dir>]

# Required arguments:
# -i|--test-inputs: the directory containing the test inputs 
# Optional arguments:
# -r|--run-dir: the directory where the tests will be run (default: /data/conformance_tests)
# -fdr|--firedancer-repo: the path to the firedancer repository (default: cloned repo)
# -fdb|--firedancer-branch: the branch of the firedancer repository to use (default: main)
# -ar|--agave-repo: the path to the solfuzz-agave repository (default: cloned repo)
# -ab|--agave-branch: the branch of the solfuzz-agave repository to use (default: agave-v2.0)
# -scr|--solana-conformance-repo: the path to the solana-conformance repository (default: cloned repo)
# -scb|--solana-conformance-branch: the branch of the solana-conformance repository to use (default: main)
# -o|--output-dir: the directory where the test results will be stored (default: run_dir/test_results)


# Default values
RUN_DIRECTORY="/data/conformance_tests"
FIREDANCER_BRANCH="main"
AGAVE_BRANCH="agave-v2.0"
SOLANA_CONFORMANCE_BRANCH="main"

# Read command-line args
while [[ $# -gt 0 ]]; do
  case $1 in
    -fdr|--firedancer-repo)
       FIREDANCER_REPO="$2"
       shift 2
       ;;
    -fdb|--firedancer-branch)
       FIREDANCER_BRANCH="$2"
       shift 2
       ;;
    -ar|--agave-repo)
       AGAVE_REPO="$2"
       shift 2
       ;;
    -ab|--agave-branch)
        AGAVE_BRANCH="$2"
        shift 2
        ;;
    -scr|--solana-conformance-repo)
        SOLANA_CONFORMANCE_REPO="$2"
        shift 2
        ;;
    -scb|--solana-conformance-branch)
        SOLANA_CONFORMANCE_BRANCH="$2"
        shift 2
        ;;
    -r|--run-dir)
       RUN_DIRECTORY="$2"
       shift 2
       ;;
    -i|--test-inputs)
       TEST_INPUTS="$2"
       shift 2
       ;;
    -o|--output-dir)
       OUTPUT_DIR="$2"
       shift 2
       ;;
    *)
      echo "Unknown flag"
      exit 1
      ;;
  esac
done

# Error if required args are not provided
if [ -z "${TEST_INPUTS}" ]; then
  echo "Error: Test inputs not specified"
  exit 1
fi

echo $RUN_DIRECTORY
if [ ! -d $RUN_DIRECTORY ]; then
  mkdir -p ${RUN_DIRECTORY}
fi
cd $RUN_DIRECTORY

if [ -z "${FIREDANCER_REPO}" ]; then
  FIREDANCER_REPO=${RUN_DIRECTORY}/firedancer
fi

if [ -z "${AGAVE_REPO}" ]; then
  AGAVE_REPO=${RUN_DIRECTORY}/solfuzz-agave
fi

if [ -z "${SOLANA_CONFORMANCE_REPO}" ]; then
  SOLANA_CONFORMANCE_REPO=${RUN_DIRECTORY}/solana-conformance
fi

# check if firedancer directory does not exist
echo $FIREDANCER_REPO
if [ ! -d $FIREDANCER_REPO ]; then
  git clone https://github.com/firedancer-io/firedancer.git
fi

if [ ! -d $AGAVE_REPO ]; then
  git clone https://github.com/firedancer-io/solfuzz-agave.git
fi

if [ ! -d $SOLANA_CONFORMANCE_REPO ]; then
  git clone https://github.com/firedancer-io/solana-conformance.git
fi

# setup firedancer
cd $FIREDANCER_REPO
git checkout $FIREDANCER_BRANCH
git pull
PATH=/opt/rh/gcc-toolset-12/root/usr/bin:$PATH
export PATH
PKG_CONFIG_PATH=/usr/lib64/pkgconfig:$PKG_CONFIG_PATH
echo "y"|./deps.sh +dev
make -j

# setup solfuzz-agave
cd $AGAVE_REPO
git checkout $AGAVE_BRANCH
git pull
cargo build --lib

# setup solana-conformance
cd $SOLANA_CONFORMANCE_REPO
git checkout $SOLANA_CONFORMANCE_BRANCH
git pull
source install.sh
source test_suite_env/bin/activate

if [ -z "${OUTPUT_DIR}" ]; then
  OUTPUT_DIR=${RUN_DIRECTORY}/test_results
fi
mkdir -p $OUTPUT_DIR

solana-test-suite run-tests --input-dir $TEST_INPUTS --solana-target ${AGAVE_REPO}/target/debug/libsolfuzz_agave.so --target ${FIREDANCER_REPO}/build/native/gcc/lib/libfd_exec_sol_compat.so --output-dir $OUTPUT_DIR -c
