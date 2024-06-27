#!/bin/bash

# help message
help() {
  echo
  echo " Usage: ./build.sh [FLAGS] [ARGS]"
  echo
  echo " Flags:"
  echo "   --no-gcc             Do not run any gcc builds"
  echo "   --no-clang           Do not run any clang builds"
  echo "   --no-deps            Do not install deps during any builds"
  echo "   --no-rust            Do not install rust"
  echo "   --verbose            Show output from failed builds"
  echo "   --exit-on-err        Exit upon hitting the first failed build"
  echo "   --help           -h  Show this message and exit"
  echo
  echo " Args: --ARG <ARG1>,<ARG2>,<ARG3>,..."
  echo "   --targets        -t  Targets to compile during building"
  echo "                        This will be used for all types of builds."
  echo "                        For example: all,unit-test,fdctl"
  echo "   --machines       -m  Machine types to build for"
  echo "                        For example: linux_gcc_icelake,linux_clang_noarch64"
  echo "   --gcc-versions   -g  GCC compiler versions to use for builds"
  echo "                        These should present on the host under /opt/gcc"
  echo "                        For example: gcc-8.5.0,gcc-12.4.0"
  echo "   --clang-versions -c  Clang compiler versions to use for builds"
  echo "                        These should present on the host under /opt/clang"
  echo "                        For example: clang-15.0.6,clang-17.0.6"
  echo
  echo " Exit Codes:"
  echo "   0  all builds that ran were successful"
  echo "   1  one or more builds failed"
  echo "   2  compiler environment activation script not found"
  echo "   3  failed to compile and install dependencies"
  echo
}

# helper functions
inf() {
  printf "[INFO] $@"
}

err() {
  printf "[ERROR] $@"
}

# Calculates the elapsed time
# in minutes and seconds and
# prints it to stdout.
elapsed() {
  local start=$1
  local stop=$2
  local diff=$(($stop-$start))
  local min=$((10#$diff / 60))
  local sec=$((10#$diff % 60))
  printf "%d:%02d" "$min" "$sec";
}

# Prints total elapsed time using
# the START global variable and then
# exits with the supplied return code.
finish() {
  local CODE=$1
  local STOP=$(date +%s)
  inf "Total Elapsed Time: "
  elapsed $START $STOP
  echo
  rm -f $LOG_FILE
  exit $CODE
}

GCC=()
CLANG=()
TARGETS=()
MACHINES=()

while [[ $# -gt 0 ]]; do
  FLAG="$1"
  shift 1
  case "$FLAG" in
    # do not run gcc builds
    "--no-gcc")
      NO_GCC=1
      ;;
    # do not run clang builds
    "--no-clang")
      NO_CLANG=1
      ;;
    # do not install dependencies
    "--no-deps")
      NO_DEPS=1
      ;;
    # do not install rust
    "--no-rust")
      NO_RUST=1
      ;;
    # exit upon hitting the first error
    "--exit-on-err")
      EXIT_ON_ERR=1
      ;;
    # print error outputs to stdout
    "--verbose")
      VERBOSE=1
      ;;
    # makefile targets to build
    "-t"|"--targets")
      IFS=',' read -r -a TARGETS <<< "$1"
      shift 1
      ;;
    # MACHINE types to build for
    "-m"|"--machines")
      IFS=',' read -r -a MACHINES <<< "$1"
      shift 1
      ;;
    # GCC versions to use for the builds
    "-g"|"--gcc-versions")
      IFS=',' read -r -a GCC <<< "$1"
      shift 1
      ;;
    # Clang versions to use for the builds
    "-c"|"--clang-versions")
      IFS=',' read -r -a CLANG <<< "$1"
      shift 1
      ;;
    "-h"|"--help")
      help
      exit 0
      ;;
    *)
      echo "Unknown flag: $FLAG"
      help
      exit 1
      ;;
  esac
done

FD_REPO_DIR=$(realpath $(dirname $(realpath "$0"))/..)

BUILD_TARGETS=( all asm ppp seccomp-policies )
TEST_TARGETS=( unit-test fuzz-test )

RUST_TARGETS=( fdctl fddev integration-test )
OTHER_TARGETS=( ${BUILD_TARGETS[@]} ${TEST_TARGETS[@]} )

# Overrides for list of targets to build for certain
# machine types. Note that is --targets is specified,
# these are not used.

declare -A CUSTOM_TARGETS=()
# gcc overrides
CUSTOM_TARGETS+=( ["linux_gcc_minimal"]="${OTHER_TARGETS[@]}" )
CUSTOM_TARGETS+=( ["linux_gcc_noarch64"]="${OTHER_TARGETS[@]}" )
CUSTOM_TARGETS+=( ["linux_gcc_noarch128"]="${OTHER_TARGETS[@]}" )
# clang overrides
CUSTOM_TARGETS+=( ["macos_clang_m1"]="${OTHER_TARGETS[@]}" )
CUSTOM_TARGETS+=( ["linux_clang_minimal"]="${OTHER_TARGETS[@]}" )
CUSTOM_TARGETS+=( ["linux_clang_noarch64"]="${OTHER_TARGETS[@]}" )
CUSTOM_TARGETS+=( ["linux_clang_noarch128"]="${OTHER_TARGETS[@]}" )
CUSTOM_TARGETS+=( ["freebsd_clang_noarch128"]="${OTHER_TARGETS[@]}" )

FAIL=0
LOG_FILE=$(mktemp)
START=$(date +%s)

# By default, use all the compilers that are available.
# Compilers are assumed to be present under /opt.
# For example:
# GCC   -> /opt/gcc/gcc-8.5.0
# Clang -> /opt/clang/clang-15.0.6
# Under each such directory, there should be a script
# called 'activate' that updates the necessary environment
# variables, sourcing that should enable using this compiler.

if [[ $NO_GCC -ne 1 ]]; then
  if [[ ${#GCC[@]} -eq 0 ]]; then
    for gcc in $(ls /opt/gcc); do
      GCC+=( $gcc )
    done
  fi
else
  GCC=()
fi

if [[ $NO_CLANG -ne 1 ]]; then
  if [[ ${#CLANG[@]} -eq 0 ]]; then
    for clang in $(ls /opt/clang); do
      CLANG+=( $clang )
    done
  fi
else
  CLANG=()
fi

# If --machine is not supplied, compile for all machine
# makefiles present in the config/machine directory.

if [[ ${#MACHINES[@]} -eq 0 ]]; then
  for machine in $(ls $FD_REPO_DIR/config/machine); do
    MACHINES+=( $machine )
  done
fi

echo "*************************"
echo "Starting Build Matrix..."
echo "*************************"
echo "machines=[ ${MACHINES[@]} ]"
echo "clang=[ ${CLANG[@]} ]"
echo "gcc=[ ${GCC[@]} ]"
echo "targets=[ ${TARGETS[@]} ]"
echo

# Install rust and packages, also fetch the git repositories
# needed for compiling.

inf "Setting up build environment...\n"
cd $FD_REPO_DIR
if [[ $NO_RUST -ne 1 ]]; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y > /dev/null 2>&1
fi
inf "Installing packages and fetching repositories...\n"
FD_AUTO_INSTALL_PACKAGES=1 ./deps.sh +dev check fetch > /dev/null 2>&1
make -j distclean > /dev/null 2>&1

if [[ $NO_GCC -ne 1 ]]; then
  GCC_START=$(date +%s)
  inf "Starting gcc builds...\n\n"
  for compiler in "${GCC[@]}"; do
    if [[ ! -f /opt/gcc/$compiler/activate ]]; then
      err "Environment activate script not found at /opt/gcc/$compiler... exiting.\n"
      finish 2
    fi
    # We need to use the same compiler for compiling our code
    # as well as the dependencies that our code uses.
    source /opt/gcc/$compiler/activate
    if [[ $NO_DEPS -ne 1 ]]; then
      start=$(date +%s)
      inf "Installing dependencies with $compiler...\n"
      ./deps.sh nuke > /dev/null 2>&1
      CC=gcc CXX=g++ ./deps.sh +dev fetch install > $LOG_FILE 2>&1
      if [[ $? -ne 0 ]]; then
        err "Failed to install deps with $compiler... exiting.\n"
        if [[ $VERBOSE -eq 1 ]]; then
          cat $LOG_FILE
        fi
        if [[ $EXIT_ON_ERR -eq 1 ]]; then
          finish 3
        else
          continue
        fi
      fi
      stop=$(date +%s)
      inf "Elapsed Time: "
      elapsed $start $stop
      echo
    fi
    for machine in "${MACHINES[@]}"; do
      MACHINE="${machine%.mk}"
      if [[ "$MACHINE" != *"clang"* ]]; then
        # override any targets list with supplied --targets
        BUILD_TARGETS=()
        if [[ ${#TARGETS[@]} -eq 0 ]]; then
          if [[ -n "${CUSTOM_TARGETS[${MACHINE}]}" ]]; then
            # overrides based on machine types
            IFS=' ' read -r -a BUILD_TARGETS <<< "${CUSTOM_TARGETS[${MACHINE}]}"
          else
            BUILD_TARGETS+=( "${OTHER_TARGETS[@]}"  )
            BUILD_TARGETS+=( "${RUST_TARGETS[@]}" )
          fi
        else
          BUILD_TARGETS=( "${TARGETS[@]}" )
        fi
        inf "Starting builds for $MACHINE with $compiler...\n"
        FAILED=()
        start=$(date +%s)
        # Truncate the LOG_FILE before every build (not every target)
        # so that if multiple targets fail, we can capture all the
        # errors that occur.
        >$LOG_FILE
        # We compile each target separately and record if it
        # fails so that we can list exactly which targets failed.
        # The output is redirected to the LOG_FILE and we only
        # print it to stdout if there's a failure and --verbose
        # is specified. This keeps our output compact and readable.
        for target in "${BUILD_TARGETS[@]}"; do
          MACHINE=${MACHINE} CC=gcc make -j $target >> $LOG_FILE 2>&1
          if [[ $? -ne 0 ]]; then
            FAILED+=( $target )
            FAIL=1
          fi
        done
        stop=$(date +%s)
        inf "Done... Elapsed Time: "
        elapsed $start $stop
        echo
        if [[ ${#FAILED[@]} -gt 0 ]]; then
          err "Failed Targets: "
          echo "${FAILED[@]}"
          inf "To reproduce, run:\n"
          echo "  source /opt/gcc/$compiler/activate"
          echo "  ./deps.sh nuke"
          echo "  FD_AUTO_INSTALL_PACKAGES=1 ./deps.sh +dev fetch check install"
          echo "  make -j distclean"
          echo "  MACHINE=${MACHINE} CC=gcc make -j ${FAILED[@]}"
          if [[ $VERBOSE -eq 1 ]]; then
            err "Failure Logs:\n"
            cat $LOG_FILE
          fi
          if [[ $EXIT_ON_ERR -eq 1 ]]; then
            finish 1
          fi
        fi
        # Cleanup everything after each build but not after
        # each target so that compile time is a bit faster
        # for the subsequent targets.
        make -j distclean > /dev/null 2>&1
        echo
      fi
    done
  done
  GCC_STOP=$(date +%s)
  inf "Done with gcc builds in "
  elapsed $GCC_START $GCC_STOP
  echo
fi

if [[ $NO_CLANG -ne 1 ]]; then
  CLANG_START=$(date +%s)
  inf "Starting clang builds...\n\n"
  for compiler in "${CLANG[@]}"; do
    if [[ ! -f /opt/clang/$compiler/activate ]]; then
      err "Environment activate script not found at /opt/clang/$compiler... exiting.\n"
      finish 2
    fi
    # We need to use the same compiler for compiling our code
    # as well as the dependencies that our code uses.
    source /opt/clang/$compiler/activate
    if [[ $NO_DEPS -ne 1 ]]; then
      start=$(date +%s)
      inf "Installing dependencies with $compiler...\n"
      ./deps.sh nuke > /dev/null 2>&1
      CC=clang CXX=clang++ ./deps.sh +dev fetch install > $LOG_FILE 2>&1
      if [[ $? -ne 0 ]]; then
        err "Failed to install deps with $compiler...\n"
        if [[ $VERBOSE -eq 1 ]]; then
          cat $LOG_FILE
        fi
        if [[ $EXIT_ON_ERR -eq 1 ]]; then
          finish 3
        else
          continue
        fi
      fi
      stop=$(date +%s)
      inf "Elapsed Time: "
      elapsed $start $stop
      echo
    fi
    for machine in "${MACHINES[@]}"; do
      MACHINE="${machine%.mk}"
      if [[ "$MACHINE" != *"gcc"* ]]; then
        # override any targets list with supplied --targets
        BUILD_TARGETS=()
        if [[ ${#TARGETS[@]} -eq 0 ]]; then
          if [[ -n "${CUSTOM_TARGETS[${MACHINE}]}" ]]; then
            # overrides based on machine types
            IFS=' ' read -r -a BUILD_TARGETS <<< "${CUSTOM_TARGETS[${MACHINE}]}"
          else
            BUILD_TARGETS+=( "${OTHER_TARGETS[@]}"  )
            BUILD_TARGETS+=( "${RUST_TARGETS[@]}" )
          fi
        else
          BUILD_TARGETS=( "${TARGETS[@]}" )
        fi
        inf "Starting builds for $MACHINE with $compiler...\n"
        FAILED=()
        start=$(date +%s)
        # Truncate the LOG_FILE before every build (not every target)
        # so that if multiple targets fail, we can capture all the
        # errors that occur.
        >$LOG_FILE
        # We compile each target separately and record if it
        # fails so that we can list exactly which targets failed.
        # The output is redirected to the LOG_FILE and we only
        # print it to stdout if there's a failure and --verbose
        # is specified. This keeps our output compact and readable.
        for target in "${BUILD_TARGETS[@]}"; do
          MACHINE=${MACHINE} CC=clang make -j $target >> $LOG_FILE 2>&1
          if [[ $? -ne 0 ]]; then
            FAILED+=( $target )
            FAIL=1
          fi
        done
        stop=$(date +%s)
        inf "Done... Elapsed Time: "
        elapsed $start $stop
        echo
        if [[ ${#FAILED[@]} -gt 0 ]]; then
          err "Failed Targets: "
          echo "${FAILED[@]}"
          echo "  source /opt/clang/$compiler/activate"
          echo "  ./deps.sh nuke"
          echo "  FD_AUTO_INSTALL_PACKAGES=1 ./deps.sh +dev fetch check install"
          echo "  make -j distclean"
          echo "  MACHINE=${MACHINE} CC=clang make -j ${FAILED[@]}"
          if [[ $VERBOSE -eq 1 ]]; then
            err "Failure Logs:\n"
            cat $LOG_FILE
          fi
          if [[ $EXIT_ON_ERR -eq 1 ]]; then
            finish 1
          fi
        fi
        # Cleanup everything after each build but not after
        # each target so that compile time is a bit faster
        # for the subsequent targets.
        make -j distclean > /dev/null 2>&1
        echo
      fi
    done
  done
  CLANG_STOP=$(date +%s)
  inf "Done with clang builds in "
  elapsed $CLANG_START $CLANG_STOP
  echo
fi

finish $FAIL
