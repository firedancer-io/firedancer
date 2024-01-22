#!/bin/bash

set -uEexo pipefail

sudo prlimit --pid $$ --memlock=-1:-1
ulimit -a

mkdir -p build/pages/cov/{test,fuzz}

MACHINES=$(ls -1 config/linux_clang_combi_* | xargs -I{} basename {} .mk)

# TEST COVERAGE

# Build and run tests for all feature combinations
for MACHINE in $MACHINES; do
    # Todo: enable lowend once it builds
    if [[ $MACHINE == linux_clang_combi_lowend ]]; then
      continue
    fi
    export MACHINE
    export EXTRAS=llvm-cov
    make clean
    make -j -o=target all
    ./test.sh -j --page-sz gigantic
done

for LEVEL in $(ls -1 build/linux/clang/combi/); do
  export MACHINE="linux_clang_combi_${LEVEL}"
  # Run script tests
  export LLVM_PROFILE_FILE="build/linux/clang/combi/${LEVEL}/cov/raw/script_tests_%p.profraw"
  sudo --preserve-env=LLVM_PROFILE_FILE,MACHINE make run-script-test
  make cov-report

  rm -rf "build/pages/cov/test/${LEVEL}" || true
  mv "build/linux/clang/combi/${LEVEL}/cov/html/" "build/pages/cov/test/${LEVEL}"
done

make combicov-report
rm -rf build/pages/cov/test/_combined || true
mv build/combi-cov/html build/pages/cov/test/_combined


FEATURE_SETS_BUILT=$(ls -1 build/linux/clang/combi/)


# FUZZ COVERAGE
mkdir -p build/fuzzcov/{profraw,profdata,lcov,corpus,corpus_unpacked}

#ALL_AVAILABLE_CORPORA=$(printf '%s' "$(gcloud storage ls gs://backup.isol-clusterfuzz.appspot.com/corpus/libFuzzer/)")
ALL_AVAILABLE_CORPORA="$(gcloud storage ls gs://backup.isol-clusterfuzz.appspot.com/corpus/libFuzzer/)"

# Let's use the previous run to figure out which corpora to fetch
for FEATURES in $FEATURE_SETS_BUILT; do
  echo $FEATURES
  echo $ALL_AVAILABLE_CORPORA
  TO_CONSUME=$(echo -n $ALL_AVAILABLE_CORPORA | tr " " "\n" | awk "/-${FEATURES}\/$/")

  for CORPUS in $TO_CONSUME; do
    BASE=$(basename $CORPUS)
    gcloud storage cp "${CORPUS}latest.zip" "build/fuzzcov/corpus/${BASE}.zip"
    unzip -o -q "build/fuzzcov/corpus/${BASE}.zip" -d build/fuzzcov/corpus_unpacked/${BASE} || true < <(yes)
  done
done

# Build Fuzzers and run coverage based on ClusterFuzz corpus
for FEATURES in $FEATURE_SETS_BUILT; do
    export MACHINE=linux_clang_combi_${FEATURES}
    export EXTRAS='llvm-cov fuzz'
    make clean
    make -j fuzz-test

    # Generate profraw and an html page for each fuzz target
    for TARGET_NAME in $(ls -1 build/linux/clang/combi/${FEATURES}/fuzz-test/); do
      TARGET=build/linux/clang/combi/${FEATURES}/fuzz-test/${TARGET_NAME}/${TARGET_NAME} || true
      CORPUS_DIR="build/fuzzcov/corpus_unpacked/${TARGET_NAME}-${FEATURES}"

      if [[ -d "${CORPUS_DIR}" ]]; then
        export LLVM_PROFILE_FILE="build/linux/clang/combi/${FEATURES}/cov/raw/${TARGET_NAME}.profraw"
        $TARGET -timeout=10 -runs=10 $CORPUS_DIR || true
        
        llvm-profdata merge -o "build/linux/clang/combi/${FEATURES}/${TARGET_NAME}.profdata" build/linux/clang/combi/${FEATURES}/cov/raw/${TARGET_NAME}.profraw
        llvm-cov export $TARGET -instr-profile="build/linux/clang/combi/${FEATURES}/${TARGET_NAME}.profdata" -format=lcov > "build/linux/clang/combi/${FEATURES}/${TARGET_NAME}.lcov"
        genhtml --output-directory "build/pages/cov/fuzz/${FEATURES}/${TARGET_NAME}" "build/linux/clang/combi/${FEATURES}/${TARGET_NAME}.lcov"

      else
        echo "corpus does not exist for ${TARGET}-${FEATURES}"
      fi
    done

    llvm-profdata merge -o "build/linux/clang/combi/${FEATURES}/cov.profdata" $(ls -1 build/linux/clang/combi/${FEATURES}/cov/raw/*.profraw)
    llvm-cov export $TARGET -instr-profile="build/linux/clang/combi/${FEATURES}/cov.profdata" -format=lcov > "build/linux/clang/combi/${FEATURES}/cov.lcov"
    make cov-report
    rm -rf "build/pages/cov/fuzz/${FEATURES}/_combined" || true
    mv build/linux/clang/combi/${FEATURES}/cov/html/ "build/pages/cov/fuzz/${FEATURES}/_combined"
done


make combicov-report
rm -rf build/pages/cov/fuzz/_combined || true
mv build/combi-cov/html/ build/pages/cov/fuzz/_combined

export FEATURE_SETS_BUILT
.github/workflows/scripts/testcov_gen_index.sh
