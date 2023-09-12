#!/bin/bash

set -uEexo pipefail

mkdir -p build/fuzzcov/{profraw,profdata,lcov,corpus,corpus_unpacked}
TARGET_DIR=$1

# List all the corpus prefixes and save those to the `corpora` array
readarray corpora < <(printf '%s' "$(gcloud storage ls gs://backup.isol-clusterfuzz.appspot.com/corpus/libFuzzer/)")

# Get the latest corpus backups and unpack those in a directory named with the target's name
for corpus in "${corpora[@]}"; do
    BASE=$(basename ${corpus})
    gcloud storage cp "$(echo $corpus | sed 's/ *$//g')latest.zip" "build/fuzzcov/corpus/${BASE}.zip"
    unzip -q "build/fuzzcov/corpus/${BASE}.zip" -d build/fuzzcov/corpus_unpacked/${BASE} < <(yes)
done

# Run a fuzzing target against the entirety of its corpus
for corpus in "${corpora[@]}"; do
    BASE=$(basename ${corpus})
    TARGET="${TARGET_DIR}/${BASE}/${BASE}"

    # Run the fuzzing target
    if [[ -f $TARGET ]]; then
        export LLVM_PROFILE_FILE="build/profraw/${BASE}.profraw"
        find build/fuzzcov/corpus_unpacked/${BASE}/ -type f -exec $TARGET {} +
        llvm-profdata merge -sparse "${LLVM_PROFILE_FILE}" -o "build/fuzzcov/profdata/${BASE}.profdata"
        CODECOV_FILE=${BASE}.lcov
        llvm-cov export $TARGET -instr-profile="build/fuzzcov/profdata/${BASE}.profdata" -format=lcov > "build/fuzzcov/lcov/${BASE}.lcov"
    else
        echo "No such target '${TARGET}' but fuzzing corpus exists for it."
    fi
done
