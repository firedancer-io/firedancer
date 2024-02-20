#!/usr/bin/env bash

# Downloads the latest ClusterFuzz corpus.
# WARNING: Destructive!

rm -rf corpus

gcloud storage ls gs://backup.isol-clusterfuzz.appspot.com/corpus/libFuzzer/ |
while read -r dir
do
  TARGET_FULL="$(basename "$dir")"                    # fuzz_base64-highend
  TARGET=$(sed -r 's/-[a-z]+$//' <<< "$TARGET_FULL")  # fuzz_base64

  CORPUS_DIR="corpus/$TARGET/$TARGET"
  mkdir -v -p "$CORPUS_DIR"

  TEMPFILE="$(mktemp)"
  gcloud storage cp "$dir"latest.zip "$TEMPFILE"

  TEMPDIR="$(mktemp -d)"
  unzip -q "$TEMPFILE" -d "$TEMPDIR"
  rm "$TEMPFILE"

  find "$TEMPDIR" -type f -exec mv -nt "$CORPUS_DIR" {} +
  rm -r "$TEMPDIR"
done
