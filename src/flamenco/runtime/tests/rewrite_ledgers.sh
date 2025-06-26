#!/bin/bash
INPUT_LEDGER_LIST=run_ledger_tests_all.txt
OUTPUT_LEDGER_LIST=output_ledger_tests_all.txt
INPUT_LEDGERS_LOCATION={path/to/ledgers}
OUTPUT_LEDGERS_LOCATION={path/to/output/ledgers}
AGAVE_REPO_DIR={path/to/agave/directory}

while [[ $# -gt 0 ]]; do
  case $1 in
    -l|--input-ledger-list)
       INPUT_LEDGER_LIST="$2"
       shift
       shift
       ;;
    -ol|--output-ledger-list)
       OUTPUT_LEDGER_LIST="$2"
       shift
       shift
       ;;
    -v|--cluster-version)
       VERSION="$2"
       shift
       shift
       ;;
    -i|--input-ledgers-location)
       INPUT_LEDGERS_LOCATION="$2"
       shift
       shift
       ;;
    -o|--output-ledgers-location)
       OUTPUT_LEDGERS_LOCATION="$2"
       shift
       shift
       ;;
    -a|--agave-repo-dir)
       AGAVE_REPO_DIR="$2"
       shift
       shift
       ;;
    -s|--ledger-suffix)
       LEDGER_SUFFIX="$2"
       shift
       shift
       ;;
    -*|--*)
       echo "unknown option $1"
       exit 1
       ;;
    *)
       POSITION_ARGS+=("$1")
       shift
       ;;
  esac
done

rm -rf $OUTPUT_LEDGER_LIST
touch $OUTPUT_LEDGER_LIST

while IFS= read -r line; do
  unset entry
  declare -A entry

  args=($line)
  i=0
  while [ $i -lt ${#args[@]} ]; do
    key="${args[$i]}"
  if [[ $key == -* ]]; then
      value="${args[$((i + 1))]}"
      entry[${key:1}]="$value"
      ((i+=2))
    else
      ((i++))
    fi
  done

  if [ -n "${entry[o]}" ]; then
    INPUT_LEDGER_LOCATION=${INPUT_LEDGERS_LOCATION}/${entry[l]}
    OUTPUT_LEDGER_LOCATION=${OUTPUT_LEDGERS_LOCATION}/${entry[l]}
    cp -r ${INPUT_LEDGER_LOCATION} ${OUTPUT_LEDGER_LOCATION}
    echo "Skipping ledger: ${entry[l]} because one-offs are not empty"
    echo "src/flamenco/runtime/tests/run_ledger_test.sh -l ${entry[l]} -s ${entry[s]} -p ${entry[p]} -y ${entry[y]} -m ${entry[m]} -e ${entry[e]} -c ${entry[c]} -o ${entry[o]}" >> $OUTPUT_LEDGER_LIST
    continue
  fi

  if [ "${entry[c]}" \> "$VERSION" ]; then
    INPUT_LEDGER_LOCATION=${INPUT_LEDGERS_LOCATION}/${entry[l]}
    OUTPUT_LEDGER_LOCATION=${OUTPUT_LEDGERS_LOCATION}/${entry[l]}
    cp -r ${INPUT_LEDGER_LOCATION} ${OUTPUT_LEDGER_LOCATION}
    echo "Skipping ledger: ${entry[l]} because cluster version is greater than $VERSION"
    echo "src/flamenco/runtime/tests/run_ledger_test.sh -l ${entry[l]} -s ${entry[s]} -p ${entry[p]} -y ${entry[y]} -m ${entry[m]} -e ${entry[e]} -c ${entry[c]}" >> $OUTPUT_LEDGER_LIST
    continue
  fi

  INPUT_LEDGER_LOCATION=${INPUT_LEDGERS_LOCATION}/${entry[l]}
  OUTPUT_LEDGER_LOCATION=${OUTPUT_LEDGERS_LOCATION}/${entry[l]}-${LEDGER_SUFFIX}
  END_SLOT=${entry[e]}
  START_SLOT=$(echo "${entry[s]}" | cut -d'-' -f2)
  cp -r ${INPUT_LEDGER_LOCATION} ${OUTPUT_LEDGER_LOCATION}

  CREATE_SNAPSHOT_CMD="$AGAVE_REPO_DIR/target/release/agave-ledger-tool create-snapshot ${START_SLOT} -l ${OUTPUT_LEDGER_LOCATION} --enable-capitalization-change"
  echo "$CREATE_SNAPSHOT_CMD"
  $CREATE_SNAPSHOT_CMD &> /dev/null

  SNAPSHOT_COUNT=$(ls $OUTPUT_LEDGER_LOCATION/snapshot*tar.zst 2>/dev/null | wc -l)
  if [ "$SNAPSHOT_COUNT" -gt 1 ]; then
    old_snapshot="${entry[s]}"
    rm "${OUTPUT_LEDGER_LOCATION}/${old_snapshot}"
    new_snapshot=$(basename $(ls $OUTPUT_LEDGER_LOCATION/snapshot*tar.zst | head -n 1))
    entry[s]=$new_snapshot
    echo "Removed ${old_snapshot} from ledger ${entry[l]} due to getting overwritten by newer snapshot ${new_snapshot}"
  fi

  REWRITE_CMD="$AGAVE_REPO_DIR/target/release/agave-ledger-tool verify -l ${OUTPUT_LEDGER_LOCATION} --halt-at-slot ${END_SLOT} --use-snapshot-archives-at-startup when-newest --no-accounts-db-experimental-accumulator-hash --force-update-to-open"
  echo "$REWRITE_CMD"
  $REWRITE_CMD &> /dev/null

  if [ -n "${entry[t]}" ]; then
    echo "src/flamenco/runtime/tests/run_ledger_test.sh  -t ${entry[t]} -l ${entry[l]}-${LEDGER_SUFFIX} -s ${entry[s]} -p ${entry[p]} -y ${entry[y]} -m ${entry[m]} -e ${entry[e]} -c $VERSION" >> $OUTPUT_LEDGER_LIST
  else
    echo "src/flamenco/runtime/tests/run_ledger_test.sh -l ${entry[l]}-${LEDGER_SUFFIX} -s ${entry[s]} -p ${entry[p]} -y ${entry[y]} -m ${entry[m]} -e ${entry[e]} -c $VERSION" >> $OUTPUT_LEDGER_LIST
  fi

  rm -rf ${OUTPUT_LEDGER_LOCATION}/ledger_tool
  rm -rf ${OUTPUT_LEDGER_LOCATION}/snapshot
  rm -rf ${OUTPUT_LEDGER_LOCATION}/accounts
done < "$INPUT_LEDGER_LIST"
