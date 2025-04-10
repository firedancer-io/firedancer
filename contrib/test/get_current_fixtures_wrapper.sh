#!/bin/bash
set -ex

DIR="$( dirname -- "${BASH_SOURCE[0]}"; )";

# map fixture categories to lineages
declare -A fixture_group_to_lineage
fixture_group_to_lineage=( ["txn"]="sol_txn_diff" ["vm_interp"]="sol_vm_interp_diff" )
declare -A fixture_group_to_output_file
fixture_group_to_output_file=( ["txn"]="contrib/test/test-vectors-fixtures/txn-fixtures/current-program-tests.list" ["vm_interp"]="contrib/test/test-vectors-fixtures/vm-interp-fixtures/current_vm_interp-fixtures.list" )

for key in "${!fixture_group_to_lineage[@]}"; do
  # Convert the value into an array and loop through it
  variants="${fixture_group_to_lineage[${key}]}"
  out_file="${fixture_group_to_output_file[${key}]}"
  for variant in "${variants[@]}"; do
    ./${DIR}/get_current_fixtures.sh $variant $out_file
  done
done
