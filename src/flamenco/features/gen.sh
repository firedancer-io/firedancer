#!/bin/bash -f

# Usage: gen.sh < solana/src/feature_set.rs > features.json

n=0
echo '['
# dumbest code ever
while read -r line; do
  if [[ "$line" =~ ^pub\ mod\ ([a-zA-Z0-9_]+)\ \{ ]]; then
    feature_name="${BASH_REMATCH[1]}"
  elif [[ "$line" =~ solana_sdk::declare_id!\(\"([a-zA-Z0-9_]+)\" ]]; then
    if ((n++ > 0)); then
        echo ','
    fi
    echo -n "  {\"name\":\"$feature_name\",\"pubkey\": \"${BASH_REMATCH[1]}\"}"
  fi
done
echo
echo ']'
