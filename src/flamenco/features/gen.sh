#!/bin/bash -f
echo '{"features": [' > $1
sed -e 's-//.*--' ~/repos/solana/sdk/src/feature_set.rs |  grep declare_id  | sed -e 's/^.*(//' -e 's/).*//' | sed -e 's/\(.*\)/{"id":\1, "status": "active", "sinceSlot": 1, "description": ""},/' | sort >> $1
echo '{}]}' >> $1
