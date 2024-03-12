#!/bin/bash -f

# This script wraps the solana-ledger-tool and solcap to produce useful output 
# while debugging ledgers for the user
#
# This script can be used to produce a solcap file for a given ledger for both firedancer
# and solana. It can also be used to produce a diff between the two solcap files.
#
# Example Command:
# src/flamenco/capture/solcap.sh --firedancer-solcap test.solcap --end-slot 250127996 
# --ledger dump/mainnet-579/ --solana-solcap solana.solcap --checkpoint test_ledger_backup --output diff

POSITION_ARGS=()
OBJDIR=${OBJDIR:-build/native/gcc}
SOLANADIR=${SOLANADIR:-$HOME/git/solana/target/release}
VERBOSITY=4

PAGE_CNT=64

echo "Solana Target Directory=$SOLANADIR"
echo "Firedancer Build Directory=$OBJDIR"

while [[ $# -gt 0 ]]; do
  case $1 in
    -l|--ledger)
       LEDGER="$2" # full path
       shift
       shift
       ;;
    -i|--start-slot)
       START_SLOT="$2"
       shift
       shift
       ;;
    -e|--end-slot)
       END_SLOT="$2"
       shift
       shift
       ;;
    -s|--solana-solcap)
       SOLANA_SOLCAP="$2"
       shift
       shift
       ;;
    -fd|--firedancer-solcap)
       FD_SOLCAP="$2"
       shift
       shift
       ;;
    -o|--output)
       DIFF_OUTPUT="$2"
       shift
       shift
       ;;
    -z|--no-diff)
       NO_DIFF=true
       shift
       shift
       ;;
    -p|--page-cnt)
       PAGE_CNT="$2"
       shift
       shift
       ;;
    -c|--checkpoint)
       CHECKPOINT="$2"
       shift
       shift
       ;;
    -v|--verbosity)
        VERBOSITY="$2"
        shift
        shift
        ;;
  esac
done

# Make sure there are no errors in the solcap output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' 

# Make sure firedancer solcap exists
if [ -f "$FD_SOLCAP" ]; then
    echo -e "${GREEN}Firedancer solcap file=${FD_SOLCAP} exists.${NC}"
else
    echo "Attempting to create firedancer solcap at file=${FD_SOLCAP}."

    FD_LOG=/tmp/test_runtime_log$$

    "$OBJDIR"/unit-test/test_runtime --load $CHECKPOINT --cmd replay --page-cnt $PAGE_CNT --validate true \
    --abort-on-mismatch 1 --capture $FD_SOLCAP --end-slot $END_SLOT --allocator libc &> $FD_LOG

    if grep -q "ERR" $FD_LOG; then
      echo -e "\n${RED}Firedancer solcap file failed. See Log at file='$FD_LOG'${NC}"
      exit 1
    else
      echo -e "\n${GREEN}Firedancer solcap file written successfully. Log at file='$FD_LOG'${NC}"
    fi

  if [ -f "$FD_SOLCAP" ]; then
    echo -e "${GREEN}File=${FD_SOLCAP} created.${NC}"
  else
    echo -e "${RED}File=${FD_SOLCAP} failed to be created.${NC}"
    exit 1
  fi
fi 

# If the solana solcap doesn't exist, we will create it with solana-ledger-tool and fd_solcap_import
if [ -f "$SOLANA_SOLCAP" ]; then
    echo -e "${GREEN}File=${SOLANA_SOLCAP} exists.${NC}"
else
    echo "Attempting to create solana solcap at file=${SOLANA_SOLCAP}."
    SOL_LOG=/tmp/solcap_diff_script_log$$

    # Ingest in the solana bank file
    ARGS="verify --ledger "$LEDGER" --halt-at-slot "$END_SLOT" --write-bank-file"
    echo -e "\nRunning solana-ledger-tool with args to log file='$SOL_LOG': " $ARGS
    "$SOLANADIR"/solana-ledger-tool $ARGS &> $SOL_LOG

    if grep -q "solana_ledger_tool] ledger tool took" $SOL_LOG; then
      echo -e "\n${GREEN}solana-ledger-tool ran successfully. Log at file='$SOL_LOG'${NC}"
    else
      echo -e "\n${RED}solana-ledger-tool failed. See Log at file='$SOL_LOG'${NC}"
      exit 1
    fi

    echo -e "\n${GREEN}Full Path:" "$LEDGER"ledger_tool/bank_hash_details/ "${NC}"
    echo -e "\n${GREEN}Solana Solcap Output: $SOLANA_SOLCAP" "${NC}"

    # Now we have to ingest the bank hash details file into solcap
    echo -e "\n${GREEN}Running fd_solana_import with args $ARGS${NC}"
    "$OBJDIR"/bin/fd_solcap_import "$LEDGER"ledger_tool/bank_hash_details/ "$SOLANA_SOLCAP"
fi


# Produce a diff between the two files and store it in a file. We will only do 
# this iff the user has specified a file to store the diff in
if [ $NO_DIFF = true ]; then
   echo -e "\n${RED}Not producing a diff${NC}"
   exit 0;
fi
if [ -z "$DIFF_OUTPUT" ]; then 
  "$OBJDIR"/bin/fd_solcap_diff "$FD_SOLCAP" "$SOLANA_SOLCAP" -v $VERBOSITY
else 
  "$OBJDIR"/bin/fd_solcap_diff "$FD_SOLCAP" "$SOLANA_SOLCAP" -v $VERBOSITY 1> "$DIFF_OUTPUT"
  if grep -q ERR "$DIFF_OUTPUT"; then
      echo -e "\n${RED}Error in diff output${NC}"
  else
      echo -e "\n${GREEN}Diff output written to $DIFF_OUTPUT${NC}"
  fi
fi 

if [ -z "$DIFF_OUTPUT" ]; then 
  "$OBJDIR"/bin/fd_solcap_yaml "$FD_SOLCAP" -v 3
else 
  "$OBJDIR"/bin/fd_solcap_yaml "$FD_SOLCAP" -v 3 1>> "$DIFF_OUTPUT"
fi

echo -e "\nScript completed."
