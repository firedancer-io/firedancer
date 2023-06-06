# without podman
#   sudo dnf install -y python38-devel
#   /bin/python3.8 -m pip install solana solders base58 --user
#   python3.8 gen_c_tests.py -j system_program_tests.json

# with podman
#   podman run -v .:/tests --security-opt label=disable python3.8 python3 /tests/gen_c_tests.py -j /tests/system_program_tests.json
#
# to generate data
#   ./cargo nightly test --package solana-runtime --lib -- system_instruction_processor::tests --nocapture

import argparse
import base58
import json
import os
import sys
from solders.instruction import AccountMeta, Instruction
from solders.pubkey import Pubkey
from solders.transaction import Transaction
from solders.keypair import Keypair
from solana.transaction import Transaction

'''
Test framework:
- Each test contains:
    - Test name
    - Instruction data (uchar array)
    - List of transaction accounts
        - Pubkey
        - Contents
            - Lamports (ulong)
            - Data (uchar array)
            - Owner (pubkey)
            - Executable (uchar)
            - Rent epoch (ulong)
    - List of instruction accounts
        - Pubkey
        - Signer (bool)
        - Writer (bool)
    - Expected result
        - Either SUCCESS or instruction error code

- Need to
    - In Python:
        - Create and sign the raw transactions
        - Output list of (raw transactions, result)
        - Output calls to C code which generate the result
    - In C:
        - Test function takes an array of the full transactions and the expected result
        - It parses the transactions
        - Creates a new funk instance
        - Feeds them into the executor
        - Checks to see if the result is what we expect
'''

def read_test_cases(path):
  with open(path, 'r') as f:
    return json.load(f)

def serializeInstructionError(err):
  if isinstance(err, dict):
    return -26
#      return err["Custom"]
  if err == "GenericError":
    return -1
  if err == "InvalidArgument":
    return -2
  if err == "InvalidInstructionData":
    return -3
  if err == "InvalidAccountData":
    return -4
  if err == "AccountDataTooSmall":
    return -5
  if err == "InsufficientFunds":
    return -6
  if err == "IncorrectProgramId":
    return -7
  if err == "MissingRequiredSignature":
    return -8
  if err == "AccountAlreadyInitialized":
    return -9
  if err == "UninitializedAccount":
    return -10
  if err == "UnbalancedInstruction":
    return -11
  if err == "ModifiedProgramId":
    return -12
  if err == "ExternalAccountLamportSpend":
    return -13
  if err == "ExternalAccountDataModified":
    return -14
  if err == "ReadonlyLamportChange":
    return -15
  if err == "ReadonlyDataModified":
    return -16
  if err == "DuplicateAccountIndex":
    return -17
  if err == "ExecutableModified":
    return -18
  if err == "RentEpochModified":
    return -19
  if err == "NotEnoughAccountKeys":
    return -20
  if err == "AccountDataSizeChanged":
    return -21
  if err == "AccountNotExecutable":
    return -22
  if err == "AccountBorrowFailed":
    return -23
  if err == "AccountBorrowOutstanding":
    return -24
  if err == "DuplicateAccountOutOfSync":
    return -25
  if err == "Custom":
    return -26
  if err == "InvalidError":
    return -27
  if err == "ExecutableDataModified":
    return -28
  if err == "ExecutableLamportChange":
    return -29
  if err == "ExecutableAccountNotRentExempt":
    return -30
  if err == "UnsupportedProgramId":
    return -31
  if err == "CallDepth":
    return -32
  if err == "MissingAccount":
    return -33
  if err == "ReentrancyNotAllowed":
    return -34
  if err == "MaxSeedLengthExceeded":
    return -35
  if err == "InvalidSeeds":
    return -36
  if err == "InvalidRealloc":
    return -37
  if err == "ComputationalBudgetExceeded":
    return -38
  if err == "PrivilegeEscalation":
    return -39
  if err == "ProgramEnvironmentSetupFailure":
    return -40
  if err == "ProgramFailedToComplete":
    return -41
  if err == "ProgramFailedToCompile":
    return -42
  if err == "Immutable":
    return -43
  if err == "IncorrectAuthority":
    return -44
  if err == "BorshIoError":
    return -45
  if err == "AccountNotRentExempt":
    return -46
  if err == "InvalidAccountOwner":
    return -47
  if err == "ArithmeticOverflow":
    return -48
  if err == "UnsupportedSysvar":
    return -49
  if err == "IllegalOwner":
    return -50
  if err == "MaxAccountsDataSizeExceeded":
    return -51
  if err == "ActiveVoteAccountClose":
    return -52

def serializeResult(result):
  if "Ok" in result:
    return 0
  if "Err" in result:
    return serializeInstructionError(result["Err"])

def main():  
  argParser = argparse.ArgumentParser()
  argParser.add_argument("-j", "--json", help="Path to the Solana test cases input JSON", required=True)
  args = argParser.parse_args()

  json_test_cases = read_test_cases(args.json)

  print("#include <stdlib.h>")
  print("#include <stdio.h>")
  print("#include \"fd_tests.h\"")
  print("#include \"../../base58/fd_base58.h\"")

  print("")
  print("#ifdef _DISABLE_OPTIMIZATION")
  print("#pragma GCC optimize (\"O0\")")
  print("#endif")
  print("")
  print("extern int fd_executor_test_suite_check_filter(fd_executor_test_suite_t *suite, fd_executor_test_t *test);")
  print("")

  test_case = 0;
  fidx = 1;

  f = None

  for json_test_case in json_test_cases:
    if (test_case % 25) == 0:
          fname = "testcases_" + str(fidx) + ".h"
          f = open(fname, "w")
          print("#include \"{}\"".format(fname))
          fidx = fidx + 1
          
    print("int test_{}(fd_executor_test_suite_t *suite) {}".format(test_case, "{"), file = f)

    print("  fd_executor_test_t test;", file = f)
    print("  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );", file = f)
    print("  test.test_name = \"{}\";".format(json_test_case["name"]), file = f)
    print("  test.test_nonce = {};".format(json_test_case["nonce"]), file = f)
    print("  test.test_number ={};".format(test_case), file = f)

    test_case = test_case + 1

    print("  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;", file = f)

    print ("ulong test_accs_len = {};".format(len(json_test_case["transaction_accounts"])), file = f)

    print("fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );", file = f)
    print("fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );", file = f)

    if len(json_test_case["transaction_accounts"]) > 0:
        print("fd_executor_test_acc_t* test_acc = test_accs;", file = f)

    # Serialize the accounts needed for this test case
    idx = 0
    for e in json_test_case["transaction_accounts"]:
        txn_acc_shared_data = e["shared_data"]
        txn_acc_result = json_test_case["resulting_accounts"][idx]
        print("fd_base58_decode_32( \"{}\",  (unsigned char *) &test_acc->pubkey);".format(e["pubkey"]), file = f)
        print("fd_base58_decode_32( \"{}\",  (unsigned char *) &test_acc->owner);".format(txn_acc_shared_data["owner"]), file = f)
        print("test_acc->lamports = {}UL;".format(txn_acc_shared_data["lamports"]), file = f)
        print("test_acc->result_lamports = {}UL;".format(txn_acc_result["lamports"]), file = f)
        if txn_acc_shared_data["executable"]:
            print("test_acc->executable = 1;", file = f);
        else:
            print("test_acc->executable = 0;", file = f);
        print("test_acc->rent_epoch = {};".format(txn_acc_shared_data["rent_epoch"]), file = f)
        data = bytes.fromhex(txn_acc_shared_data["data"])
        result_data = bytes.fromhex(txn_acc_result["data"])

        print("test_acc->data_len = {};".format(len(data)), file = f)
        if len(data) == 0:
            print("static const uchar test_acc_{}_data[] = {}0{};".format(idx, '{', '}'), file = f)
        else:
            d = str(list(data)).replace('[', '{').replace(']', '}')
            print("static const uchar test_acc_{}_data[] = {};".format(idx, d), file = f)
        print("test_acc->data = test_acc_{}_data;".format(idx), file = f)

        print("test_acc->result_data_len = {};".format(len(result_data)), file = f)
        if len(result_data) == 0:
            print("static const uchar test_acc_{}_result_data[] = {}0{};".format(idx, '{', '}'), file = f)
        else:
            d = str(list(result_data)).replace('[', '{').replace(']', '}')
            print("static const uchar test_acc_{}_result_data[] = {};".format(idx, d), file = f)
        print("test_acc->result_data = test_acc_{}_result_data;".format(idx), file = f)
        print("test_acc++;", file = f)
        idx = idx+1
            
    # Serialize the transaction this test case executes
    accounts = []
    signer_pubkeys = set()
    num_signers = 0
    for account in json_test_case["instruction_accounts"]:
        if bool(account["is_signer"]) and (account["pubkey"] not in signer_pubkeys):
            num_signers += 1
            signer_pubkeys.add(account["pubkey"])
        accounts.append(
            AccountMeta(
                pubkey=Pubkey.from_bytes(base58.b58decode(account["pubkey"])),
                is_signer=bool(account["is_signer"]),
                is_writable=bool(account["is_writable"])
            )
        )

    instruction = Instruction(
      accounts=accounts,
      program_id=Pubkey.from_string(json_test_case["program_id"]),
      data=bytes.fromhex(json_test_case["instruction_data"])
    )

    signatures = [ os.urandom(64) for _ in range(num_signers) ]
    
    tx = Transaction().add(instruction)
    message = tx.serialize_message()

    components = signatures 
    components.append(message)
#    print(components)
    serialized = [ b for bs in components for b in bs ]
    serialized.insert(0, num_signers)
#    print(serialized)

    # Serialize the expected result


    print("  fd_base58_decode_32( \"{}\",  (unsigned char *) &test.program_id);".format(json_test_case["program_id"]), file = f)
    d = str(list(serialized)).replace('[', '{').replace(']', '}')
    print("  static const uchar raw_tx[] = {};".format(d), file = f)
    print("  test.raw_tx = raw_tx;", file = f)
    print("  test.raw_tx_len = {};".format(len(serialized)), file = f)
    res = json_test_case["expected_result"]
    print("  test.expected_result = {};".format(serializeResult(res)), file = f)
    if "Err" in res and isinstance(res["Err"], dict):
        print("  test.custom_err = {};".format(res["Err"]["Custom"]), file = f)
    else:
        print("  test.custom_err = 0;", file = f)
    print("", file = f)
    print("  test.accs_len = test_accs_len;", file = f)
    print("  test.accs = test_accs;", file = f)
    print("", file = f)
    print("  return fd_executor_run_test( &test, suite );", file = f)
    print("}", file = f)
#    sys.exit(0)

  print("")
  print("int run_test(int idx, fd_executor_test_suite_t *suite) {")
  print("switch(idx) {")
  for n in range(test_case):
    print("case {}: return test_{}(suite);".format(n, n))
  print("default: return 0;")
  print("}")
  print("}")
      

if __name__ == "__main__":
  main()
