# docker run -v .:/tests --security-opt label=disable python3.8 python3 /tests/gen_c_tests.py -j /tests/system_program_tests.json

import argparse
import json
import os
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

  for json_test_case in json_test_cases:

    print("-------------- TEST CASE --------------")

    # Serialize the accounts needed for this test case
    for [txn_acc_pubkey, txn_acc_shared_data] in json_test_case["transaction_accounts"]:
      print({
        "pubkey": txn_acc_pubkey,
        "lamports": txn_acc_shared_data["lamports"],
        "data": txn_acc_shared_data["data"],
        "owner": txn_acc_shared_data["owner"],
        "executable": txn_acc_shared_data["executable"],
        "rent_epoch": txn_acc_shared_data["rentEpoch"],
      })

    # Serialize the transaction this test case executes
    accounts = []
    for account in json_test_case["instruction_accounts"]:
      accounts.append(
        AccountMeta(
          pubkey=Pubkey.from_bytes(bytes(account["pubkey"])),
          is_signer=bool(account["is_signer"]),
          is_writable=bool(account["is_writable"])
        )
      )

    instruction = Instruction(
      accounts=accounts,
      program_id=Pubkey.from_string(json_test_case["program_id"]),
      data=bytes(json_test_case["instruction_data"])
    )

    num_signers = 0
    for account in json_test_case["instruction_accounts"]:
      if bool(account["is_writable"]):
        num_signers += 1
    signatures = [ os.urandom(64) for _ in range(num_signers) ]
    
    tx = Transaction().add(instruction)
    message = tx.serialize_message()

    components = signatures 
    components.append(message)
    serialized = [ b for bs in components for b in bs ]
    serialized.insert(0, num_signers)
    print(serialized)

    # Serialize the expected result
    print(serializeResult(json_test_case["expected_result"]))
  
#   print(json_test_cases)
  
if __name__ == "__main__":
  main()
