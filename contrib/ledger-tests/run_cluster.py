'''
Script to generate a test Solana cluster. This is useful for creating test ledgers, and can be used to create both solana-test-validator and multi-node clusters. See --help for usage. E.g:

python3.8 run_cluster.py --solana-source-directory $HOME/git/solana/ --solana-cluster-nodes 5 --output-dir $HOME/scratch/test-cluster

The script will build and use the Solana binaries from the source in the --solana-source-directory, making it easy to build test clusters for different Solana versions.

The cluster can be monitored using
solana -ul validators
solana -ul epoch-info

To stop the cluster, simply kill the script.
'''

import asyncio
from contextlib import asynccontextmanager
import argparse
import shutil
import os

async def shell(cmd, **kwargs):
    return await (await asyncio.create_subprocess_shell(cmd, **kwargs)).wait()

async def build_solana(source_dir):
    await shell("./cargo build --release --package agave-validator --package solana-bench-tps --package solana-cli --package solana-keygen --package solana-dos --package agave-ledger-tool --package solana-genesis", cwd=source_dir)

def solana_binary(name, source_dir):
    return os.path.join(source_dir, "target/release", name)

def parse_genesis_output(output):
    lines = output.split('\n')
    genesis_hash = None
    shred_version = None

    for line in lines:
        if 'Genesis hash' in line:
            genesis_hash = line.split(':')[1].strip()

        elif 'Shred version' in line:
            shred_version = line.split(':')[1].strip()

    return genesis_hash, shred_version

async def run_genesis(output_dir, solana_source_directory):
    process = await asyncio.create_subprocess_shell(
        f"{solana_binary('solana-genesis', solana_source_directory)} --cluster-type mainnet-beta --ledger node-ledger-0 --enable-warmup-epochs --bootstrap-validator 'keys-0/id.json' 'keys-0/vote.json' 'keys-0/stake.json' --bootstrap-stake-authorized-pubkey 'keys-0/id.json' --bootstrap-validator-lamports 10000000000 --bootstrap-validator-stake-lamports 32282880 --faucet-pubkey 'faucet.json' --faucet-lamports 5000000000000000 --hashes-per-tick sleep --target-tick-duration 1000",
         stdout=asyncio.subprocess.PIPE,
         stderr=asyncio.subprocess.PIPE,
         cwd=output_dir)
    stdout, _stderr = await process.communicate()

    return parse_genesis_output(stdout.decode('utf-8'))

async def generate_cluster_keys(nodes, output_dir, solana_source_directory):
     await shell(f"{solana_binary('solana-keygen', solana_source_directory)} new --no-bip39-passphrase -o 'faucet.json'", cwd=output_dir)
     await shell(f"{solana_binary('solana-keygen', solana_source_directory)} new --no-bip39-passphrase -o 'authority.json'", cwd=output_dir)

     for i in range(nodes):
        key_dir = os.path.join(output_dir, f"keys-{i}")
        os.mkdir(key_dir)
        await shell(f"")
        for key in ["id", "vote", "stake"]:
            with open(os.path.join(key_dir, f"{key}.seed"), "w") as id_seed_file:
                await shell(f"{solana_binary('solana-keygen', solana_source_directory)} new --no-bip39-passphrase -o '{key}.json'", cwd=key_dir, stdout=id_seed_file)

async def get_pubkey(vote_key, solana_source_directory):
    process = await asyncio.create_subprocess_shell(
        f"{solana_binary('solana-keygen', solana_source_directory)} pubkey {vote_key}",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, _ = await process.communicate()
    if process.returncode != 0:
        raise Exception("solana-keygen command failed")
    return stdout.decode().strip()

@asynccontextmanager
async def first_cluster_validator(expected_shred_version, expected_genesis_hash, solana_source_directory, output_dir):
    ledger_path = os.path.join(output_dir, "node-ledger-0")
    identity_key = os.path.join(output_dir, "keys-0", "id.json")
    vote_key = os.path.join(output_dir, "keys-0", "vote.json")

    vote_pubkey = await get_pubkey(vote_key, solana_source_directory)

    process = await asyncio.create_subprocess_shell(
        f"{solana_binary('agave-validator', solana_source_directory)} --allow-private-addr --identity {identity_key}  --ledger {ledger_path} --limit-ledger-size 100000000 --dynamic-port-range 8000-8100 --no-genesis-fetch --no-snapshot-fetch --no-poh-speed-test --no-os-network-limits-test --vote-account {vote_pubkey} --expected-shred-version {expected_shred_version} --expected-genesis-hash {expected_genesis_hash} --no-wait-for-vote-to-start-leader --incremental-snapshots --full-snapshot-interval-slots 200 --rpc-port 8899 --gossip-port 8010 --full-rpc-api --tpu-enable-udp --log {ledger_path}/validator.log",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    try:
        yield process
    finally:
        process.terminate()
        await process.wait()

@asynccontextmanager
async def solana_cluster_validators(count, expected_shred_version, expected_genesis_hash, solana_source_directory, output_dir):
    # Create and delegate the stake accounts
    print("Creating and delegating to stake accounts", flush=True)
    for i in range(1, count):
        vote_key = os.path.join(output_dir, f"keys-{i}", "vote.json")
        stake_key = os.path.join(output_dir, f"keys-{i}", "stake.json")
        faucet_key = os.path.join(output_dir, "faucet.json")
        authority_key = os.path.join(output_dir, "authority.json")

        # Create the stake account for this validator
        await shell(f"{solana_binary('solana', solana_source_directory)} -ul create-stake-account -k {faucet_key} --stake-authority {authority_key} --withdraw-authority {faucet_key} {stake_key} 1")
        # Delegate the stake to this validator's vote account
        await shell(f"{solana_binary('solana', solana_source_directory)} -ul delegate-stake -k {faucet_key} --stake-authority {authority_key} {stake_key} {vote_key}")

    await asyncio.sleep(5)

    processes = []
    try:
        print("Spawning the rest of the validator nodes", flush=True)
        for i in range(1, count):
            print(f"Spawning validator node {i}", flush=True)
            ledger_path = os.path.join(output_dir, f"node-ledger-{i}")
            log_path = os.path.join(output_dir, f"validator-{i}.log")
            identity_key = os.path.join(output_dir, f"keys-{i}", "id.json")
            vote_key = os.path.join(output_dir, f"keys-{i}", "vote.json")
            stake_key = os.path.join(output_dir, f"keys-{i}", "stake.json")
            faucet_key = os.path.join(output_dir, "faucet.json")
            authority_key = os.path.join(output_dir, "authority.json")

            vote_pubkey = await get_pubkey(vote_key, solana_source_directory)

            process = await asyncio.create_subprocess_shell(
                f"{solana_binary('agave-validator', solana_source_directory)} --allow-private-addr --identity {identity_key}  --ledger {ledger_path} --limit-ledger-size 100000000 --dynamic-port-range 8{i}00-8{i}99 --no-poh-speed-test --no-os-network-limits-test --vote-account {vote_pubkey} --entrypoint 127.0.0.1:8010 --expected-shred-version {expected_shred_version} --expected-genesis-hash {expected_genesis_hash} --tpu-disable-quic --tpu-enable-udp --log {log_path} --incremental-snapshot-interval-slots 0",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            processes.append(process)

        yield processes
    finally:
        for process in processes:
            process.terminate()
            await process.wait()

@asynccontextmanager
async def spawn_solana_cluster(nodes, output_dir, solana_source_directory):
    await generate_cluster_keys(nodes, output_dir, solana_source_directory)
    genesis_hash, shred_version = await run_genesis(output_dir, solana_source_directory)

    async with first_cluster_validator(shred_version, genesis_hash, solana_source_directory, output_dir):

        # Wait for the first validator to be ready
        print("Waiting for the first validator to be ready", flush=True)
        while True:
            process = await asyncio.create_subprocess_shell(
                f"{solana_binary('solana', solana_source_directory)} -ul validators",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()

            if "1 current validators" in stdout.decode():
                break

        # Set up and fund vote accounts for the rest of the validators
        print("Creating and funding vote accounts for the rest of the validators", flush=True)
        for i in range(1, nodes):
            faucet_key = os.path.join(output_dir, "faucet.json")
            id_key = os.path.join(output_dir, f"keys-{i}", "id.json")
            vote_key = os.path.join(output_dir, f"keys-{i}", "vote.json")
            # Send some SOL to the identity account, so it can pay for creating vote transactions
            await shell(f"{solana_binary('solana', solana_source_directory)} -ul transfer -k {faucet_key} --allow-unfunded-recipient {id_key} 100")
            # Create vote accounts for the validators
            await shell(f"{solana_binary('solana', solana_source_directory)} -ul create-vote-account -k {id_key} --allow-unsafe-authorized-withdrawer {vote_key} {id_key} {id_key}")

        # Wait for the output_directory/node_ledger_0/snapshot/200/state_complete file to exist
        print("Waiting for the first validator to create a snapshot at slot 200", flush=True)
        while True:
            process = await asyncio.create_subprocess_shell(
                f"{solana_binary('solana', solana_source_directory)} -ul validators",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()

            if os.path.exists(os.path.join(output_dir, "node-ledger-0", "snapshot", "200", "state_complete")):
                break
            await asyncio.sleep(1)

        # Start the other validators
        print("Starting the other validators", flush=True)
        async with solana_cluster_validators(nodes, shred_version, genesis_hash, solana_source_directory, output_dir):

            # Wait for all validators to be ready
            while True:
                process = await asyncio.create_subprocess_shell(
                    f"{solana_binary('solana', solana_source_directory)} -ul validators",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await process.communicate()

                if f"{nodes} current validators" in stdout.decode():
                    yield

@asynccontextmanager
async def spawn_solana_test_validator(solana_source_directory, output_dir):
    try:
        process = await asyncio.create_subprocess_shell(
            f"{solana_binary('solana-test-validator', solana_source_directory)}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=output_dir
        )
        yield process
    finally:
        process.terminate()
        await process.wait()

@asynccontextmanager
async def solana(cluster_nodes, test_validator, output_dir, solana_source_directory):
    await build_solana(solana_source_directory)
    try:
        if test_validator:
            async with spawn_solana_test_validator(solana_source_directory, output_dir):
                yield
        else:
            async with spawn_solana_cluster(cluster_nodes, output_dir, solana_source_directory):
                yield
    finally:
        pass

def clean(output_dir):
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    os.mkdir(output_dir)

async def main():
    parser = argparse.ArgumentParser(description="Run Solana validators with specified configuration")
    parser.add_argument("--solana-source-directory", required=True, type=str, help="Absolute path to the Solana checkout")
    cluster_type_args = parser.add_mutually_exclusive_group(required=True)
    cluster_type_args.add_argument("--solana-cluster-nodes", required=False, type=int, help="Number of nodes to use for the multi-node Solana cluster")
    cluster_type_args.add_argument("--solana-test-validator", action='store_true', help="Use a solana-test-validator instance instead of a multi-node cluster")
    parser.add_argument("--output-dir", required=True, type=str, help="Output directory where validator keys and ledgers are written to")
    args = parser.parse_args()

    clean(args.output_dir)

    async with solana(args.solana_cluster_nodes, args.solana_test_validator, args.output_dir, args.solana_source_directory):
        while True:
            await asyncio.sleep(1)

if __name__ == "__main__":
    asyncio.run(main())
