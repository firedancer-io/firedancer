#!/usr/bin/env python3

"""Main CLI module for agave-cluster commands."""

import os
import sys
import subprocess
import shutil
import click
from pathlib import Path
import time
from . import __version__
from concurrent.futures import ThreadPoolExecutor, as_completed


def ip():
    ip = subprocess.check_output(
        "ip -o -4 addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -n1",
        shell=True, text=True
    ).strip()
    return ip


def get_env_var(var_name):
    """Get the environment variable value."""
    value = os.environ.get(var_name)
    if not value:
        click.echo(f"Error: {var_name} environment variable is not set.", err=True)
        click.echo(f"Please activate the agave-cluster environment with: source activate <FIREDANCER_REPO_PATH> <AGAVE_RELEASE_PATH> <LEDGER_DIR>", err=True)
        sys.exit(1)
    return Path(value)

def validate_ledger_directory():
    """Validate that the ledger directory exists."""
    ledger_path = get_env_var('AGAVE_LEDGER_PATH')
    if not ledger_path.exists():
        click.echo(f"Error: Ledger directory {ledger_path} does not exist.", err=True)
        click.echo(f"Please create the directory or set a different path with: export AGAVE_LEDGER_PATH=<LEDGER_PATH>", err=True)
        sys.exit(1)
    return ledger_path

def solana_binary(name):
    return str(get_env_var('AGAVE_RELEASE_PATH') / "target" / "release" / name)

def create_key(key_path):
    solana_keygen = solana_binary('solana-keygen')
    subprocess.run([solana_keygen, "new", "--no-bip39-passphrase", "--silent", "--outfile", key_path, "--force"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def get_pubkey(key_path):
    """Get the public key from a key file."""
    solana_keygen = solana_binary('solana-keygen')
    result = subprocess.run([solana_keygen, "pubkey", key_path], capture_output=True, text=True)
    if result.returncode != 0:
        raise Exception(f"Failed to get pubkey for {key_path}: {result.stderr}")
    return result.stdout.strip()


def get_cluster_info(key):
    """Get cluster information from the cluster-info.txt file."""
    cluster_path = str(get_env_var('AGAVE_LEDGER_PATH'))
    info_path = os.path.join(cluster_path, 'cluster-info.txt')
    try:
        with open(info_path, 'r') as f:
            for line in f:
                if line.startswith(key):
                    return line.split('=')[1].strip()
    except FileNotFoundError:
        return None
    return None


@click.group()
@click.version_option(version=__version__)
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.pass_context
def main(ctx, verbose):
    """Agave cluster management CLI tool."""
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose


@main.command('start-cluster')
@click.option('--bootstrap-validator-name', '-n', type=str, required=False, default='node-ledger-0', help='Bootstrap validator name')
@click.pass_context
def start_cluster(ctx, bootstrap_validator_name):
    """Start an Agave cluster."""
    agave_path = get_env_var('AGAVE_RELEASE_PATH')
    verbose = ctx.obj['verbose']

    cluster_path = str(validate_ledger_directory())

    if verbose:
        click.echo(f"Starting cluster with Agave release at: {agave_path}")
        click.echo(f"Cluster Path: {cluster_path}")

    info_path = os.path.join(cluster_path, 'cluster-info.txt')
    if os.path.exists(info_path):
        click.echo("Stopping any existing cluster processes...")
        import signal
        pids_to_stop = []
        with open(info_path, 'r') as f:
            for line in f:
                if "_pid=" in line:
                    pid_value = line.split('=')[1].strip()
                    if pid_value != 'NA':
                        try:
                            pid = int(pid_value)
                            pids_to_stop.append(pid)
                        except ValueError:
                            pass

        for pid in pids_to_stop:
            try:
                os.kill(pid, signal.SIGTERM)
                if verbose:
                    click.echo(f"Stopped process {pid}")
            except (ProcessLookupError, PermissionError):
                pass

        if pids_to_stop:
            time.sleep(1)

    click.echo("🚀 Starting Agave cluster...")

    click.echo(f"Using solana-genesis binary: {solana_binary('solana-genesis')}")
    if os.path.exists(cluster_path):
        shutil.rmtree(cluster_path)
    os.makedirs(cluster_path)

    open(os.path.join(cluster_path, 'cluster-info.txt'), 'w').close()

    os.makedirs(os.path.join(cluster_path, 'keys', bootstrap_validator_name))
    os.makedirs(os.path.join(cluster_path, 'nodes', bootstrap_validator_name))
    os.makedirs(os.path.join(cluster_path, 'stake-accounts'))

    faucet_key = os.path.join(cluster_path, 'faucet.json')
    authority_key = os.path.join(cluster_path, 'authority.json')

    create_key(faucet_key)
    create_key(authority_key)

    node_path = os.path.join(cluster_path, 'nodes', bootstrap_validator_name)
    node_keys_path = os.path.join(cluster_path, 'keys', bootstrap_validator_name)
    stake_accounts_path = os.path.join(cluster_path, 'stake-accounts')

    id_key = os.path.join(node_keys_path, 'id.json')
    vote_key = os.path.join(node_keys_path, 'vote.json')

    stake_accounts_count = len(os.listdir(stake_accounts_path))
    stake_key = os.path.join(stake_accounts_path, f"stake-account-{stake_accounts_count}.json")

    create_key(id_key)
    create_key(vote_key)
    create_key(stake_key)

    solana_genesis = solana_binary('solana-genesis')

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

    firedancer_repo_path = get_env_var('FIREDANCER_REPO_PATH')
    stake_program_path = os.path.join(str(firedancer_repo_path), "contrib/ledger-gen/bpf_migrated_programs/stake_elf.so")

    genesis_output = subprocess.run([solana_genesis, "--cluster-type", "mainnet-beta", "--ledger", node_path, "--bootstrap-validator", id_key, vote_key, stake_key, "--bootstrap-stake-authorized-pubkey", id_key, "--bootstrap-validator-lamports", "10000000000", "--bootstrap-validator-stake-lamports", "18000000000", "--faucet-pubkey", faucet_key, "--faucet-lamports", "500000000000000000", "--slots-per-epoch", "256", "--enable-warmup-epochs", "--upgradeable-program", "Stake11111111111111111111111111111111111111", "BPFLoaderUpgradeab1e11111111111111111111111", stake_program_path, "11111111111111111111111111111111" ], cwd=cluster_path, capture_output=True, text=True)
    genesis_hash, shred_version = parse_genesis_output(genesis_output.stdout)

    info_path = os.path.join(cluster_path, 'cluster-info.txt')
    with open(info_path, 'a') as f:
        f.write(f"genesis_hash={genesis_hash}\n")
        f.write(f"shred_version={shred_version}\n")

    agave_validator = solana_binary('agave-validator')

    validator_process = subprocess.Popen([agave_validator, "--rpc-bind-address", f"{ip()}", "--allow-private-addr", "--enable-rpc-transaction-history", "--identity", id_key, "--ledger", node_path, "--limit-ledger-size", "100000000", "--dynamic-port-range", "8000-8099", "--no-snapshot-fetch", "--no-poh-speed-test", "--no-os-network-limits-test", "--vote-account", vote_key, "--expected-shred-version", shred_version, "--expected-genesis-hash", genesis_hash, "--no-wait-for-vote-to-start-leader", "--full-snapshot-interval-slots", "100" , "--snapshot-interval-slots", "20", "--maximum-full-snapshots-to-retain", "10", "--rpc-port", "8899", "--gossip-port", "8010", "--full-rpc-api", "--bind-address", ip(), "--log", f"{node_path}/validator.log"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setpgrp)

    validator_pid = validator_process.pid
    click.echo(f"Validator {bootstrap_validator_name} has started with pid {validator_pid}")

    with open(info_path, 'a') as f:
        f.write(f"{bootstrap_validator_name}_pid={validator_pid}\n")

    time.sleep(2)

    click.echo("Funding authority account...")
    solana = solana_binary('solana')
    result = subprocess.run([solana, "-u", f"http://{ip()}:8899", "transfer", "-k", faucet_key, "--allow-unfunded-recipient", authority_key, "100"], capture_output=True, text=True)
    if result.returncode != 0:
        click.echo(f"Warning: Failed to fund authority account: {result.stderr}", err=True)
        click.echo("Authority account will need to be funded manually before creating staked validators", err=True)
    else:
        click.echo(f"Authority account funded: {get_pubkey(authority_key)}")

    click.echo(f"✅ Cluster started successfully at: {cluster_path}")
    click.echo(f"Cluster URL: http://{ip()}:8899")
    click.echo(f"Node path: {node_path}")
    click.echo((f"Log file: {node_path}/validator.log"))


@main.command('stop-cluster')
@click.option('--force', '-f', is_flag=True, help='Force stop the cluster')
@click.pass_context
def stop_cluster(ctx, force):
    """Stop the Agave cluster."""
    verbose = ctx.obj['verbose']

    if verbose:
        try:
            agave_path = get_env_var('AGAVE_RELEASE_PATH')
            click.echo(f"Stopping cluster with Agave release at: {agave_path}")
        except SystemExit:
            pass
        click.echo(f"Force stop: {force}")

    click.echo("🛑 Stopping Agave cluster...")

    try:
        cluster_path = str(get_env_var('AGAVE_LEDGER_PATH'))
        info_path = os.path.join(cluster_path, 'cluster-info.txt')

        if not os.path.exists(info_path):
            click.echo("No cluster info file found. Cluster may not be running.")
            return

        pids_to_stop = {}
        with open(info_path, 'r') as f:
            for line in f:
                if "_pid=" in line:
                    node_name = line.split('=')[0].replace('_pid', '').strip()
                    pid_value = line.split('=')[1].strip()
                    if pid_value == 'NA':
                        continue
                    pid = int(pid_value)
                    pids_to_stop[node_name] = pid

        if not pids_to_stop:
            click.echo("No running processes found.")
            return

        import signal
        for node_name, pid in pids_to_stop.items():
            try:
                if verbose:
                    click.echo(f"Stopping node {node_name}...")
                os.kill(pid, signal.SIGTERM if not force else signal.SIGKILL)
                click.echo(f"Stopped node {node_name}")
            except ProcessLookupError:
                if verbose:
                    click.echo(f"Node {node_name} was not running")
            except PermissionError:
                click.echo(f"Permission denied stopping node {node_name}", err=True)
            except Exception as e:
                click.echo(f"Error stopping node {node_name}: {e}", err=True)

        click.echo("✅ Cluster stopped successfully!")

    except FileNotFoundError:
        click.echo("Error: AGAVE_LEDGER_PATH not set or directory not found. Please check your environment variables.", err=True)


@main.command('add-node')
@click.option('--validator-name', '-n', type=str, help='Name of the node to add')
@click.pass_context
def add_node(ctx, validator_name):
    """Add a new node to the cluster."""

    cluster_path = str(get_env_var('AGAVE_LEDGER_PATH'))
    info_path = os.path.join(cluster_path, 'cluster-info.txt')

    current_node_count = len(os.listdir(os.path.join(cluster_path, 'nodes')))

    if not validator_name:
        validator_name = f"node-ledger-{current_node_count}"

    if os.path.exists(os.path.join(cluster_path, 'keys', validator_name)):
        shutil.rmtree(os.path.join(cluster_path, 'keys', validator_name))
    os.makedirs(os.path.join(cluster_path, 'keys', validator_name))

    if os.path.exists(os.path.join(cluster_path, 'nodes', validator_name)):
        shutil.rmtree(os.path.join(cluster_path, 'nodes', validator_name))
    os.makedirs(os.path.join(cluster_path, 'nodes', validator_name))

    node_path = os.path.join(cluster_path, 'nodes', validator_name)
    node_keys_path = os.path.join(cluster_path, 'keys', validator_name)

    stake_accounts_path = os.path.join(cluster_path, 'stake-accounts')
    stake_accounts_count = len(os.listdir(stake_accounts_path))
    stake_key = os.path.join(stake_accounts_path, f"stake-account-{stake_accounts_count}.json")

    id_key = os.path.join(node_keys_path, 'id.json')
    vote_key = os.path.join(node_keys_path, 'vote.json')

    create_key(id_key)
    create_key(vote_key)
    create_key(stake_key)

    agave_validator = solana_binary('agave-validator')
    genesis_hash = get_cluster_info('genesis_hash')
    shred_version = get_cluster_info('shred_version')

    faucet_key = os.path.join(cluster_path, 'faucet.json')
    authority_key = os.path.join(cluster_path, 'authority.json')

    solana = solana_binary('solana')

    subprocess.run([solana, "-u", f"http://{ip()}:8899", "transfer", "-k", faucet_key, "--allow-unfunded-recipient", id_key, "100"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    subprocess.run([solana, "-u", f"http://{ip()}:8899", "create-vote-account", "-k", id_key, "--allow-unsafe-authorized-withdrawer", vote_key, id_key, id_key], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    subprocess.run([solana, "-u", f"http://{ip()}:8899", "create-stake-account", "-k", faucet_key, "--stake-authority", authority_key, "--withdraw-authority", faucet_key, stake_key, "1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run([solana, "-u", f"http://{ip()}:8899", "delegate-stake", "-k", faucet_key, "--stake-authority", authority_key, stake_key, vote_key], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    vote_pubkey = get_pubkey(vote_key)

    validator_process = subprocess.Popen([agave_validator, "--allow-private-addr", "--identity", id_key, "--ledger", node_path, "--limit-ledger-size", "100000000", "--dynamic-port-range", f"8{current_node_count}00-8{current_node_count}99", "--no-poh-speed-test", "--no-os-network-limits-test", "--vote-account", vote_pubkey, "--entrypoint", f"{ip()}:8010", "--gossip-port", f"8{current_node_count}10", "--expected-shred-version", shred_version, "--expected-genesis-hash", genesis_hash, "--tpu-disable-quic", "--log", f"{node_path}/validator.log"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setpgrp)

    validator_pid = validator_process.pid
    click.echo(f"Validator {validator_name} has started with pid {validator_pid}")

    with open(info_path, 'a') as f:
        f.write(f"{validator_name}_pid={validator_pid}\n")

    click.echo("Giving validator time to initialize...")
    time.sleep(1)
    click.echo(f"✅ Node {validator_name} added successfully!")
    click.echo(f"Node path: {node_path}")
    click.echo(f"Log file: {node_path}/validator.log")


@main.command('create-unstaked-keys')
@click.option('--validator-name', '-n', type=str, help='Name of the node to add')
@click.pass_context
def create_unstaked_keys(ctx, validator_name):
    """Create Unstaked keys."""
    cluster_path = str(get_env_var('AGAVE_LEDGER_PATH'))
    info_path = os.path.join(cluster_path, 'cluster-info.txt')

    current_node_count = len(os.listdir(os.path.join(cluster_path, 'nodes')))

    if not validator_name:
        validator_name = f"fd-node-ledger-{current_node_count}"

    if os.path.exists(os.path.join(cluster_path, 'keys', validator_name)):
        shutil.rmtree(os.path.join(cluster_path, 'keys', validator_name))
    os.makedirs(os.path.join(cluster_path, 'keys', validator_name))

    if os.path.exists(os.path.join(cluster_path, 'nodes', validator_name)):
        shutil.rmtree(os.path.join(cluster_path, 'nodes', validator_name))
    os.makedirs(os.path.join(cluster_path, 'nodes', validator_name))

    node_keys_path = os.path.join(cluster_path, 'keys', validator_name)

    id_key = os.path.join(node_keys_path, 'id.json')
    vote_key = os.path.join(node_keys_path, 'vote.json')

    create_key(id_key)
    create_key(vote_key)

    faucet_key = os.path.join(cluster_path, 'faucet.json')
    solana = solana_binary('solana')

    subprocess.run([solana, "-u", f"http://{ip()}:8899", "transfer", "-k", faucet_key, "--allow-unfunded-recipient", id_key, "100"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    subprocess.run([solana, "-u", f"http://{ip()}:8899", "create-vote-account", "-k", id_key, "--allow-unsafe-authorized-withdrawer", vote_key, id_key, id_key], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    click.echo(f"Keys for validator {validator_name} created successfully!")
    click.echo(f"Identity key content:")
    click.echo(f"Identity key at: {id_key} with content: {open(id_key, 'r').read()}")
    click.echo(f"Vote key at: {vote_key} with content: {open(vote_key, 'r').read()}")

    with open(info_path, 'a') as f:
        f.write(f"{validator_name}_pid=NA\n")

@main.command('create-staked-keys')
@click.option('--validator-name', '-n', type=str, help='Name of the node to add')
@click.option('--sol', type=float, help='Amount of SOL to stake')
@click.option('--percentage', type=int, help='Percentage of the validator to stake')
@click.pass_context
def create_staked_keys(ctx, validator_name, sol, percentage):
    if (not sol and not percentage) or (sol and percentage):
        click.echo("Error: Either --sol or --percentage must be provided (not both)", err=True)
        sys.exit(1)

    cluster_path = str(get_env_var('AGAVE_LEDGER_PATH'))
    info_path = os.path.join(cluster_path, 'cluster-info.txt')

    current_node_count = len(os.listdir(os.path.join(cluster_path, 'nodes')))

    if not validator_name:
        validator_name = f"fd-node-ledger-{current_node_count}"

    if os.path.exists(os.path.join(cluster_path, 'keys', validator_name)):
        shutil.rmtree(os.path.join(cluster_path, 'keys', validator_name))
    os.makedirs(os.path.join(cluster_path, 'keys', validator_name))

    if os.path.exists(os.path.join(cluster_path, 'nodes', validator_name)):
        shutil.rmtree(os.path.join(cluster_path, 'nodes', validator_name))
    os.makedirs(os.path.join(cluster_path, 'nodes', validator_name))

    node_keys_path = os.path.join(cluster_path, 'keys', validator_name)

    id_key = os.path.join(node_keys_path, 'id.json')
    vote_key = os.path.join(node_keys_path, 'vote.json')

    click.echo(f"Creating keys for validator {validator_name}...")
    create_key(id_key)
    create_key(vote_key)

    faucet_key = os.path.join(cluster_path, 'faucet.json')
    solana = solana_binary('solana')

    click.echo("Funding identity account...")
    result = subprocess.run([solana, "-u", f"http://{ip()}:8899", "transfer", "-k", faucet_key, "--allow-unfunded-recipient", id_key, "100"], capture_output=True, text=True)
    if result.returncode != 0:
        click.echo(f"Error funding identity account: {result.stderr}", err=True)
        sys.exit(1)

    click.echo("Creating vote account...")
    result = subprocess.run([solana, "-u", f"http://{ip()}:8899", "create-vote-account", "-k", id_key, "--allow-unsafe-authorized-withdrawer", vote_key, id_key, id_key, "--commitment", "confirmed"], capture_output=True, text=True)
    if result.returncode != 0:
        click.echo(f"Error creating vote account: {result.stderr}", err=True)
        sys.exit(1)

    click.echo("Waiting for vote account confirmation...")
    time.sleep(2)

    vote_pubkey = get_pubkey(vote_key)
    result = subprocess.run([solana, "-u", f"http://{ip()}:8899", "vote-account", vote_pubkey], capture_output=True, text=True)
    if result.returncode != 0:
        click.echo(f"Error: Vote account not found on-chain: {result.stderr}", err=True)
        click.echo("The vote account may not have been created successfully.", err=True)
        sys.exit(1)

    click.echo(f"Keys for validator {validator_name} created successfully!")
    click.echo(f"  Identity key: {id_key}")
    click.echo(f"  Identity pubkey: {get_pubkey(id_key)}")
    click.echo(f"  Vote key: {vote_key}")
    click.echo(f"  Vote pubkey: {vote_pubkey}")

    with open(info_path, 'a') as f:
        f.write(f"{validator_name}_pid=NA\n")

    if percentage:
        click.echo(f"Calculating stake amount for {percentage}% of network...")
        result = subprocess.run([solana, '-u', f'http://{ip()}:8899', 'stake-history'], capture_output=True, text=True)
        if result.returncode != 0:
            click.echo(f"Error getting stake history: {result.stderr}", err=True)
            sys.exit(1)

        stake_history_output = result.stdout
        first_entry = stake_history_output.splitlines()[3]
        epoch, effective_stake, activating_stake, deactivating_stake, _ = first_entry.split()
        total_stake = float(effective_stake) + float(activating_stake) - float(deactivating_stake)

        staked_sol_amount = int(total_stake / (1 - float(percentage)/100.0) * float(percentage)/100.0)
        click.echo(f"  Calculated stake amount: {staked_sol_amount} SOL ({percentage}% of network)")
    else:
        staked_sol_amount = int(sol)
        click.echo(f"  Stake amount: {staked_sol_amount} SOL")

    stake_accounts_path = os.path.join(cluster_path, 'stake-accounts')
    stake_accounts_count = len(os.listdir(stake_accounts_path))

    stake_key = os.path.join(stake_accounts_path, f"stake-account-{stake_accounts_count}.json")
    create_key(stake_key)

    authority_key = os.path.join(cluster_path, 'authority.json')

    click.echo("Creating stake account...")
    result = subprocess.run([solana, "-u", f"http://{ip()}:8899", "create-stake-account", "-k", faucet_key, "--stake-authority", authority_key, "--withdraw-authority", faucet_key, stake_key, f"{staked_sol_amount}", "--commitment", "confirmed"], capture_output=True, text=True)
    if result.returncode != 0:
        click.echo(f"Error creating stake account: {result.stderr}", err=True)
        click.echo(f"\nFull output: {result.stdout}", err=True)
        click.echo(f"\nDebugging info:", err=True)
        click.echo(f"  Faucet key: {faucet_key}", err=True)
        click.echo(f"  Authority key: {authority_key}", err=True)
        click.echo(f"  Stake key: {stake_key}", err=True)
        click.echo(f"  Amount: {staked_sol_amount} SOL", err=True)
        click.echo(f"  Vote pubkey: {vote_pubkey}", err=True)

        click.echo(f"\nChecking cluster health...", err=True)
        health_check = subprocess.run([solana, "-u", f"http://{ip()}:8899", "cluster-version"], capture_output=True, text=True)
        click.echo(f"Cluster version: {health_check.stdout}", err=True)

        sys.exit(1)

    click.echo("Delegating stake...")
    result = subprocess.run([solana, "-u", f"http://{ip()}:8899", "delegate-stake", "-k", faucet_key, "--stake-authority", authority_key, stake_key, vote_pubkey, "--commitment", "confirmed"], capture_output=True, text=True)
    if result.returncode != 0:
        click.echo(f"Error delegating stake: {result.stderr}", err=True)
        sys.exit(1)

    click.echo(f"✅ Staked keys created and {staked_sol_amount} SOL delegated successfully!")
    click.echo(f"  Stake account pubkey: {get_pubkey(stake_key)}")
    click.echo(f"  Delegated to vote account: {vote_pubkey}")


@main.command('delegate-stake')
@click.argument('vote-key', type=str)
@click.argument('amount', type=int)
@click.pass_context
def delegate_stake(ctx, vote_key, amount):
    """Stake a node."""
    cluster_path = str(get_env_var('AGAVE_LEDGER_PATH'))
    info_path = os.path.join(cluster_path, 'cluster-info.txt')

    stake_accounts_path = os.path.join(cluster_path, 'stake-accounts')
    stake_accounts_count = len(os.listdir(stake_accounts_path))

    stake_key = os.path.join(stake_accounts_path, f"stake-account-{stake_accounts_count}.json")
    create_key(stake_key)

    faucet_key = os.path.join(cluster_path, 'faucet.json')
    authority_key = os.path.join(cluster_path, 'authority.json')

    solana = solana_binary('solana')

    subprocess.run([solana, "-u", f"http://{ip()}:8899", "create-stake-account", "-k", faucet_key, "--stake-authority", authority_key, "--withdraw-authority", faucet_key, stake_key, f"{amount}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run([solana, "-u", f"http://{ip()}:8899", "delegate-stake", "-k", faucet_key, "--stake-authority", authority_key, stake_key, vote_key])


@main.command('deactivate-stake')
@click.argument('stake-key', type=str)
@click.pass_context
def deactivate_stake(ctx, stake_key):
    """Deactivate a stake."""
    cluster_path = str(get_env_var('AGAVE_LEDGER_PATH'))
    faucet_key = os.path.join(cluster_path, 'faucet.json')
    authority_key = os.path.join(cluster_path, 'authority.json')

    stake_keys_path = os.path.join(cluster_path, 'stake-accounts')
    for stake_key_path in os.listdir(stake_keys_path):
        current_stake_key = get_pubkey(os.path.join(stake_keys_path, stake_key_path))
        if current_stake_key == stake_key:
            stake_key_path = os.path.join(stake_keys_path, stake_key_path)
            break
    else:
        click.echo(f"Error: Stake key does not exist: {stake_key}")
        return
    click.echo(f"Deactivating stake key: {stake_key_path}")

    solana = solana_binary('solana')
    subprocess.run([solana, "-u", f"http://{ip()}:8899", "deactivate-stake", stake_key_path, "-k", faucet_key, "--stake-authority", authority_key])


@main.command('stop-node')
@click.argument('identifier', type=str)
@click.option('--force', '-f', is_flag=True, help='Force stop the node')
@click.pass_context
def stop_node(ctx, identifier, force):
    """Stop a node by name or identity key."""
    verbose = ctx.obj['verbose']

    if verbose:
        click.echo(f"Stopping node with identifier: {identifier}")
        click.echo(f"Force stop: {force}")

    try:
        cluster_path = str(get_env_var('AGAVE_LEDGER_PATH'))
        info_path = os.path.join(cluster_path, 'cluster-info.txt')

        if not os.path.exists(info_path):
            click.echo("No cluster info file found. Cluster may not be running.")
            return

        pids_to_stop = {}
        with open(info_path, 'r') as f:
            for line in f:
                if "_pid=" in line:
                    node_name = line.split('=')[0].replace('_pid', '').strip()
                    pid_value = line.split('=')[1].strip()
                    if pid_value == 'NA':
                        continue
                    pid = int(pid_value)
                    pids_to_stop[node_name] = pid

        if identifier in pids_to_stop:
            pid = pids_to_stop[identifier]
        else:
            found = False
            for node_name in pids_to_stop:
                id_key_path = os.path.join(cluster_path, 'keys', node_name, 'id.json')
                if os.path.exists(id_key_path):
                    id_pubkey = get_pubkey(id_key_path)
                    if id_pubkey == identifier:
                        pid = pids_to_stop[node_name]
                        found = True
                        break
            if not found:
                click.echo(f"No node found with identifier: {identifier}")
                return

        import signal
        try:
            os.kill(pid, signal.SIGTERM if not force else signal.SIGKILL)
            click.echo(f"Stopped node with identifier: {identifier}")
        except ProcessLookupError:
            click.echo(f"Node with identifier {identifier} was not running")
        except PermissionError:
            click.echo(f"Permission denied stopping node with identifier {identifier}", err=True)
        except Exception as e:
            click.echo(f"Error stopping node with identifier {identifier}: {e}", err=True)

    except FileNotFoundError:
        click.echo("Error: AGAVE_LEDGER_PATH not set or directory not found. Please check your environment variables.", err=True)


@main.command('status')
@click.option('--json', 'output_json', is_flag=True, help='Output status in JSON format')
@click.pass_context
def cluster_status(ctx, output_json):
    """Get cluster status."""
    verbose = ctx.obj['verbose']

    if verbose:
        try:
            agave_path = get_env_var('AGAVE_RELEASE_PATH')
            click.echo(f"Getting cluster status with Agave release at: {agave_path}")
        except SystemExit:
            pass

    try:
        cluster_path = str(get_env_var('AGAVE_LEDGER_PATH'))
        info_path = os.path.join(cluster_path, 'cluster-info.txt')

        if not os.path.exists(info_path):
            if output_json:
                click.echo('{"status": "stopped", "nodes": 0, "validators": 0}')
            else:
                click.echo("📊 Cluster Status:")
                click.echo("  Status: Stopped")
                click.echo("  Cluster info file not found")
            return

        running_processes = 0
        genesis_hash = None
        shred_version = None

        with open(info_path, 'r') as f:
            for line in f:
                if line.strip().endswith('_pid'):
                    pid = int(line.split('=')[1].strip())
                    try:
                        os.kill(pid, 0)
                        running_processes += 1
                    except (ProcessLookupError, PermissionError):
                        pass
                elif line.startswith('genesis_hash='):
                    genesis_hash = line.split('=')[1].strip()
                elif line.startswith('shred_version='):
                    shred_version = line.split('=')[1].strip()

        status = "running" if running_processes > 0 else "stopped"

        if output_json:
            import json
            data = {
                "status": status,
                "nodes": running_processes,
                "validators": running_processes,
                "ledger_path": cluster_path
            }
            if genesis_hash:
                data["genesis_hash"] = genesis_hash
            if shred_version:
                data["shred_version"] = shred_version
            click.echo(json.dumps(data, indent=2))
        else:
            click.echo("📊 Cluster Status:")
            click.echo(f"  Status: {status.title()}")
            click.echo(f"  Cluster URL: http://{ip()}:8899")
            click.echo(f"  Running Processes: {running_processes}")
            click.echo(f"  Ledger Path: {cluster_path}")
            if genesis_hash:
                click.echo(f"  Genesis Hash: {genesis_hash}")
            if shred_version:
                click.echo(f"  Shred Version: {shred_version}")

    except FileNotFoundError:
        click.echo("Error: AGAVE_LEDGER_PATH not set or directory not found. Please check your environment variables.", err=True)


@main.command('logs')
@click.option('--node-id', help='Show logs for specific node')
@click.option('--follow', '-f', is_flag=True, help='Follow log output')
@click.option('--lines', '-n', type=int, default=100, help='Number of lines to show')
@click.pass_context
def show_logs(ctx, node_id, follow, lines):
    """Show cluster logs."""
    verbose = ctx.obj['verbose']

    if verbose:
        try:
            agave_path = get_env_var('AGAVE_RELEASE_PATH')
            click.echo(f"Showing logs with Agave release at: {agave_path}")
        except SystemExit:
            pass
        click.echo(f"Node ID: {node_id}")
        click.echo(f"Follow: {follow}")
        click.echo(f"Lines: {lines}")

    try:
        cluster_path = str(get_env_var('AGAVE_LEDGER_PATH'))

        if not node_id:
            node_id = "node-ledger-0"

        log_file = os.path.join(cluster_path, 'nodes', node_id, 'validator.log')

        if not os.path.exists(log_file):
            click.echo(f"Log file not found: {log_file}")
            click.echo(f"Available nodes in {cluster_path}/nodes/:")
            nodes_dir = os.path.join(cluster_path, 'nodes')
            if os.path.exists(nodes_dir):
                for node_dir in os.listdir(nodes_dir):
                    click.echo(f"  - {node_dir}")
            else:
                click.echo("  No nodes directory found")
            return

        click.echo(f"📋 Showing logs for {node_id}:")
        click.echo(f"Log file: {log_file}")
        click.echo("-" * 80)

        if follow:
            try:
                subprocess.run(['tail', '-f', '-n', str(lines), log_file])
            except KeyboardInterrupt:
                click.echo("\nStopped following logs.")
            except FileNotFoundError:
                click.echo("Error: 'tail' command not found.")
        else:
            try:
                result = subprocess.run(['tail', '-n', str(lines), log_file],
                                      capture_output=True, text=True)
                if result.stdout:
                    click.echo(result.stdout)
                else:
                    click.echo("No logs found or log file is empty.")
            except FileNotFoundError:
                try:
                    with open(log_file, 'r') as f:
                        log_lines = f.readlines()
                        for line in log_lines[-lines:]:
                            click.echo(line.rstrip())
                except Exception as e:
                    click.echo(f"Error reading log file: {e}")

    except FileNotFoundError:
        click.echo("Error: AGAVE_LEDGER_PATH not set or directory not found. Please check your environment variables.", err=True)


@main.command('set-cluster-version')
@click.argument('version', type=str)
@click.option('--force', '-f', is_flag=True, help='Force checkout even with uncommitted changes')
@click.pass_context
def set_cluster_version(ctx, version, force):
    """Set the cluster version by checking out a git tag and building."""
    agave_path = get_env_var('AGAVE_RELEASE_PATH')
    verbose = ctx.obj['verbose']

    if verbose:
        click.echo(f"Setting cluster version to {version} at: {agave_path}")
        click.echo(f"Force checkout: {force}")

    git_dir = agave_path / '.git'
    if not git_dir.exists():
        click.echo(f"Error: {agave_path} is not a git repository", err=True)
        sys.exit(1)

    tag_name = f"v{version}"

    try:
        original_dir = os.getcwd()
        os.chdir(agave_path)

        click.echo(f"🔄 Checking out tag {tag_name}...")

        git_cmd = ['git', 'checkout', tag_name]
        if force:
            git_cmd.insert(2, '--force')

        result = subprocess.run(git_cmd, capture_output=True, text=True)

        if result.returncode != 0:
            click.echo(f"Error: Failed to checkout tag {tag_name}", err=True)
            click.echo(f"Git error: {result.stderr}", err=True)
            sys.exit(1)

        if verbose:
            click.echo(f"Successfully checked out tag {tag_name}")

        click.echo("🔨 Building Agave with cargo build --release...")

        cargo_result = subprocess.run(
            ['cargo', 'build', '--release'],
            capture_output=True,
            text=True
        )

        if cargo_result.returncode != 0:
            click.echo("Error: Cargo build failed", err=True)
            click.echo(f"Cargo error: {cargo_result.stderr}", err=True)
            sys.exit(1)

        if verbose:
            click.echo("Cargo build output:")
            click.echo(cargo_result.stdout)

        click.echo(f"✅ Successfully set cluster version to {version} and built release!")

    except subprocess.CalledProcessError as e:
        click.echo(f"Error: Command failed with exit code {e.returncode}", err=True)
        click.echo(f"Error output: {e.stderr}", err=True)
        sys.exit(1)
    except FileNotFoundError as e:
        if 'git' in str(e):
            click.echo("Error: git command not found. Please ensure git is installed.", err=True)
        elif 'cargo' in str(e):
            click.echo("Error: cargo command not found. Please ensure Rust/Cargo is installed.", err=True)
        else:
            click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Unexpected error: {e}", err=True)
        sys.exit(1)
    finally:
        try:
            os.chdir(original_dir)
        except:
            pass

@main.command('cluster-version')
@click.pass_context
def cluster_version(ctx):
    """Get the cluster version."""
    agave_path = get_env_var('AGAVE_RELEASE_PATH')

    try:
        original_dir = os.getcwd()
        os.chdir(agave_path)
        git_cmd = ['git', 'describe', '--tags', '--exact-match']

        result = subprocess.run(git_cmd, capture_output=True, text=True)

        click.echo(result.stdout.replace('\n', '').replace('v', ''))

    except subprocess.CalledProcessError as e:
        click.echo(f"Error: Command failed with exit code {e.returncode}", err=True)
        click.echo(f"Error output: {e.stderr}", err=True)
        sys.exit(1)
    finally:
        try:
            os.chdir(original_dir)
        except:
            pass

@main.command('validators')
@click.pass_context
def validators(ctx):
    """Show validators and their keys."""
    verbose = ctx.obj['verbose']

    if verbose:
        try:
            agave_path = get_env_var('AGAVE_RELEASE_PATH')
            click.echo(f"Showing validators with Agave release at: {agave_path}")
        except SystemExit:
            pass

    solana = solana_binary('solana')

    def execute_solana_command(command):
        return subprocess.run(command, capture_output=True, text=True).stdout

    with ThreadPoolExecutor() as executor:
        solana_commands = [
            [solana, "epoch-info", "-u", f"http://{ip()}:8899"],
            [solana, "validators", "-u", f"http://{ip()}:8899", "--keep-unstaked-delinquents"]
        ]
        futures = {executor.submit(execute_solana_command, command): command for command in solana_commands}
        results = {}
        for future in as_completed(futures):
            command = futures[future]
            results[tuple(command)] = future.result()

    epoch_in_output = results[tuple(solana_commands[0])]
    validators_output = results[tuple(solana_commands[1])]

    click.echo(epoch_in_output)
    click.echo(validators_output)

    cluster_path = str(get_env_var('AGAVE_LEDGER_PATH'))
    keys_path = os.path.join(cluster_path, 'keys')

    if not os.path.exists(keys_path):
        click.echo("No keys directory found. No validators available.")
        return

    pids_to_check = {}
    info_path = os.path.join(cluster_path, 'cluster-info.txt')
    if os.path.exists(info_path):
        with open(info_path, 'r') as f:
            for line in f:
                if "_pid=" in line:
                    node_name = line.split('=')[0].replace('_pid', '').strip()
                    pid_value = line.split('=')[1].strip()
                    if pid_value == 'NA':
                        continue
                    pid = int(pid_value)
                    pids_to_check[node_name] = pid

    vote_account_to_validator = {}
    for validator_name in os.listdir(keys_path):
        id_key = os.path.join(keys_path, validator_name, 'id.json')
        vote_key = os.path.join(keys_path, validator_name, 'vote.json')
        vote_pubkey = get_pubkey(vote_key)
        vote_account_to_validator[vote_pubkey] = validator_name

    undelegated_stake_accounts = set()
    for validator_name in os.listdir(keys_path):
        id_key = os.path.join(keys_path, validator_name, 'id.json')
        vote_key = os.path.join(keys_path, validator_name, 'vote.json')
        id_pubkey = get_pubkey(id_key)
        vote_pubkey = get_pubkey(vote_key)

        running = False
        if validator_name in pids_to_check:
            try:
                os.kill(pids_to_check[validator_name], 0)
                running = True
            except (ProcessLookupError, PermissionError):
                pass

        firedancer = False
        if running == False:
            validator_line = [line for line in validators_output.splitlines() if id_pubkey in line]
            if validator_line and len(validator_line) > 0 and '⚠' not in validator_line[0]:
                firedancer = True

        status_emoji = "✅" if running else "🔥" if firedancer else "❌"

        click.echo(f"Validator: {validator_name} {status_emoji}")
        click.echo(f"  Identity Key: {id_pubkey}")
        click.echo(f"  Vote Key: {vote_pubkey}")
        click.echo(f"  Stake Info:")
        stake_accounts_path = os.path.join(cluster_path, 'stake-accounts')
        def get_stake_account_details(stake_account_pubkey):
            result = subprocess.run([solana, '-u', f'http://{ip()}:8899', 'stake-account', stake_account_pubkey], capture_output=True, text=True)
            return stake_account_pubkey, result.stdout

        stake_account_details = []
        with ThreadPoolExecutor() as executor:
            futures = {executor.submit(get_stake_account_details, get_pubkey(os.path.join(stake_accounts_path, file))): file for file in os.listdir(stake_accounts_path)}
            for future in as_completed(futures):
                stake_account_pubkey, output = future.result()
                if 'Stake account is undelegated' not in output:
                    vote_account_line = next((line for line in output.splitlines() if line.startswith('Delegated Vote Account Address:')), None)
                    if vote_account_line:
                        vote_account = vote_account_line.split(':')[1].strip()
                        if vote_account == vote_pubkey:
                            balance_line = next((line for line in output.splitlines() if line.startswith('Balance:')), None)
                            active_stake_line = next((line for line in output.splitlines() if line.startswith('Active Stake:')), None)
                            delegated_stake_line = next((line for line in output.splitlines() if line.startswith('Delegated Stake:')), None)

                            if balance_line and active_stake_line and delegated_stake_line:
                                balance = balance_line.split(':')[1].strip()
                                active_stake = active_stake_line.split(':')[1].strip()
                                delegated_stake = delegated_stake_line.split(':')[1].strip()

                                stake_account_details.append((stake_account_pubkey, balance, active_stake, delegated_stake))
                else:
                    balance_line = next((line for line in output.splitlines() if line.startswith('Balance:')), None)
                    if balance_line:
                        balance = balance_line.split(':')[1].strip()
                        undelegated_stake_accounts.add((stake_account_pubkey, balance))

        stake_account_details.sort(key=lambda x: x[0])

        for stake_account_pubkey, balance, active_stake, delegated_stake in stake_account_details:
            click.echo(f"    {stake_account_pubkey}: Balance: {balance}, Active Stake: {active_stake}, Delegated Stake: {delegated_stake}")
        click.echo("")

    for stake_account_pubkey, balance in sorted(undelegated_stake_accounts):
        click.echo(f"  Undelegated Stake Account: {stake_account_pubkey}, Balance: {balance}")



@main.command('leader-stats')
@click.pass_context
def leader_stats(ctx):
    """Show leader stats for a given identifier."""
    solana = solana_binary('solana')
    result = subprocess.run([solana, "-u", f"http://{ip()}:8899", "epoch"], capture_output=True, text=True)
    epoch = int(result.stdout)
    leader_schedule_epoch = epoch - 1
    result = subprocess.run([solana, "-u", f"http://{ip()}:8899", "leader-schedule", "--epoch", str(leader_schedule_epoch)], capture_output=True, text=True)
    leader_schedule = result.stdout

    cluster_path = str(get_env_var('AGAVE_LEDGER_PATH'))
    keys_path = os.path.join(cluster_path, 'keys')
    validator_leader_slots = {}
    for validator_name in os.listdir(keys_path):
        id_key = os.path.join(keys_path, validator_name, 'id.json')
        id_pubkey = get_pubkey(id_key)
        validator_leader_slots[id_pubkey] = set()

    for line in leader_schedule.strip().split('\n'):
        line = line.strip()
        if not line:
            continue

        parts = line.split()
        if len(parts) >= 2:
            try:
                slot = int(parts[0])
                schedule_identifier = parts[1]
                if schedule_identifier in validator_leader_slots:
                    validator_leader_slots[schedule_identifier].add(slot)
            except ValueError:
                continue

    click.echo(f"Epoch: {epoch}")
    for leader_pubkey, leader_slots in validator_leader_slots.items():
        current_txn_cnt = 0
        for slot in leader_slots:
            result = subprocess.run([solana, "-u", f"http://{ip()}:8899", "block", str(slot)], capture_output=True, text=True)
            current_txn_cnt += result.stdout.count("Transaction ")

        click.echo(f"  Leader: {leader_pubkey}")
        click.echo(f"    Number of Leader Slots: {len(leader_slots)}")
        click.echo(f"    Average Transactions per Slot: {current_txn_cnt / len(leader_slots)}")
    return


if __name__ == '__main__':
    main()
