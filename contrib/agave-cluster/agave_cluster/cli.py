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
    # get "ip -o -4 addr show scope global | awk '{ print $4 }' | cut -d/ -f1 | head -n 1"
    ip = subprocess.check_output(
        "ip -o -4 addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -n1",
        shell=True, text=True
    ).strip()
    return ip



def get_agave_release_path():
    """Get the AGAVE_RELEASE_PATH environment variable."""
    agave_path = os.environ.get('AGAVE_RELEASE_PATH')
    if not agave_path:
        click.echo("Error: AGAVE_RELEASE_PATH environment variable is not set.", err=True)
        click.echo("Please activate the agave-cluster environment with: source activate <AGAVE_RELEASE_PATH>", err=True)
        sys.exit(1)
    return Path(agave_path)

def get_ledger_directory():
    """Get the ledger directory from environment variable or config file."""
    # Try environment variable first
    ledger_path = os.environ.get('AGAVE_LEDGER_PATH')

    # If not in environment, try config file
    if not ledger_path:
        config_file = Path(__file__).parent.parent / '.ledger_config'
        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    ledger_path = f.read().strip()
            except Exception:
                pass

    if not ledger_path:
        click.echo("Error: Ledger directory is not configured.", err=True)
        click.echo("Please set the ledger directory with: agave-cluster set-ledger-dir <LEDGER_PATH>", err=True)
        sys.exit(1)
    return Path(ledger_path)

def validate_ledger_directory():
    """Validate that the ledger directory exists."""
    ledger_path = get_ledger_directory()
    if not ledger_path.exists():
        click.echo(f"Error: Ledger directory {ledger_path} does not exist.", err=True)
        click.echo(f"Please create the directory or set a different path with: agave-cluster set-ledger-dir <LEDGER_PATH>", err=True)
        sys.exit(1)
    return ledger_path

def solana_binary(name):
    return str(get_agave_release_path() / "target" / "release" / name)

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
    cluster_path = str(get_ledger_directory())
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
    # Don't validate AGAVE_RELEASE_PATH here - let individual commands handle it
    # This allows setup commands like set-ledger-dir to work without AGAVE_RELEASE_PATH being set


@main.command('start-cluster')
@click.option('--config', '-c', help='Configuration file path')
@click.option('--bootstrap-validator-name', '-n', type=str, required=False, default='node-ledger-0', help='Bootstrap validator name')
@click.pass_context
def start_cluster(ctx, config, bootstrap_validator_name):
    """Start an Agave cluster."""
    agave_path = get_agave_release_path()
    verbose = ctx.obj['verbose']

    # Validate ledger directory exists and get the path
    cluster_path = str(validate_ledger_directory())

    if verbose:
        click.echo(f"Starting cluster with Agave release at: {agave_path}")
        click.echo(f"Configuration: {config}")
        click.echo(f"Cluster Path: {cluster_path}")

    # Implementation will be added here
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

    genesis_output = subprocess.run([solana_genesis, "--cluster-type", "mainnet-beta", "--ledger", node_path, "--bootstrap-validator", id_key, vote_key, stake_key, "--bootstrap-stake-authorized-pubkey", id_key, "--bootstrap-validator-lamports", "10000000000", "--bootstrap-validator-stake-lamports", "18000000000", "--faucet-pubkey", faucet_key, "--faucet-lamports", "5000000000000000", "--slots-per-epoch", "256"], cwd=cluster_path, capture_output=True, text=True)
    genesis_hash, shred_version = parse_genesis_output(genesis_output.stdout)

    info_path = os.path.join(cluster_path, 'cluster-info.txt')
    with open(info_path, 'a') as f:
        f.write(f"genesis_hash={genesis_hash}\n")
        f.write(f"shred_version={shred_version}\n")

    agave_validator = solana_binary('agave-validator')

    validator_process = subprocess.Popen([agave_validator, "--rpc-bind-address", f"{ip()}", "--allow-private-addr", "--enable-rpc-transaction-history", "--identity", id_key, "--ledger", node_path, "--limit-ledger-size", "100000000", "--dynamic-port-range", "8000-8099", "--no-snapshot-fetch", "--no-poh-speed-test", "--no-os-network-limits-test", "--vote-account", vote_key, "--expected-shred-version", shred_version, "--expected-genesis-hash", genesis_hash, "--no-wait-for-vote-to-start-leader", "--no-incremental-snapshots", "--snapshot-interval-slots", "50", "--maximum-full-snapshots-to-retain", "10", "--rpc-port", "8899", "--gossip-port", "8010", "--full-rpc-api", "--bind-address", ip(), "--tpu-enable-udp", "--log", f"{node_path}/validator.log"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setpgrp)

    validator_pid = validator_process.pid
    click.echo(f"Validator {bootstrap_validator_name} has started with pid {validator_pid}")

    # write validator pid to cluster-info.txt
    with open(info_path, 'a') as f:
        f.write(f"{bootstrap_validator_name}_pid={validator_pid}\n")

    time.sleep(1)
    click.echo(f"✅ Cluster started successfully at: {cluster_path}")
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
            agave_path = get_agave_release_path()
            click.echo(f"Stopping cluster with Agave release at: {agave_path}")
        except SystemExit:
            pass  # AGAVE_RELEASE_PATH not needed for stop operation
        click.echo(f"Force stop: {force}")

    click.echo("🛑 Stopping Agave cluster...")

    try:
        cluster_path = str(get_ledger_directory())
        info_path = os.path.join(cluster_path, 'cluster-info.txt')

        if not os.path.exists(info_path):
            click.echo("No cluster info file found. Cluster may not be running.")
            return

        # Read all PIDs from cluster-info.txt
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

        # Stop all processes
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
        click.echo("Error: AGAVE_LEDGER_PATH not set or directory not found.", err=True)
        click.echo("Use 'agave-cluster set-ledger-dir <path>' to set the ledger directory.", err=True)


@main.command('add-node')
@click.option('--validator-name', '-n', type=str, help='Name of the node to add')
@click.pass_context
def add_node(ctx, validator_name):
    """Add a new node to the cluster."""

    cluster_path = str(get_ledger_directory())
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

    # Send some SOL to the identity account for transaction fees
    subprocess.run([solana, "-u", f"http://{ip()}:8899", "transfer", "-k", faucet_key, "--allow-unfunded-recipient", id_key, "100"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Create vote account for the new validator
    subprocess.run([solana, "-u", f"http://{ip()}:8899", "create-vote-account", "-k", id_key, "--allow-unsafe-authorized-withdrawer", vote_key, id_key, id_key], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Create and delegate stake account
    subprocess.run([solana, "-u", f"http://{ip()}:8899", "create-stake-account", "-k", faucet_key, "--stake-authority", authority_key, "--withdraw-authority", faucet_key, stake_key, "1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run([solana, "-u", f"http://{ip()}:8899", "delegate-stake", "-k", faucet_key, "--stake-authority", authority_key, stake_key, vote_key], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Get the vote account public key
    vote_pubkey = get_pubkey(vote_key)

    validator_process = subprocess.Popen([agave_validator, "--allow-private-addr", "--identity", id_key, "--ledger", node_path, "--limit-ledger-size", "100000000", "--dynamic-port-range", f"8{current_node_count}00-8{current_node_count}99", "--no-poh-speed-test", "--no-os-network-limits-test", "--vote-account", vote_pubkey, "--entrypoint", f"{ip()}:8010", "--gossip-port", f"8{current_node_count}10", "--expected-shred-version", shred_version, "--expected-genesis-hash", genesis_hash, "--tpu-disable-quic", "--tpu-enable-udp", "--log", f"{node_path}/validator.log"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setpgrp)

    validator_pid = validator_process.pid
    click.echo(f"Validator {validator_name} has started with pid {validator_pid}")

    with open(info_path, 'a') as f:
        f.write(f"{validator_name}_pid={validator_pid}\n")

    # Give the validator some time to initialize
    click.echo("Giving validator time to initialize...")
    time.sleep(1)
    click.echo(f"✅ Node {validator_name} added successfully!")
    click.echo(f"Node path: {node_path}")
    click.echo(f"Log file: {node_path}/validator.log")


@main.command('create-unstaked-keys')
@click.option('--validator-name', '-n', type=str, help='Name of the node to add')
@click.pass_context
def create_unstaked_keys(ctx, validator_name):
    import pdb; pdb.set_trace()
    """Create Unstaked keys."""
    cluster_path = str(get_ledger_directory())
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

    # Send some SOL to the identity account for transaction fees
    subprocess.run([solana, "-u", f"http://{ip()}:8899", "transfer", "-k", faucet_key, "--allow-unfunded-recipient", id_key, "100"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Create vote account for the new validator
    subprocess.run([solana, "-u", f"http://{ip()}:8899", "create-vote-account", "-k", id_key, "--allow-unsafe-authorized-withdrawer", vote_key, id_key, id_key], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    click.echo(f"Keys for validator {validator_name} created successfully!")
    # cat the id_key
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
    cluster_path = str(get_ledger_directory())
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

    # Send some SOL to the identity account for transaction fees
    subprocess.run([solana, "-u", f"http://{ip()}:8899", "transfer", "-k", faucet_key, "--allow-unfunded-recipient", id_key, "100"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Create vote account for the new validator
    subprocess.run([solana, "-u", f"http://{ip()}:8899", "create-vote-account", "-k", id_key, "--allow-unsafe-authorized-withdrawer", vote_key, id_key, id_key], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    click.echo(f"Keys for validator {validator_name} created successfully!")
    # cat the id_key
    click.echo(f"Identity key content:")
    click.echo(f"Identity key at: {id_key} with content: {open(id_key, 'r').read()}")
    click.echo(f"Vote key at: {vote_key} with content: {open(vote_key, 'r').read()}")

    with open(info_path, 'a') as f:
        f.write(f"{validator_name}_pid=NA\n")

    if (not sol and not percentage) or (sol and percentage):
        click.echo("Error: Either --sol or --percentage must be provided")
        return

    # Execute solana command to get stake history

    if percentage:
        stake_history_output = subprocess.run([solana_binary('solana'), '-u', f'http://{ip()}:8899', 'stake-history'], capture_output=True, text=True).stdout
        # Parse the first entry in the stake history table
        first_entry = stake_history_output.splitlines()[3]  # Assuming the first entry is on the fourth line
        epoch, effective_stake, activating_stake, deactivating_stake, _ = first_entry.split()
        # Print the stake information
        total_stake = float(effective_stake) + float(activating_stake) - float(deactivating_stake)

        staked_sol_amount = int(total_stake / (1 - float(percentage)/100.0) * float(percentage)/100.0)
    else:
        staked_sol_amount = int(sol)

    stake_accounts_path = os.path.join(cluster_path, 'stake-accounts')
    stake_accounts_count = len(os.listdir(stake_accounts_path))

    stake_key = os.path.join(stake_accounts_path, f"stake-account-{stake_accounts_count}.json")
    create_key(stake_key)

    faucet_key = os.path.join(cluster_path, 'faucet.json')
    authority_key = os.path.join(cluster_path, 'authority.json')

    solana = solana_binary('solana')

    subprocess.run([solana, "-u", f"http://{ip()}:8899", "create-stake-account", "-k", faucet_key, "--stake-authority", authority_key, "--withdraw-authority", faucet_key, stake_key, f"{staked_sol_amount}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run([solana, "-u", f"http://{ip()}:8899", "delegate-stake", "-k", faucet_key, "--stake-authority", authority_key, stake_key, vote_key])


@main.command('stake-node')
@click.argument('vote-key', type=str)
@click.argument('amount', type=int)
@click.pass_context
def stake_node(ctx, vote_key, amount):
    """Stake a node."""
    cluster_path = str(get_ledger_directory())
    info_path = os.path.join(cluster_path, 'cluster-info.txt')

    # TODO: Allow identitier to be a node name or identity key, for now we only support key
    stake_accounts_path = os.path.join(cluster_path, 'stake-accounts')
    # check how many stake accounts are in the stake-accounts directory
    stake_accounts_count = len(os.listdir(stake_accounts_path))

    stake_key = os.path.join(stake_accounts_path, f"stake-account-{stake_accounts_count}.json")
    create_key(stake_key)

    faucet_key = os.path.join(cluster_path, 'faucet.json')
    authority_key = os.path.join(cluster_path, 'authority.json')

    solana = solana_binary('solana')

    subprocess.run([solana, "-u", f"http://{ip()}:8899", "create-stake-account", "-k", faucet_key, "--stake-authority", authority_key, "--withdraw-authority", faucet_key, stake_key, f"{amount}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run([solana, "-u", f"http://{ip()}:8899", "delegate-stake", "-k", faucet_key, "--stake-authority", authority_key, stake_key, vote_key])


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
        cluster_path = str(get_ledger_directory())
        info_path = os.path.join(cluster_path, 'cluster-info.txt')

        if not os.path.exists(info_path):
            click.echo("No cluster info file found. Cluster may not be running.")
            return

        # Read all PIDs and keys from cluster-info.txt
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

        # Check if identifier is a node name or identity key
        if identifier in pids_to_stop:
            pid = pids_to_stop[identifier]
        else:
            # Try to find the node by identity key
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

        # Stop the process
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
        click.echo("Error: AGAVE_LEDGER_PATH not set or directory not found.", err=True)
        click.echo("Use 'agave-cluster set-ledger-dir <path>' to set the ledger directory.", err=True)


@main.command('status')
@click.option('--json', 'output_json', is_flag=True, help='Output status in JSON format')
@click.pass_context
def cluster_status(ctx, output_json):
    """Get cluster status."""
    verbose = ctx.obj['verbose']

    if verbose:
        try:
            agave_path = get_agave_release_path()
            click.echo(f"Getting cluster status with Agave release at: {agave_path}")
        except SystemExit:
            pass  # AGAVE_RELEASE_PATH not needed for status check

    try:
        cluster_path = str(get_ledger_directory())
        info_path = os.path.join(cluster_path, 'cluster-info.txt')

        if not os.path.exists(info_path):
            if output_json:
                click.echo('{"status": "stopped", "nodes": 0, "validators": 0}')
            else:
                click.echo("📊 Cluster Status:")
                click.echo("  Status: Stopped")
                click.echo("  Cluster info file not found")
            return

        # Count running processes
        running_processes = 0
        genesis_hash = None
        shred_version = None

        with open(info_path, 'r') as f:
            for line in f:
                if line.strip().endswith('_pid'):
                    pid = int(line.split('=')[1].strip())
                    try:
                        os.kill(pid, 0)  # Check if process is running
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
                "validators": running_processes,  # Assuming all nodes are validators for now
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
            click.echo(f"  Running Processes: {running_processes}")
            click.echo(f"  Ledger Path: {cluster_path}")
            if genesis_hash:
                click.echo(f"  Genesis Hash: {genesis_hash}")
            if shred_version:
                click.echo(f"  Shred Version: {shred_version}")

    except FileNotFoundError:
        if output_json:
            click.echo('{"error": "AGAVE_LEDGER_PATH not set or directory not found"}')
        else:
            click.echo("Error: AGAVE_LEDGER_PATH not set or directory not found.", err=True)
            click.echo("Use 'agave-cluster set-ledger-dir <path>' to set the ledger directory.", err=True)


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
            agave_path = get_agave_release_path()
            click.echo(f"Showing logs with Agave release at: {agave_path}")
        except SystemExit:
            pass  # AGAVE_RELEASE_PATH not needed for log viewing
        click.echo(f"Node ID: {node_id}")
        click.echo(f"Follow: {follow}")
        click.echo(f"Lines: {lines}")

    try:
        cluster_path = str(get_ledger_directory())

        # If no specific node-id is provided, default to the bootstrap validator
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
            # Use tail -f to follow the log
            try:
                subprocess.run(['tail', '-f', '-n', str(lines), log_file])
            except KeyboardInterrupt:
                click.echo("\nStopped following logs.")
            except FileNotFoundError:
                click.echo("Error: 'tail' command not found.")
        else:
            # Show the last N lines
            try:
                result = subprocess.run(['tail', '-n', str(lines), log_file],
                                      capture_output=True, text=True)
                if result.stdout:
                    click.echo(result.stdout)
                else:
                    click.echo("No logs found or log file is empty.")
            except FileNotFoundError:
                # Fallback to Python implementation
                try:
                    with open(log_file, 'r') as f:
                        log_lines = f.readlines()
                        for line in log_lines[-lines:]:
                            click.echo(line.rstrip())
                except Exception as e:
                    click.echo(f"Error reading log file: {e}")

    except FileNotFoundError:
        click.echo("Error: AGAVE_LEDGER_PATH not set or directory not found.", err=True)
        click.echo("Use 'agave-cluster set-ledger-dir <path>' to set the ledger directory.", err=True)


@main.command('set-cluster-version')
@click.argument('version', type=str)
@click.option('--force', '-f', is_flag=True, help='Force checkout even with uncommitted changes')
@click.pass_context
def set_cluster_version(ctx, version, force):
    """Set the cluster version by checking out a git tag and building."""
    agave_path = get_agave_release_path()
    verbose = ctx.obj['verbose']

    if verbose:
        click.echo(f"Setting cluster version to {version} at: {agave_path}")
        click.echo(f"Force checkout: {force}")

    # Validate that the AGAVE_RELEASE_PATH is a git repository
    git_dir = agave_path / '.git'
    if not git_dir.exists():
        click.echo(f"Error: {agave_path} is not a git repository", err=True)
        sys.exit(1)

    # Construct the tag name (prepend 'v' to the version)
    tag_name = f"v{version}"

    try:
        # Change to the AGAVE_RELEASE_PATH directory
        original_dir = os.getcwd()
        os.chdir(agave_path)

        click.echo(f"🔄 Checking out tag {tag_name}...")

        # Run git checkout with the tag
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

        # Run cargo build --release
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
    agave_path = get_agave_release_path()

    try:
        # Change to the AGAVE_RELEASE_PATH directory
        original_dir = os.getcwd()
        os.chdir(agave_path)
        # Run git checkout with the tag
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

@main.command('set-ledger-dir')
@click.argument('ledger_path', type=str, required=False)
@click.pass_context
def set_ledger_directory(ctx, ledger_path):
    """Set or show the ledger directory path."""
    verbose = ctx.obj['verbose']

    # If no path provided, show current configuration
    if not ledger_path:
        try:
            current_path = get_ledger_directory()
            click.echo(f"📁 Current ledger directory: {current_path}")
            if current_path.exists():
                click.echo(f"   Status: ✅ Directory exists")
            else:
                click.echo(f"   Status: ❌ Directory does not exist")
            return
        except SystemExit:
            click.echo("📁 No ledger directory configured.")
            click.echo("   Use: agave-cluster set-ledger-dir <path>")
            return

    # Convert to absolute path
    ledger_path = os.path.abspath(ledger_path)

    if verbose:
        click.echo(f"Setting ledger directory to: {ledger_path}")

    # Create directory if it doesn't exist
    os.makedirs(ledger_path, exist_ok=True)

    # Write to config file
    config_file = Path(__file__).parent.parent / '.ledger_config'

    try:
        with open(config_file, 'w') as f:
            f.write(ledger_path)

        click.echo(f"✅ Ledger directory set to: {ledger_path}")

    except Exception as e:
        click.echo(f"Error saving ledger directory config: {e}", err=True)
        sys.exit(1)

    os.environ['AGAVE_LEDGER_PATH'] = ledger_path

@main.command('validators')
@click.pass_context
def validators(ctx):
    """Show validators and their keys."""
    verbose = ctx.obj['verbose']

    if verbose:
        try:
            agave_path = get_agave_release_path()
            click.echo(f"Showing validators with Agave release at: {agave_path}")
        except SystemExit:
            pass  # AGAVE_RELEASE_PATH not needed for showing validators

    solana = solana_binary('solana')

    # Function to execute solana command
    def execute_solana_command(command):
        return subprocess.run(command, capture_output=True, text=True).stdout

    # Use ThreadPoolExecutor to parallelize independent solana command executions
    with ThreadPoolExecutor() as executor:
        # Define solana commands
        solana_commands = [
            [solana, "epoch-info", "-u", f"http://{ip()}:8899"],
            [solana, "validators", "-u", f"http://{ip()}:8899", "--keep-unstaked-delinquents"]
        ]
        # Submit solana commands to executor
        futures = {executor.submit(execute_solana_command, command): command for command in solana_commands}
        results = {}
        for future in as_completed(futures):
            command = futures[future]
            results[tuple(command)] = future.result()

    # Process results
    epoch_in_output = results[tuple(solana_commands[0])]
    validators_output = results[tuple(solana_commands[1])]

    click.echo(epoch_in_output)
    click.echo(validators_output)

    cluster_path = str(get_ledger_directory())
    keys_path = os.path.join(cluster_path, 'keys')

    if not os.path.exists(keys_path):
        click.echo("No keys directory found. No validators available.")
        return

    # Read all PIDs from cluster-info.txt
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

    # Create a mapping of vote accounts to validators
    vote_account_to_validator = {}
    for validator_name in os.listdir(keys_path):
        id_key = os.path.join(keys_path, validator_name, 'id.json')
        vote_key = os.path.join(keys_path, validator_name, 'vote.json')
        vote_pubkey = get_pubkey(vote_key)
        vote_account_to_validator[vote_pubkey] = validator_name

    # Iterate over validators and print their information along with associated stake accounts
    for validator_name in os.listdir(keys_path):
        id_key = os.path.join(keys_path, validator_name, 'id.json')
        vote_key = os.path.join(keys_path, validator_name, 'vote.json')
        id_pubkey = get_pubkey(id_key)
        vote_pubkey = get_pubkey(vote_key)

        # Check if the validator is running
        running = False
        if validator_name in pids_to_check:
            try:
                os.kill(pids_to_check[validator_name], 0)  # Check if process is running
                running = True
            except (ProcessLookupError, PermissionError):
                pass

        firedancer = False
        if running == False:
            # Check if any row in validators_output does not contain the ⚠️ symbol
            validator_line = [line for line in validators_output.splitlines() if id_pubkey in line]
            if '⚠' != validator_line[0][0]:
                firedancer = True

        status_emoji = "✅" if running else "🔥" if firedancer else "❌"

        click.echo(f"Validator: {validator_name} {status_emoji}")
        click.echo(f"  Identity Key: {id_pubkey}")
        click.echo(f"  Vote Key: {vote_pubkey}")
        click.echo(f"  Stake Info:")
        # Print associated stake accounts
        stake_accounts_path = os.path.join(cluster_path, 'stake-accounts')
        # Function to get stake account details
        def get_stake_account_details(stake_account_pubkey):
            result = subprocess.run([solana, '-u', f'http://{ip()}:8899', 'stake-account', stake_account_pubkey], capture_output=True, text=True)
            return stake_account_pubkey, result.stdout

        # Collect stake account details
        stake_account_details = []
        with ThreadPoolExecutor() as executor:
            futures = {executor.submit(get_stake_account_details, get_pubkey(os.path.join(stake_accounts_path, file))): file for file in os.listdir(stake_accounts_path)}
            for future in as_completed(futures):
                stake_account_pubkey, output = future.result()
                # Parse the output
                if 'Stake account is undelegated' not in output:
                    vote_account_line = next(line for line in output.splitlines() if line.startswith('Delegated Vote Account Address:'))
                    vote_account = vote_account_line.split(':')[1].strip()
                    if vote_account == vote_pubkey:
                        balance_line = next(line for line in output.splitlines() if line.startswith('Balance:'))
                        active_stake_line = next(line for line in output.splitlines() if line.startswith('Active Stake:'))
                        delegated_stake_line = next(line for line in output.splitlines() if line.startswith('Delegated Stake:'))
                        balance = balance_line.split(':')[1].strip()
                        active_stake = active_stake_line.split(':')[1].strip()
                        delegated_stake = delegated_stake_line.split(':')[1].strip()

                        stake_account_details.append((stake_account_pubkey, balance, active_stake, delegated_stake))

        # Sort stake accounts by pubkey
        stake_account_details.sort(key=lambda x: x[0])

        # Print sorted stake account details
        for stake_account_pubkey, balance, active_stake, delegated_stake in stake_account_details:
            click.echo(f"    {stake_account_pubkey}: Balance: {balance}, Active Stake: {active_stake}, Delegated Stake: {delegated_stake}")
        click.echo("")


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

    # collect leader pubkeys
    cluster_path = str(get_ledger_directory())
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
                # Skip lines that don't have valid slot numbers
                continue

    click.echo(f"Epoch: {epoch}")
    for leader_pubkey, leader_slots in validator_leader_slots.items():
        current_txn_cnt = 0
        for slot in leader_slots:
            result = subprocess.run([solana, "-u", f"http://{ip()}:8899", "block", str(slot)], capture_output=True, text=True)
            # count number of "Transaction " in result.stdout
            current_txn_cnt += result.stdout.count("Transaction ")

        click.echo(f"  Leader: {leader_pubkey}")
        click.echo(f"    Number of Leader Slots: {len(leader_slots)}")
        click.echo(f"    Average Transactions per Slot: {current_txn_cnt / len(leader_slots)}")
    return


if __name__ == '__main__':
    main()
