# Agave Cluster Management Tool

A Python-based CLI tool for managing Agave clusters with a clean command interface.

## Prerequisites

- Python 3.7 or higher
- An Agave release directory

## Quick Start

1. **Activate the environment** by providing your Agave release path:
   ```bash
   cd contrib/agave-cluster
   source activate /path/to/your/agave/release
   ```

2. **Use the CLI commands**:
   ```bash
   agave-cluster --help
   agave-cluster start-cluster
   agave-cluster status
   ```

3. **Deactivate when done**:
   ```bash
   deactivate_agave_cluster
   ```

## Environment Setup

The `activate` script creates a Python virtual environment and sets up the necessary environment variables:

- **AGAVE_RELEASE_PATH**: Points to your Agave release directory
- **AGAVE_CLUSTER_ACTIVE**: Indicates the environment is active
- **Virtual Environment**: Isolated Python environment with required dependencies

### Activation
```bash
source activate <AGAVE_RELEASE_PATH>
```

The activation script will:
- Create a Python virtual environment (`.venv/`) if it doesn't exist
- Install the `agave-cluster` package in development mode
- Set the `AGAVE_RELEASE_PATH` environment variable
- Add `(agave-cluster)` prefix to your shell prompt
- Make all `agave-cluster` commands available

### Deactivation
```bash
deactivate_agave_cluster
```

## Available Commands

All commands are prefixed with `agave-cluster`:

### Cluster Management
```bash
# Start a cluster
agave-cluster start-cluster [OPTIONS]
  --bootstrap-validator-name, -n    Bootstrap validator name (default: node-ledger-0)

# Stop a cluster
agave-cluster stop-cluster [OPTIONS]
  --force, -f        Force stop the cluster

# Get cluster status
agave-cluster status [OPTIONS]
  --json            Output status in JSON format

# Get cluster version
agave-cluster cluster-version
```

### Node Management
```bash
# Add a new validator node
agave-cluster add-node [OPTIONS]
  --validator-name, -n    Name of the node to add

# Stop a node by name or identity key
agave-cluster stop-node IDENTIFIER [OPTIONS]
  --force, -f      Force stop the node

# Create unstaked validator keys
agave-cluster create-unstaked-keys [OPTIONS]
  --validator-name, -n    Name of the node

# Create staked validator keys
agave-cluster create-staked-keys [OPTIONS]
  --validator-name, -n    Name of the node
  --sol                   Amount of SOL to stake
  --percentage            Percentage of network stake
```

### Stake Management
```bash
# Delegate stake to a vote account
agave-cluster delegate-stake VOTE_KEY AMOUNT

# Deactivate a stake account
agave-cluster deactivate-stake STAKE_KEY
```

### Monitoring
```bash
# View cluster logs
agave-cluster logs [OPTIONS]
  --node-id        Show logs for specific node
  --follow, -f     Follow log output
  --lines, -n      Number of lines to show (default: 100)

# Show validators and their keys
agave-cluster validators

# Show leader statistics
agave-cluster leader-stats
```

### Version Management
```bash
# Set cluster version by checking out git tag and building
agave-cluster set-cluster-version VERSION [OPTIONS]
  --force, -f      Force checkout even with uncommitted changes
```

### Global Options
```bash
--verbose, -v       Enable verbose output
--version          Show version information
--help             Show help message
```

## Examples

### Basic Cluster Operations
```bash
# Activate environment
source activate /home/user/agave-releases/v2.1.0

# Start a basic cluster
agave-cluster start-cluster

# Check status
agave-cluster status

# View validators
agave-cluster validators

# Add a validator node
agave-cluster add-node --validator-name my-validator

# View logs
agave-cluster logs --follow

# Stop the cluster
agave-cluster stop-cluster
```

### Advanced Usage
```bash
# Set cluster to specific Agave version (checks out git tag v2.3.0 and builds)
agave-cluster set-cluster-version 2.3.0

# Start cluster with custom bootstrap validator name
agave-cluster start-cluster --bootstrap-validator-name custom-bootstrap

# Create staked validator keys (10% of network)
agave-cluster create-staked-keys --validator-name my-staked-validator --percentage 10

# Create staked validator keys (specific SOL amount)
agave-cluster create-staked-keys --validator-name my-staked-validator --sol 1000000

# Delegate stake to a vote account
agave-cluster delegate-stake <VOTE_PUBKEY> 500000

# Get status in JSON format
agave-cluster status --json

# Stop a specific node by name (force)
agave-cluster stop-node my-validator --force

# View leader statistics
agave-cluster leader-stats
```

## Development

### Project Structure
```
agave-cluster/
├── agave_cluster/          # Python package
│   ├── __init__.py
│   └── cli.py             # Main CLI implementation
├── activate               # Environment activation script
├── setup.py              # Package configuration
├── requirements.txt       # Dependencies
└── README.md             # This file
```

### Adding New Commands

To add new commands, edit `agave_cluster/cli.py`:

1. Create a new command function with the `@main.command()` decorator
2. Add appropriate Click options and arguments
3. Implement the command logic
4. Access `AGAVE_RELEASE_PATH` via `ctx.obj['agave_release_path']`

### Dependencies

Core dependencies:
- **click**: Command line interface framework
- **pyyaml**: YAML configuration parsing
- **requests**: HTTP client for API calls

Optional dependencies:
- **colorama**: Cross-platform colored terminal output
- **psutil**: System and process monitoring
- **tabulate**: Pretty-print tabular data

## Environment Variables

- **AGAVE_RELEASE_PATH**: Path to Agave release directory (set by activation)
- **AGAVE_CLUSTER_ACTIVE**: Flag indicating active environment
- **VIRTUAL_ENV**: Python virtual environment path

## Troubleshooting

### Environment Not Activating
- Ensure you're using `source activate` not just `activate`
- Check that the provided Agave release path exists
- Verify Python 3.7+ is available

### Commands Not Found
- Make sure the environment is activated (check for `(agave-cluster)` in prompt)
- Try reinstalling: `pip install -e .` from the agave-cluster directory
- Deactivate and reactivate the environment

### Permission Issues
- Ensure the `activate` script is executable: `chmod +x activate`
- Check write permissions in the agave-cluster directory for the `.venv` folder
