#!/bin/bash
set -e

OBJDIR=${OBJDIR:-build/native/gcc}

$OBJDIR/bin/firedancer-dev backtest mainnet-308392063-v3.0.0
$OBJDIR/bin/firedancer-dev backtest mainnet-308392063-v3.0.0-vinyl
$OBJDIR/bin/firedancer-dev backtest devnet-350814254-v3.0.0
$OBJDIR/bin/firedancer-dev backtest devnet-350814254-v3.0.0-vinyl
$OBJDIR/bin/firedancer-dev backtest testnet-281546597-v3.0.0
$OBJDIR/bin/firedancer-dev backtest testnet-281546597-v3.0.0-vinyl
$OBJDIR/bin/firedancer-dev backtest mainnet-324823213-v3.0.0
$OBJDIR/bin/firedancer-dev backtest mainnet-325467935-v3.0.0
$OBJDIR/bin/firedancer-dev backtest testnet-283927487-v3.0.0
$OBJDIR/bin/firedancer-dev backtest testnet-281688085-v3.0.0
$OBJDIR/bin/firedancer-dev backtest testnet-321168308-v3.0.0
$OBJDIR/bin/firedancer-dev backtest mainnet-327324660-v3.0.0
$OBJDIR/bin/firedancer-dev backtest devnet-370199634-v3.0.0
$OBJDIR/bin/firedancer-dev backtest devnet-378683870-v3.0.0
$OBJDIR/bin/firedancer-dev backtest mainnet-330219081-v3.0.0
$OBJDIR/bin/firedancer-dev backtest devnet-372721907-v3.0.0
$OBJDIR/bin/firedancer-dev backtest mainnet-331691646-v3.0.0
$OBJDIR/bin/firedancer-dev backtest testnet-336218682-v3.0.0
$OBJDIR/bin/firedancer-dev backtest testnet-340269866-v3.0.0
$OBJDIR/bin/firedancer-dev backtest devnet-390056400-v3.0.0
$OBJDIR/bin/firedancer-dev backtest mainnet-254462437-v3.0.0
$OBJDIR/bin/firedancer-dev backtest multi-epoch-per-200-v3.0.0
$OBJDIR/bin/firedancer-dev backtest testnet-346556000
$OBJDIR/bin/firedancer-dev backtest multi-bpf-loader-v3.0.0
$OBJDIR/bin/firedancer-dev backtest devnet-380592002-v3.0.0
$OBJDIR/bin/firedancer-dev backtest local-multi-boundary
$OBJDIR/bin/firedancer-dev backtest genesis-v3.0
$OBJDIR/bin/firedancer-dev backtest localnet-stake-v3.0.0
$OBJDIR/bin/firedancer-dev backtest mainnet-378539412
$OBJDIR/bin/firedancer-dev backtest devnet-422969842
$OBJDIR/bin/firedancer-dev backtest breakpoint-385786458
$OBJDIR/bin/firedancer-dev backtest breakpoint-385786458-vinyl
$OBJDIR/bin/firedancer-dev backtest vote-states-v4-local
$OBJDIR/bin/firedancer-dev backtest testnet-384169347
$OBJDIR/bin/firedancer-dev backtest testnet-384395810
$OBJDIR/bin/firedancer-dev backtest testnet-386300256
