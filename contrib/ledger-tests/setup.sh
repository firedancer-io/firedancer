#!/bin/bash

setup_firedancer_repo="$REPO_ROOT/firedancer"
setup_solana_repo="$REPO_ROOT/solana"
setup_agave_repo="$REPO_ROOT/solfuzz-agave"
setup_solana_conformance_repo="$REPO_ROOT/solana-conformance"

setup_firedancer_branch="main"
setup_solana_branch="master-tools"
setup_agave_branch="agave-v2.0"
setup_solana_conformance_branch="main"

update_firedancer() {    
    cd $setup_firedancer_repo
    git checkout $setup_firedancer_branch
    git pull
    PATH=/opt/rh/gcc-toolset-12/root/usr/bin:$PATH
    export PATH
    PKG_CONFIG_PATH=/usr/lib64/pkgconfig:$PKG_CONFIG_PATH
    echo "y" | ./deps.sh +dev
    make -j
}

update_solana() {
    cd $setup_solana_repo
    git checkout $setup_solana_branch
    git pull
    cargo build --package solana-ledger-tool --release
}

update_solfuzz_agave() {
    cd $setup_agave_repo
    git checkout $setup_agave_branch
    git pull
    cargo build --lib    
}

update_solana_conformance() {
    cd $setup_solana_conformance_repo
    git checkout $setup_solana_conformance_branch
    git pull
    source install.sh
}

# Setup firedancer
if [ ! -d "$setup_firedancer_repo" ]; then
    git clone https://github.com/firedancer-io/firedancer.git $REPO_ROOT/firedancer
fi
update_firedancer

# Setup solana (master-tools)
if [ ! -d "$setup_solana_repo" ]; then
    git clone https://github.com/firedancer-io/solana $REPO_ROOT/solana
fi
update_solana

# Setup agave
if [ ! -d "$setup_agave_repo" ]; then
    git clone https://github.com/firedancer-io/solfuzz-agave.git $REPO_ROOT/solfuzz-agave
fi
update_solfuzz_agave        

# Setup solana conformance 
if [ ! -d "$setp_solana_conformance_repo" ]; then
    git clone https://github.com/firedancer-io/solana-conformance.git $REPO_ROOT/solana-conformance
fi 
update_solana_conformance