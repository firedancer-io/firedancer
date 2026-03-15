# Glossary of Firedancer Terminology

This glossary provides definitions for the common acronyms, abbreviations, and internal module names used throughout the Firedancer codebase.

## Internal Modules & Tile Names

- **Firedancer**: A new validator client for Solana, written from scratch in C/C++.
- **Frankendancer**: A hybrid validator using parts of Firedancer (networking and block production) and parts of Agave (execution and consensus).
- **Ballet**: Standalone implementations of various standards needed for interoperability with the Solana ecosystem (e.g., hash functions, cryptographic algorithms like SHA256, Ed25519).
- **Choreo**: Consensus components (fork choice, voting).
- **Disco**: Common tiles (network stack, block production).
- **Discof**: Full Firedancer tiles (consensus, runtime, RPC).
- **Discoh**: Frankendancer tiles (Agave FFI).
- **Flamenco**: Solana SVM (Smart Contract Virtual Machine) and runtime implementation.
- **Funk**: Fork-aware in-memory key-value store used for the accounts DB and program cache.
- **Groove**: Disk-backed memory-mapped key-value cold store for the accounts DB.
- **Tango**: IPC (Inter-Process Communication) messaging layer used for communication between tiles.
- **Waltz**: Networking layer implementation (e.g., QUIC, HTTP, IP, XDP).
- **Wiredancer**: FPGA (Field Programmable Gate Array) modules for hardware acceleration.
- **Util**: C language environment abstractions, system runtime macros, common data structures, and various utilities (math, bits, rng, SIMD).

## Core Concepts & Acronyms

- **Tile**: A single logical unit of execution within the Firedancer architecture, typically running pinned to a specific CPU core to maximize cache locality and performance.
- **Workspace (wksp)**: Memory region used by Firedancer for fast allocation and data sharing.
- **FCTL**: Firedancer Control - typically associated with command and control or configuration tools.
- **CNC**: Command and Control - the interface/structures used to monitor, command, and inspect individual tiles.
- **MCACHE**: Message Cache - A core Tango construct for high-speed publish-subscribe IPC.
- **DCACHE**: Data Cache - Associated with MCACHE, stores the actual payload data of the IPC messages.
- **FSEQ**: Fast Sequence - Used for sequence number tracking in Tango's IPC.
- **XSK**: AF_XDP Socket - Linux facility for high-performance packet processing, bypassing the normal network stack.
- **XDP**: eXpress Data Path - eBPF-based high-performance data path used to process packets at the lowest level of the Linux networking stack.
- **eBPF (or sBPF)**: Solana uses a modified version of eBPF (extended Berkeley Packet Filter) as its smart contract VM instruction set (referred to in Firedancer as sBPF).
- **TPU**: Transaction Processing Unit - The part of the network stack that handles incoming transactions.
- **TVU**: Transaction Validation Unit - The part of the network stack that handles blockchain state validation.
