
//use solana_sdk::stake_history::{StakeHistoryEntry, StakeHistory};

//use solana_runtime::epoch_stakes::EpochStakes;
//use solana_runtime::stakes::*;
use solana_runtime::serde_snapshot::newer::DeserializableVersionedBank;
//use solana_sdk::stake::state::Delegation;
//use std::sync::Arc;
//use solana_sdk::pubkey::Pubkey;

extern crate hex;
extern crate serde_json;

//use std::io;
use std::io::Read;
use std::io::BufReader;
use std::fs::File;

fn main() {
    let f = File::open("/home/jsiegel/manifest").unwrap();
    let mut reader = BufReader::new(f);
    let mut buffer = Vec::new();
    
    // Read file into vector.
    reader.read_to_end(&mut buffer).unwrap();

    let versioned_bank: DeserializableVersionedBank = bincode::deserialize(buffer.as_slice()).unwrap();
    println!("{}", versioned_bank.epoch_stakes.keys().len());
    println!("{}", versioned_bank.stakes.vote_accounts.vote_accounts.keys().len());
    println!("{}", versioned_bank.tick_height);

    let d2: Vec<u8> = bincode::serialize(&versioned_bank.stakes).unwrap();
    println!("hex: {}",  hex::encode(d2));


//    let d = Delegation {
//        voter_pubkey: Pubkey::try_from("5mpjDRgoRYRmSnAXZTfB2bBkbpwvRjobXUjb4WYjF225").unwrap(),
//        stake: 1,
//        activation_epoch: 2,
//        deactivation_epoch: 3,
//        warmup_cooldown_rate: 4.0
//    };
//
////    let d1: Vec<u8> = bincode::serialize(&d).unwrap();
////    println!("Delegation: {} {}", serde_json::to_string(&d).unwrap(), hex::encode(d1));
//
//    let mut stakes = Stakes::<Delegation>::default();
//    stakes.stake_delegations.insert(d.voter_pubkey, d);
//    stakes.unused = 98; // 62 in hex
//    stakes.epoch = 41; // 29 in hex
//
//    let d2: Vec<u8> = bincode::serialize(&stakes).unwrap();
//    println!("Stakes::<Delegation>: {}",  hex::encode(d2));
//
//    let a = EpochStakes::new(Arc::new(StakesEnum::Delegations(stakes)), 10);
//    let encoded: Vec<u8> = bincode::serialize(&a).unwrap();
//    println!("EpochStakes: {}", hex::encode(encoded));

//    {
//        let e = StakeHistoryEntry {
//            effective: 1,
//            activating: 2,
//            deactivating: 3,
//        };
//
//        let mut a = StakeHistory::default();
//        a.add(5, e);
//
//        let encoded: Vec<u8> = bincode::serialize(&a).unwrap();
//
//        println!("StakeHistory: {} {}", serde_json::to_string(&a).unwrap(), hex::encode(encoded));
//    }
    
//    {
//        let acct = Account {
//            lamports: 1,
//            data: vec![4,5,6],
//            executable: true,
//            rent_epoch: 3,
//            owner: Pubkey::try_from("5mpjDRgoRYRmSnAXZTfB2bBkbpwvRjobXUjb4WYjF225").unwrap()
//        };
//
//        let encoded: Vec<u8> = bincode::serialize(&acct).unwrap();
//
//        println!("Account: {} {}", serde_json::to_string(&acct).unwrap(), hex::encode(encoded));
//    }
//    {
//        let mut t = solana_runtime::blockhash_queue::BlockhashQueue::new(5);
//
//        let buf = [5u8; 32];
//
//        let h = solana_sdk::hash::Hash::new(&buf);
//        t.genesis_hash(&h, 123);
//
//        let encoded: Vec<u8> = bincode::serialize(&t).unwrap();
//        println!("BlockhashQueue: {}", hex::encode(encoded));
//    }
}
