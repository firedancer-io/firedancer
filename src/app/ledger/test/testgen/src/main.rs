
extern crate hex;
extern crate serde_json;

use serde::Serialize;

//use std::collections::BTreeMap;
use clock::UnixTimestamp;

#[derive(Serialize)]
pub struct Foo {
    /// when the network (bootstrap validator) was started relative to the UNIX Epoch
    pub creation_time: UnixTimestamp,
    /// initial accounts
//    pub accounts: BTreeMap<Pubkey, Account>,
    /// built-in programs
    pub b : u64
};

fn main() {
    let s = Foo {
        creation_time:  2,
        b: 5
    };

    let d2: Vec<u8> = bincode::serialize(&s).unwrap();
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
