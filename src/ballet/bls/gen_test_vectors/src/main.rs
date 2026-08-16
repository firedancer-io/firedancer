use solana_bls_signatures::{
    keypair::Keypair as BLSKeypair,
    signature::SignatureProjective,
    pubkey::PubkeyProjective,
    BLS_SECRET_KEY_SIZE,
};
use solana_keypair::Keypair;
use solana_signer::Signer;
use zeroize::Zeroizing;

fn main() {
    println!("=== BLS12-381 Test Vector Generator ===\n");

    // -----------------------------------------------------------------
    // 1) KDF test vectors (unchanged — KDF outputs compressed)
    // -----------------------------------------------------------------
    println!("--- KDF Test Vectors ---");

    let ed25519_secret: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];

    let ed25519_kp = Keypair::new_from_array(ed25519_secret);
    let ed25519_pk = ed25519_kp.pubkey();

    println!("ed25519_private_key: {}", hex::encode(ed25519_secret));
    println!("ed25519_public_key:  {}", hex::encode(ed25519_pk.to_bytes()));

    let bls_kp = BLSKeypair::derive_from_signer(&ed25519_kp, b"alpenglow").unwrap();
    let bls_pk_compressed = bls_kp.public.to_bytes_compressed();
    let bls_sk_zeroizing: Zeroizing<[u8; BLS_SECRET_KEY_SIZE]> = (&bls_kp.secret).into();
    let bls_sk_bytes: [u8; 32] = *bls_sk_zeroizing;

    println!("bls_secret_key:        {}", hex::encode(bls_sk_bytes));
    println!("bls_pubkey_compressed: {}", hex::encode(bls_pk_compressed));

    // PoP test (using 41-byte message only)
    let vote_account_pubkey_bytes: [u8; 32] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    ];

    let mut pop_message = Vec::new();
    pop_message.extend_from_slice(b"ALPENGLOW");
    pop_message.extend_from_slice(&vote_account_pubkey_bytes);

    let pop = bls_kp.proof_of_possession(Some(&pop_message));
    let pop_compressed = pop.to_bytes_compressed();
    println!("pop_compressed:        {}", hex::encode(pop_compressed));

    // -----------------------------------------------------------------
    // 2) Signature test vectors — both compressed and uncompressed
    // -----------------------------------------------------------------
    println!("\n--- Signature Test Vectors ---");

    let ikm1 = b"test_ikm_keypair_1_at_least_32_bytes_long!!!";
    let ikm2 = b"test_ikm_keypair_2_at_least_32_bytes_long!!!";
    let ikm3 = b"test_ikm_keypair_3_at_least_32_bytes_long!!!";

    let kp1 = BLSKeypair::derive(ikm1).unwrap();
    let kp2 = BLSKeypair::derive(ikm2).unwrap();
    let kp3 = BLSKeypair::derive(ikm3).unwrap();

    // Pubkeys — both formats
    println!("pk1_compressed:     {}", hex::encode(kp1.public.to_bytes_compressed()));
    println!("pk2_compressed:     {}", hex::encode(kp2.public.to_bytes_compressed()));
    println!("pk3_compressed:     {}", hex::encode(kp3.public.to_bytes_compressed()));
    println!("pk1_uncompressed:   {}", hex::encode(kp1.public.to_bytes_uncompressed()));
    println!("pk2_uncompressed:   {}", hex::encode(kp2.public.to_bytes_uncompressed()));
    println!("pk3_uncompressed:   {}", hex::encode(kp3.public.to_bytes_uncompressed()));

    let msg1 = b"message_one";
    let msg2 = b"message_two";
    let msg3 = b"message_three";

    let sig1 = kp1.sign(msg1);
    let sig2 = kp2.sign(msg2);
    let sig3 = kp3.sign(msg3);

    // Signatures — both formats
    println!("msg1: {}", hex::encode(msg1));
    println!("msg2: {}", hex::encode(msg2));
    println!("msg3: {}", hex::encode(msg3));
    println!("sig1_compressed:    {}", hex::encode(sig1.to_bytes_compressed()));
    println!("sig2_compressed:    {}", hex::encode(sig2.to_bytes_compressed()));
    println!("sig3_compressed:    {}", hex::encode(sig3.to_bytes_compressed()));
    println!("sig1_uncompressed:  {}", hex::encode(sig1.to_bytes_uncompressed()));
    println!("sig2_uncompressed:  {}", hex::encode(sig2.to_bytes_uncompressed()));
    println!("sig3_uncompressed:  {}", hex::encode(sig3.to_bytes_uncompressed()));

    // Aggregate signatures — output both formats
    let agg_sig = SignatureProjective::aggregate(
        [&sig1, &sig2, &sig3].into_iter()
    ).unwrap();
    println!("agg_sig_compressed:   {}", hex::encode(agg_sig.to_bytes_compressed()));
    println!("agg_sig_uncompressed: {}", hex::encode(agg_sig.to_bytes_uncompressed()));

    // Single sig aggregation
    let agg_sig1 = SignatureProjective::aggregate([&sig1].into_iter()).unwrap();
    println!("agg_sig1_uncompressed (== sig1): {}", hex::encode(agg_sig1.to_bytes_uncompressed()));

    // -----------------------------------------------------------------
    // 3) Pubkey aggregation — output both formats
    // -----------------------------------------------------------------
    println!("\n--- Pubkey Aggregation Test Vectors ---");

    use solana_bls_signatures::pubkey::AddToPubkeyProjective;

    let mut agg_pk_proj = PubkeyProjective::identity();
    (*kp1.public).add_to_accumulator(&mut agg_pk_proj).unwrap();
    (*kp2.public).add_to_accumulator(&mut agg_pk_proj).unwrap();
    (*kp3.public).add_to_accumulator(&mut agg_pk_proj).unwrap();

    let agg_pk_affine: solana_bls_signatures::pubkey::PubkeyAffine = agg_pk_proj.into();
    println!("agg_pk_compressed:   {}", hex::encode(agg_pk_affine.to_bytes_compressed()));
    println!("agg_pk_uncompressed: {}", hex::encode(agg_pk_affine.to_bytes_uncompressed()));

    // Single pk aggregation
    let mut agg_pk1_proj = PubkeyProjective::identity();
    (*kp1.public).add_to_accumulator(&mut agg_pk1_proj).unwrap();
    let agg_pk1_affine: solana_bls_signatures::pubkey::PubkeyAffine = agg_pk1_proj.into();
    println!("agg_pk1_uncompressed (== pk1): {}", hex::encode(agg_pk1_affine.to_bytes_uncompressed()));

    // -----------------------------------------------------------------
    // 4) Batch verify test vectors
    // -----------------------------------------------------------------
    println!("\n--- Batch Verify Test Vectors (same message) ---");

    let common_msg = b"common_message_for_batch_verify";
    let bsig1 = kp1.sign(common_msg);
    let bsig2 = kp2.sign(common_msg);
    let bsig3 = kp3.sign(common_msg);

    println!("common_msg: {}", hex::encode(common_msg));
    println!("bsig1_uncompressed: {}", hex::encode(bsig1.to_bytes_uncompressed()));
    println!("bsig2_uncompressed: {}", hex::encode(bsig2.to_bytes_uncompressed()));
    println!("bsig3_uncompressed: {}", hex::encode(bsig3.to_bytes_uncompressed()));

    assert!(kp1.verify(&bsig1, common_msg).is_ok());
    assert!(kp2.verify(&bsig2, common_msg).is_ok());
    assert!(kp3.verify(&bsig3, common_msg).is_ok());

    // Batch verify with distinct messages
    let batch_result = SignatureProjective::verify_distinct(
        [&kp1.public, &kp2.public, &kp3.public].iter().copied(),
        [&sig1, &sig2, &sig3].iter().copied(),
        [msg1.as_slice(), msg2.as_slice(), msg3.as_slice()].iter().copied(),
    );
    println!("batch_verify_distinct_result: {:?}", batch_result);

    println!("\n=== Done ===");
}
