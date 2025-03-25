//OP_PUSHBYTES_32 6d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0 OP_CHECKSIG // Example Spending Path

//OP_SHA256 OP_PUSHBYTES_32 6c93e898c1bcf964c54bbdc8bafeb5ab557ccba4f7f7a1f55cecb80581875d9f OP_EQUALVERIFY OP_PUSHBYTES_32 6d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0 OP_CHECKSIG // reedeem path

//OP_PUSHBYTES_3 0e0040 OP_CHECKSEQUENCEVERIFY OP_DROP OP_PUSHBYTES_32 6d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0 OP_CHECKSIG // refund taproot path

use bitcoin::secp256k1::{SecretKey, PublicKey, Message, Secp256k1};
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootError, TaprootMerkleBranch};
use bitcoin::{ScriptBuf, XOnlyPublicKey, TapNodeHash, Address, KnownHrp, Witness, OutPoint, TxIn, TxOut, Transaction, Sequence, Amount, Network, TapSighashType};
use bitcoin::key::{Parity, TapTweak, Keypair};
use bitcoin::address::{NetworkUnchecked, NetworkChecked};
use bitcoin::sighash::SighashCache;
use std::str::FromStr;
use hex;

// Struct to hold HTLC Taproot data
#[derive(Debug)]
struct TaprootHTLC {
    address: Address,
    merkle_root: TapNodeHash,
    redeem_leaf: TapNodeHash,
    refund_leaf: TapNodeHash,
    parity: Parity,
    internal_key: XOnlyPublicKey,
    redeem_script: ScriptBuf,
    refund_script: ScriptBuf,
}

fn main() {
    // Test data (not for real funds)
    let sender_private_key = "c929c768be0902d5bb7ae6e38bdc6b3b24cefbe93650da91975756a09e408460";
    let receiver_private_key = "8957096d6d79f8ba171bcce36eb0e6e6a6c02f17546180d849745988b2f5b0ee";
    let secret_hash = "6c93e898c1bcf964c54bbdc8bafeb5ab557ccba4f7f7a1f55cecb80581875d9f";
    let sender_pubkey = "456db773aa5c4cc6ed3a4780243d16bd58220be318702603b219fe79eceb848f";
    let receiver_pubkey = "fdfbf55076737c3b8e150ab1fcf138caa7a8671d2185695944c2581ef11aa866";
    let preimage = "6e0d8625db81003c347c5ccc2c26f3a6b3cc8991c05624b9eeb80b1357ca8408";

    // Create Taproot HTLC address
    let htlc = create_taproot_htlc(secret_hash, sender_pubkey, receiver_pubkey).unwrap();
    println!("HTLC Address: {:?}", htlc.address);

    // Attempt to redeem and refund the HTLC
    redeem_taproot_htlc(&htlc, preimage, receiver_private_key);
    refund_taproot_htlc(&htlc, sender_private_key);
}

// Creates a Taproot address with HTLC scripts (redeem and refund paths)
fn create_taproot_htlc(secret_hash: &str, sender_pubkey: &str, receiver_pubkey: &str) -> Option<TaprootHTLC> {
    let secp = Secp256k1::new();

    // Parse sender and receiver X-only public keys (32 bytes)
    let sender_xonly = XOnlyPublicKey::from_str(sender_pubkey).expect("Invalid sender pubkey");
    let receiver_xonly = XOnlyPublicKey::from_str(receiver_pubkey).expect("Invalid receiver pubkey");

    // Use an unspendable internal key (NUMS point)
    let internal_key = XOnlyPublicKey::from_str("0000000000000000000000000000000000000000000000000000000000000001")
        .expect("Invalid NUMS point");

    // Redeem script: OP_SHA256 <secret_hash> OP_EQUALVERIFY <receiver_pubkey> OP_CHECKSIG
    let redeem_script_hex = format!("a820{}87{}ac", secret_hash, receiver_pubkey);
    let redeem_script_bytes = hex::decode(redeem_script_hex).expect("Invalid redeem script hex");
    let redeem_script = ScriptBuf::from_bytes(redeem_script_bytes);

    // Refund script: <timelock> OP_CHECKSEQUENCEVERIFY OP_DROP <sender_pubkey> OP_CHECKSIG
    let refund_script_hex = format!("030e0040b27520{}ac", sender_pubkey); // 14 units timelock (~2 hours)
    // let refund_script_hex = format!("03010000b27520{}ac", sender_pubkey);
    let refund_script_bytes = hex::decode(refund_script_hex).expect("Invalid refund script hex");
    let refund_script = ScriptBuf::from_bytes(refund_script_bytes);

    // Create TapLeaf hashes for both scripts
    let leaf_version = LeafVersion::TapScript;
    let redeem_leaf = TapNodeHash::from_script(&redeem_script, leaf_version);
    let refund_leaf = TapNodeHash::from_script(&refund_script, leaf_version);

    // Compute Merkle root from the two leaf hashes
    let merkle_root = TapNodeHash::from_node_hashes(redeem_leaf, refund_leaf);

    // Tweak the internal key with the Merkle root to get the final Taproot output key
    let (tweaked_public_key, parity) = internal_key.tap_tweak(&secp, Some(merkle_root));
    let address = Address::p2tr_tweaked(tweaked_public_key, KnownHrp::Testnets);

    Some(TaprootHTLC {
        address,
        merkle_root,
        redeem_leaf,
        refund_leaf,
        parity,
        internal_key,
        redeem_script,
        refund_script,
    })
}

// Redeems the HTLC using the preimage (receiver's path)
fn redeem_taproot_htlc(htlc: &TaprootHTLC, preimage: &str, receiver_private_key: &str) -> Option<Address> {
    let secp = Secp256k1::new();

    // Compute Merkle branch for redeem path (using refund leaf as sibling)
    let hash_hex = htlc.refund_leaf.to_string();
    let hash_bytes: [u8; 32] = hex::decode(hash_hex)
        .expect("Invalid hex string")
        .try_into()
        .expect("Hex string must be 32 bytes");
    let merkle_branch = TaprootMerkleBranch::decode(&hash_bytes)
        .map_err(|e: TaprootError| format!("Failed to decode Merkle branch: {}", e))
        .unwrap();

    // Create control block for Taproot script spend
    let control_block = ControlBlock {
        leaf_version: LeafVersion::TapScript,
        output_key_parity: htlc.parity,
        internal_key: htlc.internal_key,
        merkle_branch,
    };

    // Derive receiver's keypair for signing
    let receiver_secret_key = SecretKey::from_str(receiver_private_key).expect("Invalid private key");
    let key_pair = Keypair::from_secret_key(&secp, &receiver_secret_key);

    // Construct a basic transaction
    let prevout_txid = bitcoin::Txid::from_str("759262674c73539823c17206495a47f42b1c28bb3218c2321e67e14dd58d6858").unwrap();
    let prevout = OutPoint::new(prevout_txid, 0);
    let input = TxIn {
        previous_output: prevout,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::default(),
    };

    let output_address: Address<NetworkUnchecked> = "tb1q96nq377kphel5ru9rf5f6nh2lqdsxz25h79lxa".parse().unwrap();
    let output_address = output_address.require_network(Network::Testnet).unwrap();
    let output = TxOut {
        value: Amount::from_sat(700), // 0.001 BTC
        script_pubkey: output_address.script_pubkey(),
    };

    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![input],
        output: vec![output],
    };

    // Compute Taproot sighash for script spend
    let mut sighash_cache = SighashCache::new(&tx);
    let sighash = sighash_cache.taproot_script_spend_signature_hash(
        0,
        &bitcoin::sighash::Prevouts::All(&[TxOut {
            value: Amount::from_sat(900), // Previous output amount
            script_pubkey: htlc.address.script_pubkey(),
        }]),
        TapLeafHash::from_script(&htlc.redeem_script, LeafVersion::TapScript),
        TapSighashType::Default,
    ).expect("Failed to compute sighash");

    // Sign the transaction with Schnorr
    let msg = Message::from_digest_slice(&sighash[..]).unwrap();
    let signature = secp.sign_schnorr_no_aux_rand(&msg, &key_pair);

    // Construct witness for redeem path
    let mut witness = Witness::new();
    witness.push(preimage.as_bytes());              // Preimage for hash verification
    witness.push(signature.as_ref());              // Schnorr signature
    witness.push(htlc.redeem_script.as_bytes());   // Redeem script
    witness.push(&control_block.serialize());      // Control block

    tx.input[0].witness = witness;

    let tx_hex = bitcoin::consensus::encode::serialize_hex(&tx);
    println!("tx_hex {}",tx_hex);

    

    None // Placeholder return (could return the output address if needed)
}

// Refunds the HTLC after timelock (sender's path)
fn refund_taproot_htlc(htlc: &TaprootHTLC, sender_private_key: &str) -> Option<Address> {
    let secp = Secp256k1::new();

    // Compute Merkle branch for refund path (using redeem leaf as sibling)
    let hash_hex = htlc.redeem_leaf.to_string();
    let hash_bytes: [u8; 32] = hex::decode(hash_hex)
        .expect("Invalid hex string")
        .try_into()
        .expect("Hex string must be 32 bytes");
    let merkle_branch = TaprootMerkleBranch::decode(&hash_bytes)
        .map_err(|e: TaprootError| format!("Failed to decode Merkle branch: {}", e))
        .unwrap();
    println!("Merkle Branch: {:?}", merkle_branch);

    // Create control block for Taproot script spend
    let control_block = ControlBlock {
        leaf_version: LeafVersion::TapScript,
        output_key_parity: htlc.parity,
        internal_key: htlc.internal_key,
        merkle_branch,
    };
    // println!("Control Block: {:?}", control_block);

    // Derive sender's keypair for signing
    let sender_secret_key = SecretKey::from_str(sender_private_key).expect("Invalid private key");
    let key_pair = Keypair::from_secret_key(&secp, &sender_secret_key);

    // Construct a basic transaction
    let prevout_txid = bitcoin::Txid::from_str("76785f45d5b7ee248b0ca4d7612a9055ce8dc82c9c0573786743532ce7425ad6").unwrap();
    let prevout = OutPoint::new(prevout_txid, 1);
    let input = TxIn {
        previous_output: prevout,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME, // Note: Should reflect timelock in practice
        witness: Witness::default(),
    };

    let output_address: Address<NetworkUnchecked> = "tb1q96nq377kphel5ru9rf5f6nh2lqdsxz25h79lxa".parse().unwrap();
    let output_address = output_address.require_network(Network::Testnet).unwrap();
    let output = TxOut {
        value: Amount::from_sat(700), // 0.001 BTC
        script_pubkey: output_address.script_pubkey(),
    };

    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![input],
        output: vec![output],
    };

    // Compute Taproot sighash for script spend
    let mut sighash_cache = SighashCache::new(&tx);
    let sighash = sighash_cache.taproot_script_spend_signature_hash(
        0,
        &bitcoin::sighash::Prevouts::All(&[TxOut {
            value: Amount::from_sat(900), // Previous output amount
            script_pubkey: htlc.address.script_pubkey(),
        }]),
        TapLeafHash::from_script(&htlc.refund_script, LeafVersion::TapScript),
        TapSighashType::Default,
    ).expect("Failed to compute sighash");

    // Sign the transaction with Schnorr
    let msg = Message::from_digest_slice(&sighash[..]).unwrap();
    let signature = secp.sign_schnorr_no_aux_rand(&msg, &key_pair);

    // Construct witness for refund path
    let mut witness = Witness::new();
    witness.push(signature.as_ref());             // Schnorr signature
    witness.push(htlc.refund_script.as_bytes());  // Refund script
    witness.push(&control_block.serialize());     // Control block
    // println!("Witness: {:?}", witness);

    tx.input[0].witness = witness;


    let tx_hex = bitcoin::consensus::encode::serialize_hex(&tx);
    println!("tx_hex {}",tx_hex);

    None // Placeholder return (could return the output address if needed)
}

