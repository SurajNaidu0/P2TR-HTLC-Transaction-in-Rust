use bitcoin::secp256k1::{  SecretKey,PublicKey};
use bitcoin::taproot::{merkle_branch, ControlBlock, LeafVersion, TapLeaf, TapLeafHash, TapTweakHash, TaprootError, TaprootMerkleBranch, TaprootSpendInfo};
use bitcoin::{Script, ScriptBuf,XOnlyPublicKey,TapNodeHash,Address,KnownHrp,Witness,OutPoint,TxIn,TxOut,Transaction,Sequence,Amount,Network,TapSighashType};
use std::str::FromStr;
use bitcoin::key::{Parity, Secp256k1, TapTweak, UntweakedPublicKey,Keypair};
use bitcoin::consensus::Encodable;
use bitcoin::TapBranchTag;
use hex;
use bitcoin::address::{NetworkUnchecked, NetworkChecked};
use bitcoin::sighash::SighashCache;
use bitcoin::secp256k1::{Message};

#[derive(Debug)]
struct MerkleBranchHTLC {
    Address: Address,
    MerkleRoot: TapNodeHash,
    RedeemScriptLeaf: TapNodeHash,
    RefundScriptLeaf: TapNodeHash,
    Parity: Parity,
    InternalKey: XOnlyPublicKey,
    ReedeemScript: ScriptBuf,
    RefundScript: ScriptBuf,
}



fn main() {
    //This data is only for ez of testing dont use it with key holding real money
    let private_key_sender = "c929c768be0902d5bb7ae6e38bdc6b3b24cefbe93650da91975756a09e408460";
    let private_key_receiver = "8957096d6d79f8ba171bcce36eb0e6e6a6c02f17546180d849745988b2f5b0ee";
    let secret_hash = "6c93e898c1bcf964c54bbdc8bafeb5ab557ccba4f7f7a1f55cecb80581875d9f";
    let sender_pubkey = "456db773aa5c4cc6ed3a4780243d16bd58220be318702603b219fe79eceb848f";
    let receiver_pubkey = "fdfbf55076737c3b8e150ab1fcf138caa7a8671d2185695944c2581ef11aa866";
    let pre_image = "6e0d8625db81003c347c5ccc2c26f3a6b3cc8991c05624b9eeb80b1357ca8408";

    let merkle_branch = create_taproot_address_HTLC(secret_hash, sender_pubkey, receiver_pubkey).unwrap();
    println!("Address: {:?}", merkle_branch.Address);

    redeem_taproot_address_HTLC(merkle_branch,pre_image,private_key_receiver);
}

//OP_PUSHBYTES_32 6d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0 OP_CHECKSIG // Example Spending Path

//OP_SHA256 OP_PUSHBYTES_32 6c93e898c1bcf964c54bbdc8bafeb5ab557ccba4f7f7a1f55cecb80581875d9f OP_EQUALVERIFY OP_PUSHBYTES_32 6d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0 OP_CHECKSIG // reedeem path

//OP_PUSHBYTES_3 0e0040 OP_CHECKSEQUENCEVERIFY OP_DROP OP_PUSHBYTES_32 6d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0 OP_CHECKSIG // refund taproot path

fn create_taproot_address_HTLC(secret_hash: &str, sender_pubkey: &str, receiver_pubkey: &str) -> Option<MerkleBranchHTLC>  {
    // Initialize secp256k1 context
    let secp = Secp256k1::new();

    // Parse the x-only public keys (32 bytes)
    let sender_xonly = XOnlyPublicKey::from_str(sender_pubkey).expect("Invalid sender pubkey");
    let receiver_xonly = XOnlyPublicKey::from_str(receiver_pubkey).expect("Invalid receiver pubkey");

    // Use an unspendable internal key
    let internal_key: XOnlyPublicKey = XOnlyPublicKey::from_str("0000000000000000000000000000000000000000000000000000000000000001")
        .expect("Invalid NUMS point");

    // Redeem Script: OP_SHA256 <secret_hash> OP_EQUALVERIFY <receiver_pubkey> OP_CHECKSIG
    let redeem_script_hex = format!(
        "a820{}87{}ac", // OP_SHA256 <32-byte hash> OP_EQUALVERIFY <32-byte pubkey> OP_CHECKSIG
        secret_hash,
        receiver_pubkey
    );
    let redeem_script_bytes = hex::decode(redeem_script_hex).expect("Invalid redeem script hex");
    let redeem_script = ScriptBuf::from_bytes(redeem_script_bytes);

    // Refund Script: OP_PUSHBYTES_3 0e0040 OP_CHECKSEQUENCEVERIFY OP_DROP <sender_pubkey> OP_CHECKSIG
    let refund_script_hex = format!(
        "030e0040b27520{}ac", // 3-byte timelock (14 units ≈ 2 hours), CSV, DROP, pubkey, CHECKSIG
        sender_pubkey
    );
    let refund_script_bytes = hex::decode(refund_script_hex).expect("Invalid refund script hex");
    let refund_script = ScriptBuf::from_bytes(refund_script_bytes);


    // Creating TapLeaf
    let leafVersion = LeafVersion::TapScript;

    let redeem_script_leaf_hash: TapNodeHash = TapNodeHash::from_script(&redeem_script, leafVersion); //constructs Leaf Node Hash

    let refund_script_leaf_hash: TapNodeHash = TapNodeHash::from_script(&refund_script, leafVersion); //constructs Leaf Node Hash

    let merkle_root = TapNodeHash::from_node_hashes(redeem_script_leaf_hash, refund_script_leaf_hash); //constructs Merkle Branch

    let (tweaked_public_key,parity) = internal_key.tap_tweak(&secp,Some(merkle_root));
    let tweaked_pubkey_script = ScriptBuf::new_p2tr_tweaked(tweaked_public_key);
    let address = Address::p2tr_tweaked(tweaked_public_key, KnownHrp::Mainnet);

    let merkle_branch = MerkleBranchHTLC {
        Address: address,
        MerkleRoot: merkle_root,
        RedeemScriptLeaf: redeem_script_leaf_hash,
        RefundScriptLeaf: refund_script_leaf_hash,
        Parity: parity,
        InternalKey: internal_key,
        ReedeemScript: redeem_script,
        RefundScript: refund_script
    };

    return Some(merkle_branch);
}

fn redeem_taproot_address_HTLC(merkle_branch:MerkleBranchHTLC,preimage : &str, private_key_receiver: &str)-> Option<Address>{

    //Merkal path for spending in constrol bytes
    let hash_hex = merkle_branch.RefundScriptLeaf.to_string();
    let hash_bytes: [u8; 32] = hex::decode(hash_hex)
        .expect("Invalid hex string")
        .try_into()
        .expect("Hex string must be 32 bytes");
    
    let merkle_branch_redeem = TaprootMerkleBranch::decode(&hash_bytes).map_err(|e: TaprootError| format!("Failed to decode Merkle branch: {}", e)).unwrap();
    print!("Merkle Branch: {:?}", merkle_branch_redeem);
    
    //Creating Control Block
    let control_block = ControlBlock{
        leaf_version: LeafVersion::TapScript,
        output_key_parity: merkle_branch.Parity,
        internal_key: merkle_branch.InternalKey,
        merkle_branch: merkle_branch_redeem,
    };

    println!("{:?}",control_block);

    // Receiver's key for signing
    let secp = Secp256k1::new();
    let receiver_secret_key = SecretKey::from_str(private_key_receiver).expect("Invalid private key");
    let receiver_public_key = PublicKey::from_secret_key(&secp, &receiver_secret_key);
    let receiver_xonly = XOnlyPublicKey::from(receiver_public_key);

    // Construct a simple transaction
    let prevout_txid = bitcoin::Txid::from_str("0000000000000000000000000000000000000000000000000000000000000000").unwrap(); // Dummy txid

    // Dummy txid // Dummy txid
    let prevout = OutPoint::new(prevout_txid, 0); // Assume vout 0
    let input = TxIn {
        previous_output: prevout,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME, // RBF enabled, no locktime
        witness: Witness::default(),
    };

    let address: Address<NetworkUnchecked> = "32iVBEu4dxkUQk9dJbZUiBiQdmypcEyJRf".parse().unwrap();
    let address: Address<NetworkChecked> = address.require_network(Network::Bitcoin).unwrap();


    let output = TxOut {
        value: Amount::from_sat(100_000), // 0.001 BTC (example amount)
        script_pubkey: address.script_pubkey(), // Dummy destination
    };

    

    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![input],
        output: vec![output],
    };

    // Compute TapSighash
    let mut sighash_cache = SighashCache::new(&tx);
    let sighash = sighash_cache.taproot_script_spend_signature_hash(
        0, // Input index
        &bitcoin::sighash::Prevouts::All(&[TxOut {
            value: Amount::from_sat(200_000), // Previous output amount (example)
            script_pubkey: merkle_branch.Address.script_pubkey(),
        }]),
        TapLeafHash::from_script(&merkle_branch.ReedeemScript, LeafVersion::TapScript),
        TapSighashType::Default,
    ).expect("Failed to compute sighash");

    // Sign with Schnorr
    let key_pair = Keypair::from_secret_key(&secp,&receiver_secret_key);
    let msg = Message::from_digest_slice(&sighash[..]).unwrap();
    let sign = secp.sign_schnorr_no_aux_rand(&msg, &key_pair);
    // Construct Witness
    let mut witness = Witness::new();
    witness.push(preimage.as_bytes());                   // 1. Preimage
    witness.push(sign.as_ref());                    // 2. Schnorr signature
    witness.push(merkle_branch.ReedeemScript.as_bytes()); // 3. Redeem script
    witness.push(&control_block.serialize());            // 4. Control block

    println!("control block {:?}",witness.taproot_control_block());

    


    None
}


 