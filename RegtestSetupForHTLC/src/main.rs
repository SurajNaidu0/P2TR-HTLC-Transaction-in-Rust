#![allow(unused)]
use bitcoin::{opcodes, Address, Amount, KnownHrp, Network, OutPoint, ScriptBuf, Sequence, TapNodeHash, TapSighashType, Transaction, TxIn, TxOut, Txid, Witness, XOnlyPublicKey};
use bitcoin::blockdata;
use bitcoin::key::{Parity, TapTweak, Keypair};
use bitcoin::address::{NetworkUnchecked, NetworkChecked};
use bitcoin::sighash::SighashCache;
use std::str::FromStr;
use hex;
use bitcoin::script::PushBytesBuf;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use serde::Deserialize;
use serde_json::json;
use std::fs::File;
use std::io::Write;
use bitcoincore_rpc::json::LoadWalletResult;
use anyhow::Result;
use bitcoincore_rpc::bitcoin::key::{rand, PrivateKey, PublicKey};
use bitcoincore_rpc::bitcoin::secp256k1::{Secp256k1, SecretKey, Message};
use rand::Rng;
use bitcoincore_rpc::bitcoin::CompressedPublicKey;
use bitcoincore_rpc::json::EstimateMode;
use bitcoincore_rpc::bitcoin::transaction::Version;
use bitcoincore_rpc::bitcoin::consensus::encode::serialize_hex;
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootError, TaprootMerkleBranch};
use bitcoin::EcdsaSighashType;
use bitcoin::absolute::{LockTime,Time};



// Node access params
// Bitcoin Core RPC connection parameters for regtest network (local test environment)
const RPC_URL: &str = "http://127.0.0.1:18443"; // Default regtest RPC port
const RPC_USER: &str = "alice";
const RPC_PASS: &str = "password";

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

// You can use calls not provided in RPC lib API using the generic `call` function.
// An example of using the `send` RPC call, which doesn't have exposed API.
// You can also use serde_json `Deserialize` derivation to capture the returned json result.
// This function creates a transaction with both a payment output and an OP_RETURN data output
fn send(rpc: &Client, addr: &str) -> bitcoincore_rpc::Result<String> {
    let recipient_address = addr;
    let amount_btc = 100.0;
    let message = "We are all Satoshi!!";
    let op_return_hex = hex::encode(message.as_bytes());
    let args = [
        json!([
            { recipient_address: amount_btc }, // BTC payment output
            { "data": op_return_hex } // OP_RETURN output - stores arbitrary data on blockchain
        ]),
        json!(null), // conf target
        json!(null), // estimate mode
        json!(21),   // Explicit fee rate: 21 sat/vB
        json!({}),   // Empty options object
    ];

    #[derive(Deserialize)]
    struct SendResult {
        complete: bool,
        txid: String,
    }
    let send_result = rpc.call::<SendResult>("send", &args)?;
    assert!(send_result.complete);
    Ok(send_result.txid)
}

// Lists all wallets in the Bitcoin Core data directory
// Returns a vector of wallet names found in the Bitcoin Core wallet directory
fn list_wallet_dir(client: &Client) -> bitcoincore_rpc::Result<Vec<String>> {
    #[derive(Deserialize)]
    struct Name {
        name: String,
    }
    #[derive(Deserialize)]
    struct CallResult {
        wallets: Vec<Name>,
    }

    let result: CallResult = client.call("listwalletdir", &[])?;
    Ok(result.wallets.into_iter().map(|n| n.name).collect())
}

pub fn create_or_load_wallet(client: &Client)-> Result<LoadWalletResult>  {
    println!("Getting Wallet Info");
    // Check existing wallets and create/load as needed
    let current_wallets = list_wallet_dir(&client).unwrap();
    if let 0 = current_wallets.into_iter().len(){
        println!("No wallet exists creating one");
        Ok(client.create_wallet("test",None,None,None,None).unwrap())
    }else{
        println!("Loading wallet");
        // Unload existing wallet before loading to prevent conflicts
        let _ = client.unload_wallet(Some("testwallet"));
        Ok(client.load_wallet("testwallet").unwrap())
    }
}

fn get_address_balance_scan(rpc: &Client, address: &Address) -> Result<f64> {
    // Convert the address to string
    let address_str = address.to_string();

    // Use scantxoutset to find all UTXOs for this address
    #[derive(Deserialize)]
    struct ScanResult {
        total_amount: f64,
        unspents: Vec<Unspent>,
        // other fields...
    }

    #[derive(Deserialize)]
    struct Unspent {
        txid: String,
        vout: u32,
        amount: f64,
        // other fields...
    }

    // Create the descriptor for the address
    // For a P2WPKH address, the descriptor would be "addr(address)"
    let descriptor = format!("addr({})", address_str);

    // The call method expects individual JSON values, not a single array
    let scan_result: ScanResult = rpc.call("scantxoutset", &[
        json!("start"),
        json!([descriptor])
    ])?;

    // Convert BTC to satoshis
    let balance_btc = scan_result.total_amount;

    println!("Address {} has balance: {} BTC", address_str, balance_btc);

    Ok(balance_btc)
}

fn get_address_utxos(rpc: &Client, address: &Address) -> Result<Vec<(OutPoint, u64)>> {
    // Convert the address to string
    let address_str = address.to_string();

    // Use scantxoutset to find all UTXOs for this address
    #[derive(Deserialize)]
    struct ScanResult {
        total_amount: f64,
        unspents: Vec<Unspent>,
    }

    #[derive(Deserialize)]
    struct Unspent {
        txid: String,
        vout: u32,
        amount: f64,
        height: u32,
    }

    let descriptor = format!("addr({})", address_str);

    let scan_result: ScanResult = rpc.call("scantxoutset", &[
        json!("start"),
        json!([descriptor])
    ])?;

    // Convert to list of OutPoint and amount in satoshis
    let utxos = scan_result.unspents.iter().map(|u| {
        let txid = u.txid.parse().unwrap();
        let outpoint = OutPoint { txid, vout: u.vout };
        let amount_sats = (u.amount * 100_000_000.0) as u64;
        (outpoint, amount_sats)
    }).collect();

    Ok(utxos)
}


fn main() -> bitcoincore_rpc::Result<()> {
    // Initialize RPC connection to the Bitcoin Core node
    let rpc = Client::new(
        RPC_URL,
        Auth::UserPass(RPC_USER.to_owned(), RPC_PASS.to_owned()),
    )?;

    // Check Connection
    let info = rpc.get_blockchain_info()?;
    println!("{:?}", info);
    // Create or load the wallet
    // create_or_load_wallet(&rpc).unwrap();

    let secp = Secp256k1::new();
    let sk = SecretKey::new(&mut rand::thread_rng());
    let private_key_minner = PrivateKey::new(sk, Network::Regtest);
    let compressed_public_key_minner = CompressedPublicKey::from_private_key(&secp, &private_key_minner).unwrap();
    let minner_address = Address::p2wpkh(&compressed_public_key_minner, Network::Regtest);
    println!("The minnner address is {}", minner_address);


    // Mine 101 blocks to the new address to activate the wallet with mined coins
    // Check current balance and mine if needed
    // In regtest, mining 104 blocks makes coinbase rewards spendable (mature)
    let block_hashes = rpc.generate_to_address(101, &minner_address)?;
    println!("Mined 104 blocks. Last block: {}", block_hashes.last().unwrap());

    // minner spending this coin to another address
    let sk = SecretKey::new(&mut rand::thread_rng());
    let private_key_recipient = PrivateKey::new(sk, Network::Regtest);
    let compressed_public_key_recipient = CompressedPublicKey::from_private_key(&secp, &private_key_recipient).unwrap();
    let recipient1_address = Address::p2wpkh(&compressed_public_key_recipient, Network::Regtest);
    println!("The recipient1 address is {}", recipient1_address);

    // Fetch a matured coinbase UTXO (from block 1 for simplicity)
    let block_hash = rpc.get_block_hash(1)?;
    let block = rpc.get_block(&block_hash)?;
    println!("Block 1: {:?}", block_hash);
    let coinbase_tx = &block.txdata[0];
    let utxo_txid = coinbase_tx.txid();
    let utxo_vout = 0;
    let utxo_amount = coinbase_tx.output[0].value; // Amount in satoshis
    println!("Coinbase UTXO txid: {}, amount: {} satoshis", utxo_txid, utxo_amount);

    //spending
    let txin = TxIn {
        previous_output: OutPoint { txid: utxo_txid, vout: 0 as u32},
        script_sig: ScriptBuf::new() ,
        sequence: Sequence::MAX,
        witness: Witness::default(),
    };

    // fetching the fee rate but it will be zero since we didnt fill previous blocks
    let feerate = match rpc.estimate_smart_fee(100,Some(EstimateMode::Economical)){
        Ok(fee) => match fee.fee_rate {
            Some(fee_rate) => fee_rate,
            None => Amount::from_sat(1000),
        },
        Err(e) => Amount::from_sat(1000),
    };

    let txout = TxOut {
        value: utxo_amount - feerate,
        script_pubkey: recipient1_address.script_pubkey(),
    };

    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![txin],
        output: vec![txout],
    };

    // Sign the transaction
    // For P2WPKH, we need to create a signature using the proper sighash
    let witness_script = minner_address.script_pubkey();
    let sighash_type = EcdsaSighashType::All;

    // Create a sighash cache for efficient signature hash computation
    let mut sighash_cache = SighashCache::new(&tx);

    // Compute the sighash for the first input
    let sighash = sighash_cache.p2wpkh_signature_hash(
        0, // Input index
        &witness_script, // The script being spent
        utxo_amount, // Value of the output being spent
        sighash_type
    ).unwrap();


    // Sign the sighash with the private key
    let msg = Message::from_digest_slice(&sighash[..])?;
    let signature = secp.sign_ecdsa(&msg, &private_key_minner.inner);

    // Serialize the signature with the sighash type appended
    let mut signature_serialized = signature.serialize_der().to_vec();
    signature_serialized.push(sighash_type as u8);

    let mut witness = Witness::new();
    witness.push(signature_serialized);
    witness.push(compressed_public_key_minner.to_bytes().to_vec());

    // Set the witness data for our transaction
    tx.input[0].witness = witness;

    // Print the transaction hex for inspection
    let tx_hex = serialize_hex(&tx);
    println!("Signed transaction hex: {}", tx_hex);

    // Broadcast the transaction to the network
    let txid = rpc.send_raw_transaction(&tx)?;
    println!("Transaction successfully broadcast! TXID: {}", txid);
    let block_hashes = rpc.generate_to_address(1, &minner_address)?;
    let balance_recenpt_1 = get_address_balance_scan(&rpc, &recipient1_address).unwrap();


    // Create a new address for the second recipient
    // Test data (not for real funds)
    let sender_private_key = "c929c768be0902d5bb7ae6e38bdc6b3b24cefbe93650da91975756a09e408460";
    let receiver_private_key = "8957096d6d79f8ba171bcce36eb0e6e6a6c02f17546180d849745988b2f5b0ee";
    let secret_hash = "6644fd23b8327a04d86bdadbeba6903c1e9bfef68f9c9ee7c00cc8f59529430c";
    let sender_pubkey = "456db773aa5c4cc6ed3a4780243d16bd58220be318702603b219fe79eceb848f";
    let receiver_pubkey = "fdfbf55076737c3b8e150ab1fcf138caa7a8671d2185695944c2581ef11aa866";
    let preimage = "6e0d8625db81003c347c5ccc2c26f3a6b3cc8991c05624b9eeb80b1357ca8408";

    let htlc = create_taproot_htlc(secret_hash, sender_pubkey, receiver_pubkey).unwrap();

    println!("Taproot Address is {}",htlc.address);

    


    // Get UTXOs for recipient1
    let recipient1_utxos = get_address_utxos(&rpc, &recipient1_address).unwrap();
    if recipient1_utxos.is_empty() {
        println!("No UTXOs found for recipient1 address");
        return Ok(());
    }
    // We know there is one UTXO so we can use the first one
    let (utxo_outpoint, utxo_amount_sats) = &recipient1_utxos[0];
    println!("Using UTXO: {} with amount: {} satoshis", utxo_outpoint, utxo_amount_sats);
    // Create the input for the transaction
    let txin = TxIn {
        previous_output: *utxo_outpoint,
        script_sig: ScriptBuf::new() ,
        sequence: Sequence::MAX,
        witness: Witness::default(),
    };
    // Create the output for the transaction (send all minus fee)
    let txout = TxOut {
        value: Amount::from_sat(*utxo_amount_sats) - feerate,
        script_pubkey: htlc.address.script_pubkey(),
    };
    // Create the transaction
    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![txin],
        output: vec![txout],
    };

    let redeem_amount = Amount::from_sat(*utxo_amount_sats) - feerate;

    // Sign the transaction
    // For P2WPKH, we need to create a signature using the proper sighash
    let witness_script = recipient1_address.script_pubkey();
    let sighash_type = EcdsaSighashType::All;

    // Create a sighash cache for efficient signature hash computation
    let mut sighash_cache = SighashCache::new(&tx);

    // Compute the sighash for the first input
    let sighash = sighash_cache.p2wpkh_signature_hash(
        0, // Input index
        &witness_script, // The script being spent
        Amount::from_sat(*utxo_amount_sats), // Value of the output being spent
        sighash_type
    ).unwrap();

    // Sign the sighash with the private key
    let msg = Message::from_digest_slice(&sighash[..])?;
    let signature = secp.sign_ecdsa(&msg, &private_key_recipient.inner);

    // Serialize the signature with the sighash type appended
    let mut signature_serialized = signature.serialize_der().to_vec();
    signature_serialized.push(sighash_type as u8);

    // Create the witness
    let mut witness = Witness::new();
    witness.push(signature_serialized);
    witness.push(compressed_public_key_recipient.to_bytes().to_vec());

    // Set the witness data for our transaction
    tx.input[0].witness = witness;

    // Print the transaction hex for inspection
    let tx_hex = serialize_hex(&tx);
    println!("Signed transaction hex (recipient1 -> recipient2): {}", tx_hex);

    // Broadcast the transaction to the network
    let txid_prv = rpc.send_raw_transaction(&tx)?;
    println!("Transaction successfully broadcast! TXID: {}", txid);

    // Mine a block to confirm the transaction
    let block_hashes = rpc.generate_to_address(1, &minner_address)?;
    println!("Mined a block to confirm the second transaction: {}", block_hashes.last().unwrap());

    // Check balances of both recipients
    let balance_recipient1 = get_address_balance_scan(&rpc, &recipient1_address).unwrap();
    let htlc_contract_balance = get_address_balance_scan(&rpc, &htlc.address).unwrap();
    println!("Final balance of recipient1: {} BTC", balance_recipient1);
    println!("Final balance of htlc_contract: {} BTC", htlc_contract_balance);

    // //***************** redeeming ******************
    // let redeem_hex = redeem_taproot_htlc(&htlc, preimage, receiver_private_key, txid_prv,redeem_amount,&recipient1_address  ).unwrap();
    // let txid = rpc.send_raw_transaction(&redeem_hex)?;
    // println!("Transaction successfully broadcast! TXID: {}", txid);

    // //Mining one block
    // let block_hashes = rpc.generate_to_address(1, &minner_address)?;
    // println!("Mined a block to confirm the redeem transaction: {}", block_hashes.last().unwrap());

    //Checking Balance 
    let htlc_balance = get_address_balance_scan(&rpc, &htlc.address).unwrap();
    let redeem_balance = get_address_balance_scan(&rpc,&recipient1_address).unwrap();

    println!("balance of htlc contract {}",htlc_balance);
    println!("balance of the redeem_balance: {}",redeem_balance);

    //******************** Refund *******************
    //Mining to block to test refund
    let block_hashes = rpc.generate_to_address(6, &minner_address)?;
    let refund_hex = refund_taproot_htlc(&htlc, sender_private_key,txid_prv,redeem_amount, &recipient1_address).unwrap();
    let txid = rpc.send_raw_transaction(&refund_hex)?;
    println!("Transaction successfully broadcast! TXID: {}", txid);
    //adding refund trc to the block 
    let block_hashes = rpc.generate_to_address(1, &minner_address)?;
    //Checking balance 
    let htlc_balance = get_address_balance_scan(&rpc, &htlc.address).unwrap();
    let refund_balance = get_address_balance_scan(&rpc,&recipient1_address).unwrap();
    println!("balance of htlc contract {}",htlc_balance);
    println!("balance of the refund_balance: {}",refund_balance);
    Ok(())
}



fn create_taproot_htlc(secret_hash: &str, sender_pubkey: &str, receiver_pubkey: &str) -> Option<TaprootHTLC> {
    let secp = Secp256k1::new();

    // Parse sender and receiver X-only public keys (32 bytes)
    let sender_xonly = XOnlyPublicKey::from_str(sender_pubkey).expect("Invalid sender pubkey");
    let receiver_xonly = XOnlyPublicKey::from_str(receiver_pubkey).expect("Invalid receiver pubkey");

    // Use an unspendable internal key (NUMS point)
    let internal_key = XOnlyPublicKey::from_str("0000000000000000000000000000000000000000000000000000000000000001")
        .expect("Invalid NUMS point");

    // Redeem script: OP_SHA256 <secret_hash> OP_EQUALVERIFY <receiver_pubkey> OP_CHECKSIG
    // let redeem_script_hex = format!("a820{}87{}ac", secret_hash, receiver_pubkey);
    // let redeem_script_bytes = hex::decode(redeem_script_hex).expect("Invalid redeem script hex");
    // let redeem_script = ScriptBuf::from_bytes(redeem_script_bytes);

    let redeem_script_builder = ScriptBuf::builder()
    .push_opcode(opcodes::all::OP_SHA256)
    .push_slice(PushBytesBuf::try_from(hex::decode(secret_hash).expect("Invalid secret hash hex")).unwrap())
    .push_opcode(opcodes::all::OP_EQUALVERIFY)
    .push_x_only_key(&receiver_xonly)
    .push_opcode(opcodes::all::OP_CHECKSIG);

    let redeem_script = redeem_script_builder.into_script();
    println!("Redeem_Script : {}",redeem_script);




    // Refund script: <timelock> OP_CHECKSEQUENCEVERIFY OP_DROP <sender_pubkey> OP_CHECKSIG
    // let refund_script_hex = format!("030e0040b27520{}ac", sender_pubkey); // 14 units timelock (~2 hours)
    // let refund_script_hex = format!("03010000b27520{}ac", sender_pubkey);
    // let refund_script_bytes = hex::decode(refund_script_hex).expect("Invalid refund script hex");
    // let refund_script = ScriptBuf::from_bytes(refund_script_bytes)

    let lock_time = 7; //Redeem at 7 blocks or 7*512 seconds
    let refund_script_builder = ScriptBuf::builder()
    .push_int(lock_time)
    .push_opcode(opcodes::all::OP_CSV)
    .push_opcode(opcodes::all::OP_DROP)
    .push_x_only_key(&sender_xonly)
    .push_opcode(opcodes::all::OP_CHECKSIG);

    let refund_script = refund_script_builder.into_script();
    println!("Refundscrip : {}",refund_script);
    // Create TapLeaf hashes for both scripts
    let leaf_version = LeafVersion::TapScript;
    let redeem_leaf = TapNodeHash::from_script(&redeem_script, leaf_version);
    let refund_leaf = TapNodeHash::from_script(&refund_script, leaf_version);

    // Compute Merkle root from the two leaf hashes
    let merkle_root = TapNodeHash::from_node_hashes(redeem_leaf, refund_leaf);

    // Tweak the internal key with the Merkle root to get the final Taproot output key
    let (tweaked_public_key, parity) = internal_key.tap_tweak(&secp, Some(merkle_root));
    let address = Address::p2tr_tweaked(tweaked_public_key, KnownHrp::Regtest);

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

fn redeem_taproot_htlc(htlc: &TaprootHTLC, preimage: &str, receiver_private_key: &str,prev_txid:Txid, amount:Amount, transfer_to_address:&Address) -> Option<Transaction> {
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
    let prevout_txid = prev_txid;
    let prevout = OutPoint::new(prevout_txid, 0);
    let input = TxIn {
        previous_output: prevout,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::default(),
    };


    let output = TxOut {
        value: amount - Amount::from_sat(1000), // 0.001 BTC
        script_pubkey: transfer_to_address.script_pubkey(),
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
            value: amount, // Previous output amount
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
    witness.push(signature.as_ref());    
    witness.push(preimage.as_bytes());  
    witness.push(htlc.redeem_script.to_bytes());   
    witness.push(&control_block.serialize());     

    tx.input[0].witness = witness;

    // let tx_hex = bitcoin::consensus::encode::serialize_hex(&tx);
    // println!("redeem hex : {}",tx_hex);
    
    return Some(tx); // Placeholder return (could return the output address if needed)
}

fn refund_taproot_htlc(htlc: &TaprootHTLC, sender_private_key: &str,prev_txid:Txid, refund_amount: Amount,redeem_to_address:&Address) -> Option<Transaction> {
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
    let prevout_txid = prev_txid;
    let prevout = OutPoint::new(prevout_txid, 0);
    let input = TxIn {
        previous_output: prevout,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::from_height(7), // Note: Should reflect timelock in practice
        witness: Witness::default(),
    };

    let output = TxOut {
        value: refund_amount-Amount::from_sat(1000), // 0.001 BTC
        script_pubkey: redeem_to_address.script_pubkey(),
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
            value: refund_amount, // Previous output amount
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


    // let tx_hex = bitcoin::consensus::encode::serialize_hex(&tx);
    // println!("tx_hex {}",tx_hex);

    return Some(tx);
}



