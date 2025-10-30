// Example: Complete Bitcoin ↔ Pluribit atomic swap
// 
// This shows the full flow for a trustless cross-chain trade.

use pluribit_core::*;

fn main() {
    println!("=== Bitcoin ↔ Pluribit Atomic Swap Example ===\n");
    
    // Setup
    let alice_secret = mimblewimble::generate_secret_key();
    let bob_secret = mimblewimble::generate_secret_key();
    let bob_pubkey = (&bob_secret * &mimblewimble::PC_GENS.B_blinding)
        .compress()
        .to_bytes()
        .to_vec();
    
    // Bitcoin RPC (connect to your node or use public endpoint)
    let bitcoin_rpc = atomic_swap::BitcoinRPC::new(
        "https://blockstream.info/testnet/api".to_string()
    );
    
    println!("Step 1: Alice initiates swap");
    println!("  Offering: 100 PLB");
    println!("  Wants: 10,000 sats\n");
    
    let mut swap = atomic_swap::AtomicSwap::initiate(
        &alice_secret,
        100_000_000, // 100 PLB
        bob_pubkey.clone(),
        10_000,      // 10,000 sats
        144          // ~24 hours
    ).unwrap();
    
    println!("  ✓ Swap ID: {}", hex::encode(&swap.swap_id[..8]));
    println!("  ✓ Secret hash: {}", hex::encode(&swap.secret_hash));
    println!("  ✓ State: {:?}\n", swap.state);
    
    // Alice shares swap details with Bob off-chain (Discord, Signal, etc.)
    
    println!("Step 2: Bob creates Bitcoin HTLC");
    println!("  Bob creates P2WSH HTLC locked to secret hash\n");
    
    // Bob's Bitcoin keys (in real usage)
    let bob_btc_pubkey = [2u8; 33]; // Bob's compressed pubkey
    let alice_btc_pubkey = [3u8; 33]; // Alice's compressed pubkey
    
    let htlc = atomic_swap::BitcoinHTLC::create(
        &swap.secret_hash,
        &alice_btc_pubkey,  // Alice can claim with secret
        &bob_btc_pubkey,    // Bob can refund after timeout
        144                 // CSV timeout
    );
    
    println!("  ✓ HTLC Script: {} bytes", htlc.script.len());
    println!("  ✓ HTLC Address: {}", htlc.address);
    
    // Bob funds the HTLC (using bitcoin-cli or wallet)
    println!("\n  Bob runs: bitcoin-cli sendtoaddress {} 0.0001", htlc.address);
    println!("  Bob gets txid: abc123def456...\n");
    
    println!("Step 3: Bob responds to swap");
    swap.respond(
        &bob_secret,
        htlc.address.clone(),
        "abc123def456".to_string(), // Bitcoin funding txid
        0,                           // vout index
        vec![0u8; 64],              // Bob's adaptor sig (simplified)
        144
    ).unwrap();
    
    println!("  ✓ Bob committed Bitcoin");
    println!("  ✓ State: {:?}", swap.state);
    println!("  ✓ Progress: {}%\n", swap.progress());
    
    println!("Step 4: Alice creates adaptor signature");
    let alice_adaptor_sig = swap.alice_create_adaptor_signature(&alice_secret).unwrap();
    
    println!("  ✓ Adaptor signature created");
    println!("  ✓ Alice shares signature with Bob\n");
    
    println!("Step 5: Bob claims Pluribit (reveals secret)");
    let bob_receive = (&bob_secret * &mimblewimble::PC_GENS.B_blinding);
    
    // Bob needs the adaptor secret (he learns it from Alice's adaptor sig)
    let adaptor_secret_scalar = if let Some(secret_bytes) = swap.adaptor_secret {
        curve25519_dalek::scalar::Scalar::from_bytes_mod_order(secret_bytes)
    } else {
        panic!("No adaptor secret");
    };
    
    let claim_tx = swap.bob_claim(
        &bob_secret,
        &adaptor_secret_scalar,
        &bob_receive
    ).unwrap();
    
    println!("  ✓ Bob created claim transaction");
    println!("  ✓ Transaction reveals secret!");
    println!("  ✓ Bob broadcasts to Pluribit network\n");
    
    println!("Step 6: Alice extracts secret from Bob's transaction");
    // Alice watches blockchain, sees Bob's claim transaction
    let bob_completed_sig = adaptor_secret_scalar; // From Bob's tx kernel
    
    let secret = swap.alice_extract_and_claim(&bob_completed_sig).unwrap();
    
    println!("  ✓ Alice extracted secret: {}", hex::encode(secret.to_bytes()));
    println!("  ✓ State: {:?}", swap.state);
    println!("  ✓ Progress: {}%\n", swap.progress());
    
    println!("Step 7: Alice claims Bitcoin with secret");
    let bitcoin_claim_tx = swap.create_bitcoin_claim_tx(
        &secret.to_bytes(),
        "tb1qaliceaddress",
        1000  // 1000 sat fee
    ).unwrap();
    
    println!("  ✓ Alice creates Bitcoin claim transaction");
    println!("  ✓ Claim tx version: {}", bitcoin_claim_tx.version);
    println!("  ✓ Claim tx outputs: {}", bitcoin_claim_tx.outputs.len());
    println!("  ✓ Output amount: {} sats", bitcoin_claim_tx.outputs[0].amount);
    
    // Serialize and broadcast
    let tx_hex = hex::encode(bitcoin_claim_tx.serialize());
    println!("  ✓ Transaction hex: {}... ({} bytes)", &tx_hex[..40], tx_hex.len() / 2);
    println!("  Alice runs: bitcoin-cli sendrawtransaction {}\n", tx_hex);
    
    println!("Step 8: Swap completed! ✅");
    println!("  Bob received: 100 PLB");
    println!("  Alice received: 10,000 sats");
    println!("  No trust required!");
    println!("  No intermediary!");
    println!("  Atomic execution!\n");
    
    // Save swap for recovery
    let json = swap.to_json().unwrap();
    std::fs::write("swap.json", json).unwrap();
    println!("  ✓ Swap saved to swap.json for recovery\n");
    
    println!("=== Refund Example (if Bob doesn't respond) ===\n");
    
    // If Bob never responds, Alice can refund Pluribit after timeout
    let alice_receive = (&alice_secret * &mimblewimble::PC_GENS.B_blinding);
    let current_height = 1000; // Assume timeout reached
    
    if current_height >= swap.alice_timeout_height {
        let refund_tx = swap.refund_alice(
            &alice_secret,
            &alice_receive,
            current_height
        ).unwrap();
        
        println!("  ✓ Alice created Pluribit refund transaction");
        println!("  ✓ Alice gets her 100 PLB back");
    }
    
    // Bob can also refund his Bitcoin after timeout
    if current_height >= swap.bob_timeout_height {
        let bob_refund_tx = swap.bob_refund_bitcoin(
            "tb1qbobaddress",
            1000,  // 1000 sat fee
            current_height
        ).unwrap();
        
        println!("  ✓ Bob created Bitcoin refund transaction");
        println!("  ✓ Bob gets his {} sats back", bob_refund_tx.outputs[0].amount);
        
        let tx_hex = hex::encode(bob_refund_tx.serialize());
        println!("  Bob runs: bitcoin-cli sendrawtransaction {}\n", tx_hex);
    }
    
    println!("  ✓ Both parties can safely refund after timeout\n");
    
    println!("=== Complete! ===");
    println!("\nTo use with real Bitcoin:");
    println!("1. Run a Bitcoin testnet node");
    println!("2. Or use Blockstream API: https://blockstream.info/testnet/api");
    println!("3. Replace placeholder bitcoin-cli commands with real calls");
    println!("4. Use proper Bitcoin library for tx creation\n");
}

// Additional helper for Bitcoin integration
fn example_bitcoin_rpc_usage() {
    println!("=== Bitcoin RPC Example ===\n");
    
    // Connect to local Bitcoin Core
    let rpc = atomic_swap::BitcoinRPC::with_auth(
        "http://localhost:18332".to_string(),  // testnet
        "user".to_string(),
        "password".to_string()
    );
    
    // Get current block height
    match rpc.get_block_count() {
        Ok(height) => println!("Current Bitcoin height: {}", height),
        Err(e) => println!("Failed to get block height: {}", e),
    }
    
    // Get transaction
    let txid = "abc123...";
    match rpc.get_raw_transaction(txid) {
        Ok(tx_hex) => println!("Transaction: {} bytes", tx_hex.len()),
        Err(e) => println!("Failed to get transaction: {}", e),
    }
    
    // Send transaction
    let tx_hex = "01000000...";
    match rpc.send_raw_transaction(tx_hex) {
        Ok(txid) => println!("Sent transaction: {}", txid),
        Err(e) => println!("Failed to send transaction: {}", e),
    }
}
