// native/src/lib.rs
use neon::prelude::*;
use neon::types::JsBigInt;
use pluribit_core::vdf::VDF;
use pluribit_core::wasm_types::WasmU64;

mod db;
mod mining_loop;

fn perform_vdf_computation(mut cx: FunctionContext) -> JsResult<JsObject> {
    // 1. Get arguments
    let input_str = cx.argument::<JsString>(0)?.value(&mut cx);
    let iterations_handle = cx.argument::<JsValue>(1)?;

    let iterations: u64 = if let Ok(js_bigint) = iterations_handle.downcast::<JsBigInt, _>(&mut cx) {
        match js_bigint.to_u64(&mut cx) {
            Ok(val) => {
                // If Ok(), the conversion was successful and lossless.
                val
            },
            Err(_) => return cx.throw_error("Failed to convert BigInt to u64. It may be out of range (e.g., negative or too large)."),
        }
    } else if let Ok(js_number) = iterations_handle.downcast::<JsNumber, _>(&mut cx) {
        js_number.value(&mut cx) as u64
    } else {
        return cx.throw_error("Second argument 'iterations' must be a Number or a BigInt.");
    };

    // 2. Explicitly match the Result to handle errors clearly
    let vdf = match VDF::new_with_default_modulus() {
        Ok(instance) => instance,
        Err(e) => return cx.throw_error(e.to_string()),
    };

    let proof = match vdf.compute_with_proof(input_str.as_bytes(), WasmU64::from(iterations)) {
        Ok(p) => p,
        Err(e) => return cx.throw_error(e.to_string()),
    };

    // 3. Create the JS object to return
    let obj = cx.empty_object();
    let y = cx.string(hex::encode(&proof.y));
    let pi = cx.string(hex::encode(&proof.pi));
    let l = cx.string(hex::encode(&proof.l));
    let r = cx.string(hex::encode(&proof.r));
    let iter = cx.number(*proof.iterations as f64);

    obj.set(&mut cx, "y", y)?;
    obj.set(&mut cx, "pi", pi)?;
    obj.set(&mut cx, "l", l)?;
    obj.set(&mut cx, "r", r)?;
    obj.set(&mut cx, "iterations", iter)?;

    Ok(obj)
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    // VDF function (for mining-worker.js)
    cx.export_function("performVdfComputation", perform_vdf_computation)?;

    // Mining loop function
    cx.export_function("findMiningCandidateBatch", mining_loop::find_mining_candidate_batch)?; 

    // Database functions
    cx.export_function("initializeDatabase", db::initialize_database)?;

    // --- Functions for WASM (src/lib.rs) ---
    cx.export_function("load_block_from_db", db::load_block)?;
    cx.export_function("get_tip_height_from_db", db::get_tip_height)?;
    cx.export_function("save_total_work_to_db", db::save_total_work)?;
    cx.export_function("get_total_work_from_db", db::load_total_work)?;
    cx.export_function("save_utxo", db::save_utxo)?;
    cx.export_function("load_utxo", db::load_utxo)?;
    cx.export_function("delete_utxo", db::delete_utxo)?;
    cx.export_function("clear_all_utxos", db::clear_all_utxos)?;
    cx.export_function("loadAllUtxos", db::load_all_utxos)?; // Also used by worker.js
    cx.export_function("save_coinbase_index", db::save_coinbase_index)?;
    cx.export_function("delete_coinbase_index", db::delete_coinbase_index)?;
    cx.export_function("loadAllCoinbaseIndexes", db::load_all_coinbase_indexes)?; // Also used by worker.js
    cx.export_function("save_block_filter", db::save_block_filter)?;
    cx.export_function("load_block_filter_range", db::load_block_filter_range)?;
    cx.export_function("delete_block_filter", db::delete_block_filter)?;
    cx.export_function("save_reorg_marker", db::save_reorg_marker)?;
    cx.export_function("clear_reorg_marker", db::clear_reorg_marker)?;
    cx.export_function("check_incomplete_reorg", db::check_incomplete_reorg)?;
    cx.export_function("save_block_to_staging", db::save_block_to_staging)?;
    cx.export_function("commit_staged_reorg", db::commit_staged_reorg)?;
    cx.export_function("saveBlockWithHash", db::save_block_with_hash)?; // Also used by worker.js
    cx.export_function("loadBlockByHash", db::load_block_by_hash)?; // Also used by worker.js
    cx.export_function("save_channel", db::save_channel)?;
    cx.export_function("load_channel", db::load_channel)?;
    cx.export_function("save_atomic_swap", db::save_atomic_swap)?;
    cx.export_function("load_atomic_swap", db::load_atomic_swap)?;
    cx.export_function("clear_all_coinbase_indexes", db::clear_all_coinbase_indexes)?;
    
    // --- Functions for JS (worker.js) ---
    // Note: Some of these are duplicates of the above, just with the
    // camelCase names that worker.js expects.
    cx.export_function("saveBlock", db::save_block)?;
    cx.export_function("loadBlock", db::load_block)?;
    cx.export_function("getTipHeight", db::get_tip_height)?;
    cx.export_function("getChainTip", db::get_chain_tip)?;
    cx.export_function("getAllBlocks", db::get_all_blocks)?;
    cx.export_function("loadBlocks", db::load_blocks)?;
    cx.export_function("saveDeferredBlock", db::save_deferred_block)?;
    cx.export_function("loadAllDeferredBlocks", db::load_all_deferred_blocks)?;
    cx.export_function("clearDeferredBlocks", db::clear_deferred_blocks)?;
    cx.export_function("walletExists", db::wallet_exists)?;
    cx.export_function("loadWallet", db::load_wallet)?;
    cx.export_function("saveWallet", db::save_wallet)?;
    cx.export_function("isWalletEncrypted", db::is_wallet_encrypted)?;
    cx.export_function("saveTotalWork", db::save_total_work)?;
    cx.export_function("loadTotalWork", db::load_total_work)?;
    cx.export_function("deleteCanonicalBlock", db::delete_canonical_block)?;
    cx.export_function("setTipMetadata", db::set_tip_metadata)?;
    cx.export_function("saveChannel", db::save_channel)?;
    cx.export_function("loadChannel", db::load_channel)?;
    cx.export_function("saveAtomicSwap", db::save_atomic_swap)?;
    cx.export_function("loadAtomicSwap", db::load_atomic_swap)?;
    cx.export_function("clearAllCoinbaseIndexes", db::clear_all_coinbase_indexes)?;

    Ok(())
}
