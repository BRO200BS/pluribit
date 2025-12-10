// src/side_blocks.rs
use std::sync::Mutex;
use std::collections::{HashMap, VecDeque};
use lazy_static::lazy_static;
use crate::block::Block;

lazy_static! {
    /// Side blocks that are not on the current canonical chain (by hash)
    pub static ref SIDE_BLOCKS: Mutex<HashMap<String, Block>> = Mutex::new(HashMap::new());
    pub static ref SIDE_BLOCKS_LRU: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());
}
