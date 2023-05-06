// Copyright (c) 2023 herrsmitty8128
// Distributed under the MIT software license, see the accompanying
// file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

use std::cmp::{Ordering, PartialOrd};
use std::collections::{HashMap, hash_map};
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct MapItem<const BLOCK_SIZE: usize> {
    heap_idx: usize, // the index on the heap
    block: [u8; BLOCK_SIZE],
}

#[derive(Debug, Clone)]
struct HeapItem {
    timestamp: Instant, // the last time the block was requested
    block_num: u64,
}

impl PartialEq for HeapItem {
    fn eq(&self, other: &Self) -> bool {
        self.timestamp == other.timestamp
    }
}

impl Eq for HeapItem {}

impl PartialOrd for HeapItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }

    fn ge(&self, other: &Self) -> bool {
        self.timestamp >= other.timestamp
    }

    fn gt(&self, other: &Self) -> bool {
        self.timestamp > other.timestamp
    }

    fn lt(&self, other: &Self) -> bool {
        self.timestamp < other.timestamp
    }

    fn le(&self, other: &Self) -> bool {
        self.timestamp <= other.timestamp
    }
}

impl Ord for HeapItem {
    fn cmp(&self, other: &Self) -> Ordering {
        self.timestamp.cmp(&other.timestamp)
    }
}

#[derive(Debug, Clone)]
pub struct Cache<const BLOCK_SIZE: usize> {
    heap: Vec<HeapItem>,
    map: HashMap<u64, MapItem<BLOCK_SIZE>>,
    capacity: usize,
}

impl<const BLOCK_SIZE: usize> Cache<BLOCK_SIZE> {
    pub fn new(capacity: usize) -> Self {
        Self {
            heap: Vec::new(),
            map: HashMap::new(),
            capacity,
        }
    }

    pub fn iter(&self) -> hash_map::Iter<'_, u64, MapItem<BLOCK_SIZE>> {
        self.map.iter()
    }

    pub fn count(&self) -> usize {
        self.map.len()
    }

    pub fn clear(&mut self) {
        self.map.clear();
        self.heap.clear();
    }

    /// Private function to sort the heap by going down the tree starting from index ```p```.
    fn sort_down(&mut self, mut p: usize) -> Option<()> {
        if p < self.heap.len() {
            let length: usize = self.heap.len();
            loop {
                let left: usize = (p * 2) + 1;
                let right: usize = left + 1;
                let mut s: usize = if left < length && self.heap[left] < self.heap[p] {
                    left
                } else {
                    p
                };
                if right < length && self.heap[right] < self.heap[s] {
                    s = right;
                }
                if s == p {
                    break;
                }
                self.map.get_mut(&self.heap[p].block_num).unwrap().heap_idx = s;
                self.map.get_mut(&self.heap[s].block_num).unwrap().heap_idx = p;
                self.heap.swap(p, s);
                p = s;
            }
            Some(())
        } else {
            None
        }
    }

    /// Private function to sort the heap by going up the tree starting from index ```c```.
    fn sort_up(&mut self, mut c: usize) -> Option<()> {
        if c < self.heap.len() {
            while c > 0 {
                let p: usize = (c - 1) >> 1; // calculate the index of the parent node
                if self.heap[c] < self.heap[p] {
                    self.map.get_mut(&self.heap[c].block_num).unwrap().heap_idx = p;
                    self.map.get_mut(&self.heap[p].block_num).unwrap().heap_idx = c;
                    self.heap.swap(c, p); // if the child is smaller than the parent then swap them
                } else {
                    break;
                }
                c = p;
            }
            Some(())
        } else {
            None
        }
    }

    pub fn get(&mut self, block_num: u64) -> Option<&[u8; BLOCK_SIZE]> {
        match self.map.get_mut(&block_num) {
            Some(item) => {
                self.heap[item.heap_idx].timestamp = Instant::now();
                Some(&item.block)
            }
            None => None,
        }
    }

    #[allow(clippy::map_entry)]
    pub fn put(&mut self, block_num: u64, block: &[u8; BLOCK_SIZE]) -> Option<()> {
        if self.map.contains_key(&block_num) {
            None
        } else {
            let heap_idx: usize = self.heap.len(); // get the index of the new child node
            self.heap.push(HeapItem {
                timestamp: Instant::now(),
                block_num,
            });
            self.map.insert(
                block_num,
                MapItem {
                    heap_idx,
                    block: *block,
                },
            );
            self.sort_up(heap_idx)?;
            if self.map.len() > self.capacity {
                self.map.remove(&self.heap.swap_remove(0).block_num)?;
                self.sort_down(0)
            } else {
                None
            }
        }
    }
}
