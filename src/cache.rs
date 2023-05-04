// Copyright (c) 2023 herrsmitty8128
// Distributed under the MIT software license, see the accompanying
// file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

use std::collections::HashMap;
use std::collections::hash_map::Iter;
use std::cmp::{Ordering, PartialOrd};
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct TimestampedItem<T> where T: Ord {
    timestamp: Instant, // the last time the block was requested
    item: T,
}

impl<T> TimestampedItem<T> where T: Ord {
    pub fn new(item: T) -> Self {
        Self {
            timestamp: Instant::now(),
            item,
        }
    }

    pub fn set_timestamp(&mut self, timestamp: Instant) {
        self.timestamp = timestamp;
    }

    pub fn timestamp(&self) -> &Instant {
        &self.timestamp
    }

    pub fn set_item(&mut self, item: T) {
        self.item = item;
    }

    pub fn item(&self) -> &T {
        &self.item
    }
}

impl<T> PartialEq for TimestampedItem<T> where T: Ord {
    fn eq(&self, other: &Self) -> bool {
        self.timestamp == other.timestamp
    }
}

impl<T> Eq for TimestampedItem<T> where T: Ord {}

impl<T> PartialOrd for TimestampedItem<T> where T: Ord {
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

impl<T> Ord for TimestampedItem<T> where T: Ord {
    fn cmp(&self, other: &Self) -> Ordering {
        self.timestamp.cmp(&other.timestamp)
    }
}



#[derive(Debug, Clone)]
pub struct Cache<const BLOCK_SIZE: usize> {
    heap: Vec<u64>,
    map: HashMap<u64, TimestampedItem<[u8; BLOCK_SIZE]>>,
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

    pub fn count(&self) -> usize {
        self.map.len()
    }

    pub fn iter(&self) -> Iter<'_, u64, TimestampedItem<[u8; BLOCK_SIZE]>> {
        self.map.iter()
    }

    pub fn clear(&mut self) {
        self.map.clear();
        self.heap.clear();
    }

    /// Private function to compare two keys on the min heap.
    fn compare(&self, a: usize, b: usize) -> Option<Ordering> {
        let b1: u64 = self.heap[a];
        let b2: u64 = self.heap[b];
        Some(self.map.get(&b1)?.cmp(self.map.get(&b2)?))
    }

    /// Private function to update the heap after removal.
    /// Usually starts from index 0 in the heap array
    fn sort_heap_down(&mut self, index: usize) -> Option<()> {
        let mut p: usize = index;
        let length: usize = self.heap.len();
        loop {
            let left: usize = (p * 2) + 1;
            let right: usize = left + 1;
            let mut smallest: usize = if left < length && self.compare(left, p)? == Ordering::Less {
                left
            } else {
                p
            };
            if right < length && self.compare(right, smallest)? == Ordering::Less {
                smallest = right;
            }
            if smallest == p {
                break;
            }
            self.heap.swap(p, smallest);
            p = smallest;
        }
        Some(())
    }

    /// Private function to update the heap after insert
    /// Usually starts from the last index in the heap array
    fn sort_heap_up(&mut self, index: usize) -> Option<()> {
        let mut c: usize = index;
        while c > 0 {
            let p: usize = (c - 1) >> 1; // calculate the index of the parent node
            if self.compare(c, p)? == Ordering::Less {
                // if the child is smaller than the parent
                self.heap.swap(c, p); // then swap them
            } else {
                break;
            }
            c = p;
        }
        Some(())
    }

    pub fn get(&mut self, block_num: u64) -> Option<&[u8; BLOCK_SIZE]> {
        match self.map.get_mut(&block_num) {
            Some(item) => {
                let timestamp: Instant = Instant::now();
                item.set_timestamp(timestamp);
                Some(item.item())
            }
            None => None,
        }
    }

    /// Private function used to remove the oldest block from the cache.
    pub fn del(&mut self) -> Option<()> {
        if self.map.is_empty() {
            None
        } else {
            let index: usize = 0;
            self.map.remove(&self.heap.swap_remove(index))?; //.item();
            self.sort_heap_down(index)
        }
    }

    #[allow(clippy::map_entry)]
    pub fn put(&mut self, block_num: u64, block: [u8; BLOCK_SIZE]) -> Option<()> {
        if self.map.contains_key(&block_num) {
            None
        } else {
            let index: usize = self.heap.len(); // get the index of the new child node
            self.heap.push(block_num); // push the new item on the heap
            self.map.insert(block_num, TimestampedItem::new(block));
            self.sort_heap_up(index)?;
            if self.map.len() > self.capacity {
                self.del()
            } else {
                None
            }
        }
    }
}
