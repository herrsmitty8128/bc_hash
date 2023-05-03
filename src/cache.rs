use std::collections::HashMap;
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

    pub fn clear(&mut self) {
        self.map.clear();
        self.heap.clear();
    }

    /* private function to compare two keys on the min heap */
    fn compare(&self, a: usize, b: usize) -> Option<Ordering> {
        Some(self.map.get(&(a as u64))?.cmp(self.map.get(&(b as u64))?))
    }

    pub fn lookup(&mut self, block_num: u64) -> Option<&[u8; BLOCK_SIZE]> {
        match self.map.get_mut(&block_num) {
            Some(item) => {
                let timestamp: Instant = Instant::now();
                item.set_timestamp(timestamp);
                Some(item.item())
            }
            None => None,
        }
    }

    fn extract(&mut self) -> Option<()> {
        if self.heap.is_empty() {
            None
        } else {
            let mut p: usize = 0;
            self.map.remove(&self.heap.swap_remove(p))?.item();
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
    }

    // need to cover the option on line 158

    pub fn insert(&mut self, block_num: u64, block: [u8; BLOCK_SIZE]) -> Option<()> {
        match self.map.get_mut(&block_num) {
            Some(item) => {
                let timestamp: Instant = Instant::now();
                item.set_timestamp(timestamp);
                None
            }
            None => {
                if self.map.len() >= self.capacity {
                    self.extract()?;
                }
                let mut c: usize = self.heap.len(); // get the index of the new child node
                self.heap.push(block_num); // push the new item on the heap
                self.map.insert(block_num, TimestampedItem::new(block));
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
            },
        }
    }

    /*
    pub fn put(&mut self, k: K, v: V) -> error::Result<()> {
        if !self.map.contains_key(&k) {
            if self.map.len() >= self.capacity {
                if let Some(item) = self.heap.extract() {
                    self.map.remove(&item.item());
                }
            }
            let item: TimestampedItem<K> = TimestampedItem::new(k);
            self.map.insert(k, item);
            self.heap.insert(&item);
            Ok(())
        } else {
            Err(error::Error::new(
                error::ErrorKind::Other,
                "Key already exists in the cache",
            ))
        }
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        match self.map.get(key) {
            Some(item) => {
                let timestamp: Instant = Instant::now();
                item.set_timestamp(timestamp);
                Some(item)
            }
            None => None,
        }
    }
    */
}
