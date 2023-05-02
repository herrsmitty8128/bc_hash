use std::collections::HashMap;
use std::hash::Hash;
use std::time::Instant;
use crate::heap::{MinHeap, TimestampedItem};
use crate::error;

#[derive(Debug, Clone)]
pub struct Cache<K, V>
where
    K: Default + Clone + Eq + Hash,
    V: Default + Clone + Ord,
{
    heap: MinHeap<&TimestampedItem<K>>,
    map: HashMap<K, TimestampedItem<V>>,
    capacity: usize,
}

impl<K, V> Cache<K, V>
where
    K: Default + Clone + Eq + Hash,
    V: Default + Clone + Ord,
{
    pub fn new(capacity: usize) -> Self {
        Self{
            heap: MinHeap::default(),
            map: HashMap::new(),
            capacity
        }
    }

    pub fn count(&self) -> usize {
        self.map.len()
    }

    pub fn put(&mut self, k: K, v: V) -> error::Result<()> {
        if !self.map.contains_key(&k){
            if self.map.len() >= self.capacity {
                if let Some(item) = self.heap.extract() {
                    self.map.remove(&item.item());
                }
            }
            let item: TimestampedItem<K> = TimestampedItem::new(k);
            self.map.insert(k,item);
            self.heap.insert(&item);
            Ok(())
        } else {
            Err(error::Error::new(error::ErrorKind::Other, "Key already exists in the cache"))
        }
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        match self.map.get(key) {
            Some(item) => {
                let timestamp: Instant = Instant::now();
                item.set_timestamp(timestamp);
                Some(item)
            },
            None => None,
        }
    }
}