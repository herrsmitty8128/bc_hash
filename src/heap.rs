use std::cmp::{Ordering, PartialOrd};
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct TimestampedItem<T>
where
    T: Default + Clone,
{
    timestamp: Instant, // the last time the block was requested
    item: T,
}

impl<T> TimestampedItem<T>
where
    T: Default + Clone,
{
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

impl<T> PartialEq for TimestampedItem<T>
where
    T: Default + Clone,
{
    fn eq(&self, other: &Self) -> bool {
        self.timestamp == other.timestamp
    }
}

impl<T> Eq for TimestampedItem<T> where T: Default + Clone {}

impl<T> PartialOrd for TimestampedItem<T>
where
    T: Default + Clone,
{
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

impl<T> Ord for TimestampedItem<T>
where
    T: Default + Clone,
{
    fn cmp(&self, other: &Self) -> Ordering {
        self.timestamp.cmp(&other.timestamp)
    }
}

#[derive(Debug, Clone)]
pub struct MinHeap<T>
where
    T: Ord + Clone,
{
    heap: Vec<T>,
}

impl<T> Default for MinHeap<T>
where
    T: Ord + Clone,
{
    fn default() -> Self {
        Self { heap: Vec::new() }
    }
}

impl<T> MinHeap<T>
where
    T: Ord + Clone,
{
    pub fn new<I>(iter: I) -> Self
    where
        I: Iterator<Item = T>,
    {
        let mut heap = Vec::from_iter(iter);
        heap.sort();
        Self { heap }
    }

    pub fn count(&self) -> usize {
        self.heap.len()
    }

    pub fn clear(&mut self) {
        self.heap.truncate(0)
    }

    pub fn iter(&self) -> std::slice::Iter<'_, T> {
        self.heap.iter()
    }

    pub fn extract(&mut self) -> Option<T> {
        if self.heap.is_empty() {
            None
        } else {
            let mut p: usize = 0;
            let removed_item: T = self.heap.swap_remove(p);
            let length: usize = self.heap.len();
            loop {
                let left: usize = (p * 2) + 1;
                let right: usize = left + 1;
                let mut smallest: usize = if left < length && self.heap[left] < self.heap[p] {
                    left
                } else {
                    p
                };
                if right < length && self.heap[right] < self.heap[smallest] {
                    smallest = right;
                }
                if smallest == p {
                    break;
                }
                self.heap.swap(p, smallest);
                p = smallest;
            }
            Some(removed_item)
        }
    }

    pub fn insert(&mut self, item: T) {
        let mut c: usize = self.heap.len(); // get the index of the new child node
        self.heap.push(item); // push the new item on the heap
        while c > 0 {
            let p: usize = (c - 1) >> 1; // calculate the index of the parent node
            if self.heap[c] < self.heap[p] {
                // if the child is smaller than the parent
                self.heap.swap(c, p); // then swap them
            } else {
                break;
            }
            c = p;
        }
    }
}
