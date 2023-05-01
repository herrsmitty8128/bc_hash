use std::cmp::{PartialOrd, Ordering};
use std::time::Instant;


pub struct TimestampedItem<T> where T: Default + Clone {
    timestamp: Instant, // the last time the block was requested
    item: T,
}

impl<T> TimestampedItem<T> where T: Default + Clone {
    pub fn new(item: T) -> Self {
        Self {
            timestamp: Instant::now(),
            item,
        }
    }
}

impl<T> PartialEq for TimestampedItem<T> where T: Default + Clone {
    fn eq(&self, other: &Self) -> bool {
        self.timestamp == other.timestamp
    }
}

impl<T> Eq for TimestampedItem<T> where T: Default + Clone {}

impl<T> PartialOrd for TimestampedItem<T> where T: Default + Clone {
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

impl<T> Ord for TimestampedItem<T> where T: Default + Clone {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.timestamp > other.timestamp {
            Ordering::Greater
        } else if self.timestamp < other.timestamp {
            Ordering::Less
        } else {
            Ordering::Equal
        }
    }
}

pub struct MinHeap<T>
where
    T: Ord,
{
    heap: Vec<T>, // The buffer of nodes
}

impl<T> Default for MinHeap<T> where T: Ord + Clone {
    fn default() -> Self {
        Self { heap: Vec::new() }
    }
}

impl<T> MinHeap<T>
where
    T: Ord + Clone,
{
    pub fn new<I>(iter: I) -> Self where I: Iterator<Item = T> + Copy {
        let mut heap = Vec::from_iter(iter);
        heap.sort();
        Self{ heap }
    }

    pub fn count(&self) -> usize {
        self.heap.len()
    }

    pub fn extract(&mut self) -> Option<T> {
        if self.heap.is_empty() {
            None
        } else {
            let x: T = self.heap.swap_remove(0);
            self.heapify(0);
            Some(x)
        }
    }

    pub fn insert(&mut self, item: T) {
        self.heap.push(item);
        self.heapify(self.heap.len() - 1);
    }

    fn heapify(&mut self, i: usize) {
        let l: usize = Self::left(i);
        let r: usize = Self::right(i);

        let mut smallest: usize = if l < self.heap.len() && self.heap[l] < self.heap[i] {
            l
        } else {
            i
        };

        if r < self.heap.len() && self.heap[r] < self.heap[smallest] {
            smallest = r;
        }

        if smallest != i {
            self.heap.swap(i, smallest);
            self.heapify(smallest);
        }
    }

    #[inline]
    fn left(index: usize) -> usize {
        (index * 2) + 1
    }

    #[inline]
    fn right(index: usize) -> usize {
        (index * 2) + 2
    }
}
