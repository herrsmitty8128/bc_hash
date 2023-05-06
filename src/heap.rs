// Copyright (c) 2023 herrsmitty8128
// Distributed under the MIT software license, see the accompanying
// file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

use std::cmp::{Ord, Ordering};
use std::error;
use std::fmt::Display;

#[derive(Debug, Copy, Clone)]
pub enum ErrorKind {
    InvalidIndex,
    InvalidOrdering,
    EmptyHeap,
}

impl Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            ErrorKind::InvalidIndex => f.write_str("Index out of bounds."),
            ErrorKind::InvalidOrdering => f.write_str("Invalid cmp::Ordering."),
            ErrorKind::EmptyHeap => f.write_str("Heap is empty."),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Error {
    kind: ErrorKind,
    message: &'static str,
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{} {}", self.kind, self.message))
    }
}

impl Error {
    pub fn new(kind: ErrorKind, message: &'static str) -> Self {
        Error { kind, message }
    }
}

impl error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeapType {
    MinHeap,
    MaxHeap,
}

/// Function to update the heap after removal.
/// Usually starts from index 0 in the heap array
/// Returns the new index where the element ends up.
/// Panics if p is out of bounds.
fn sort_down<T>(heap: &mut [T], heap_type: HeapType, mut p: usize)
where
    T: Ord,
{
    let order: Ordering = if heap_type == HeapType::MaxHeap {
        Ordering::Greater
    } else {
        Ordering::Less
    };
    let length: usize = heap.len();
    loop {
        let left: usize = (p * 2) + 1;
        let right: usize = left + 1;
        let mut x: usize = if left < length && heap[left].cmp(&heap[p]) == order {
            left
        } else {
            p
        };
        if right < length && heap[right].cmp(&heap[x]) == order {
            x = right;
        }
        if x == p {
            break;
        }
        heap.swap(p, x);
        p = x;
    }
}

/// Private function to update the heap after insert
/// Usually starts from the last index in the heap array
/// Panics if c is out of bounds.
//fn sort_up<T>(heap: &mut Vec<T>, heap_type: HeapType, mut c: usize)
fn sort_up<T>(heap: &mut [T], heap_type: HeapType, mut c: usize)
where
    T: Ord,
{
    let order: Ordering = if heap_type == HeapType::MaxHeap {
        Ordering::Greater
    } else {
        Ordering::Less
    };
    while c > 0 {
        let p: usize = (c - 1) >> 1; // calculate the index of the parent node
        if heap[c].cmp(&heap[p]) == order {
            heap.swap(c, p); // if the child is smaller than the parent, then swap them
        } else {
            break;
        }
        c = p;
    }
}

/// Function to insert an element into a heap.
pub fn insert<T>(heap: &mut Vec<T>, heap_type: HeapType, element: T)
where
    T: Ord,
{
    let c: usize = heap.len();
    heap.push(element);
    sort_up(heap, heap_type, c)
}

/// Function to remove an item from the top of the heap.
pub fn extract<T>(heap: &mut Vec<T>, heap_type: HeapType) -> Result<T>
where
    T: Ord,
{
    remove(heap, heap_type, 0)
}

/// Searches for an element on the heap and returns a reference to it.
/// Performs a linear search for ```element``` in O(n) time. If the element
/// is found, then it will return its index. Otherwise, it will return None.
pub fn find<T>(heap: &[T], element: &T) -> Option<usize>
where
    T: Ord + Eq,
{
    (0..heap.len()).find(|&i| heap[i] == *element)
}

/// Updates a value on the heap.
pub fn update<T>(heap: &mut [T], heap_type: HeapType, element: &T, replace_with: &T) -> Option<()>
where
    T: Ord + Clone,
{
    if let Some(i) = find(heap, element) {
        let order: Ordering = if heap_type == HeapType::MaxHeap {
            Ordering::Greater
        } else {
            Ordering::Less
        };
        heap[i] = replace_with.clone();
        if replace_with.cmp(element) == order {
            sort_up(heap, heap_type, i);
        } else {
            sort_down(heap, heap_type, i);
        }
        Some(())
    } else {
        None
    }
}

/// Removes an element from the heap.
pub fn remove<T>(heap: &mut Vec<T>, heap_type: HeapType, index: usize) -> Result<T>
where
    T: Ord,
{
    if heap.is_empty() {
        Err(Error::new(
            ErrorKind::EmptyHeap,
            "Can not remove elements from an empty heap.",
        ))
    } else if index >= heap.len() {
        Err(Error::new(
            ErrorKind::InvalidIndex,
            "Index is beyond the end of the heap.",
        ))
    } else {
        let removed: T = heap.swap_remove(index);
        sort_down(heap, heap_type, index);
        Ok(removed)
    }
}

/// Performs an in-place heap sort.
pub fn heap_sort<T>(heap: &mut [T], heap_type: HeapType)
where
    T: Ord,
{
    for i in (1..=(heap.len() - 1)).rev() {
        heap.swap(0, i);
        sort_down(heap, heap_type, 0);
    }
}

pub trait Heap<T>
where
    T: Ord + Eq,
{
    fn insert(&mut self, element: T);
    fn extract(&mut self) -> Result<T>;
    fn find(&self, element: &T) -> Option<usize>;
    fn update(&mut self, element: &T, replace_with: &T) -> Option<()>;
    fn remove(&mut self, index: usize) -> Result<T>;
    fn count(&self) -> usize;
    fn truncate(&mut self, len: usize);
    fn clear(&mut self);
}

#[derive(Debug, Clone)]
pub struct MinHeap<T>
where
    T: Ord + Eq + Clone,
{
    heap: Vec<T>,
}

impl<T> Default for MinHeap<T>
where
    T: Ord + Eq + Clone,
{
    fn default() -> Self {
        Self { heap: Vec::new() }
    }
}

impl<T> MinHeap<T>
where
    T: Ord + Eq + Clone,
{
    pub fn new() -> Self {
        Self { heap: Vec::new() }
    }
}

impl<T> Heap<T> for MinHeap<T>
where
    T: Ord + Eq + Clone,
{
    fn clear(&mut self) {
        self.heap.clear()
    }

    fn count(&self) -> usize {
        self.heap.len()
    }

    fn extract(&mut self) -> Result<T> {
        extract(&mut self.heap, HeapType::MinHeap)
    }

    fn find(&self, element: &T) -> Option<usize> {
        find(&self.heap, element)
    }

    fn insert(&mut self, element: T) {
        insert(&mut self.heap, HeapType::MinHeap, element)
    }

    fn remove(&mut self, index: usize) -> Result<T> {
        remove(&mut self.heap, HeapType::MinHeap, index)
    }

    fn truncate(&mut self, len: usize) {
        self.heap.truncate(len)
    }

    fn update(&mut self, element: &T, replace_with: &T) -> Option<()> {
        update(&mut self.heap, HeapType::MinHeap, element, replace_with)
    }
}

#[derive(Debug, Clone)]
pub struct MaxHeap<T>
where
    T: Ord + Eq + Clone,
{
    heap: Vec<T>,
}

impl<T> Default for MaxHeap<T>
where
    T: Ord + Eq + Clone,
{
    fn default() -> Self {
        Self { heap: Vec::new() }
    }
}

impl<T> MaxHeap<T>
where
    T: Ord + Eq + Clone,
{
    pub fn new() -> Self {
        Self { heap: Vec::new() }
    }
}

impl<T> Heap<T> for MaxHeap<T>
where
    T: Ord + Eq + Clone,
{
    fn clear(&mut self) {
        self.heap.clear()
    }

    fn count(&self) -> usize {
        self.heap.len()
    }

    fn extract(&mut self) -> Result<T> {
        extract(&mut self.heap, HeapType::MaxHeap)
    }

    fn find(&self, element: &T) -> Option<usize> {
        find(&self.heap, element)
    }

    fn insert(&mut self, element: T) {
        insert(&mut self.heap, HeapType::MaxHeap, element)
    }

    fn remove(&mut self, index: usize) -> Result<T> {
        remove(&mut self.heap, HeapType::MaxHeap, index)
    }

    fn truncate(&mut self, len: usize) {
        self.heap.truncate(len)
    }

    fn update(&mut self, element: &T, replace_with: &T) -> Option<()> {
        update(&mut self.heap, HeapType::MaxHeap, element, replace_with)
    }
}
