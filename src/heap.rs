// Copyright (c) 2023 herrsmitty8128
// Distributed under the MIT software license, see the accompanying
// file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

use std::cmp::{Ord, Ordering};

/// Function to update the heap after removal.
/// Usually starts from index 0 in the heap array
pub fn sort_down<T>(heap: &mut Vec<T>, mut p: usize, order: Ordering)
where
    T: Ord,
{
    let length: usize = heap.len();
    if p < length && order != Ordering::Equal {
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
    };
}

/// Function to update the heap after insert
/// Usually starts from the last index in the heap array
pub fn sort_up<T>(heap: &mut Vec<T>, mut c: usize, order: Ordering)
where
    T: Ord,
{
    if c < heap.len() && order != Ordering::Equal {
        while c > 0 {
            let p: usize = (c - 1) >> 1; // calculate the index of the parent node
            if heap[c].cmp(&heap[p]) == order {
                heap.swap(c, p); // if the child is smaller than the parent, then swap them
            } else {
                break;
            }
            c = p;
        }
    };
}

/// Function to insert an element into a heap.
pub fn insert<T>(heap: &mut Vec<T>, element: T, order: Ordering)
where
    T: Ord,
{
    let c: usize = heap.len();
    heap.push(element);
    sort_up(heap, c, order);
}

/// Function to remove an item from the top of the heap.
pub fn extract<T>(heap: &mut Vec<T>, order: Ordering) -> Option<T>
where
    T: Ord,
{
    if heap.len() > 0 {
        let removed: T = heap.swap_remove(0);
        sort_down(heap, 0, order);
        Some(removed)
    } else {
        None
    }
}

/// Clears the vector, removing all values.
/// Note that this method has no effect on the allocated capacity of the heap.
pub fn clear<T>(heap: &mut Vec<T>)
where
    T: Ord,
{
    heap.clear()
}

/// Searches for an element on the heap and returns a reference to it.
/// Performs a linear search for ```element``` in O(n) time. If the element
/// is found, then it will return its index. Otherwise, it will return None.
pub fn find<T>(heap: &mut Vec<T>, element: &T) -> Option<usize>
where
    T: Ord + Eq,
{
    for i in 0..heap.len() {
        if heap[i] == *element {
            return Some(i);
        }
    }
    None
}

/// Updates a value on the heap.
pub fn update<T>(heap: &mut Vec<T>, element: &T, replace_with: T, order: Ordering) -> Option<()>
where
    T: Ord + Copy,
{
    if let Some(i) = find(heap, element) {
        heap[i] = replace_with;
        if replace_with.cmp(element) == order {
            sort_up(heap, i, order);
        } else {
            sort_down(heap, i, order);
        }
        Some(())
    } else {
        None
    }
}

/// Removes an element from the heap.
pub fn remove<T>(heap: &mut Vec<T>, index: usize, order: Ordering) -> Option<T> where T: Ord {
    if index < heap.len() {
        let removed: T = heap.swap_remove(index);
        sort_down(heap, index, order);
        Some(removed)
    } else {
        None
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
            let removed_item: T = self.heap.swap_remove(0);
            sort_down(&mut self.heap, 0, Ordering::Less);
            Some(removed_item)
        }
    }

    pub fn insert(&mut self, item: T) {
        let c: usize = self.heap.len(); // get the index of the new child node
        self.heap.push(item); // push the new item on the heap
        sort_up(&mut self.heap, c, Ordering::Less);
    }
}
