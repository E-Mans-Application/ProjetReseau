use std::collections::hash_map::ValuesMut;
use std::collections::VecDeque;
use std::hash::Hash;
use std::iter::FromIterator;

/// A `HashMap` that retains the order of insertion of the items.
/// The order of insertion is used only when `pop`ing the oldest item.
/// It is ignored when iterating over the map in order to keep the same
/// complexity as the standard `HashMap`.
///
/// Only the methods used in the project are implemented.
pub struct QueuedMap<K, V> {
    queue: VecDeque<K>,
    map: std::collections::HashMap<K, V>,
}

impl<K: Clone + Eq + Hash, V> QueuedMap<K, V> {
    /// Creates an empty `QueuedMap`, with an initial capacity of 0.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self {
            queue: std::collections::VecDeque::new(),
            map: std::collections::HashMap::new(),
        }
    }

    /// Tries to insert a key-value pair into the map.
    /// Returns `true` if the insertion is successful.
    /// If the key is already in the map, nothing is updated and
    /// this function returns `false`.
    ///
    /// ### Complexity:
    /// `O(1)` amortized.
    #[inline]
    pub fn try_insert(&mut self, key: K, value: V) -> bool {
        if self.map.try_insert(key.clone(), value).is_ok() {
            self.queue.push_back(key);
            true
        } else {
            false
        }
    }

    /// Returns an iterator visiting all the values mutably in arbitrary order.
    ///
    /// ### Complexity:
    /// `O(capacity)`
    #[inline]
    pub fn values_mut(&mut self) -> ValuesMut<'_, K, V> {
        self.map.values_mut()
    }

    /// Retains only the elements specified by the predicate.
    /// In other words, removes all pairs `(k, v)` for which `f(&k, &mut v)` returns `false`.
    /// The elements are visited in unsorted (and unspecified) order.
    ///
    /// ### Complexity:
    /// `O(capacity)`
    #[inline]
    pub fn retain<F: Fn(&K, &mut V) -> bool>(&mut self, f: F) {
        let map = &mut self.map;
        map.retain(f);
        self.queue.retain(|k| map.contains_key(k));
    }

    /// Returns a mutable reference to the value corresponding to the key,
    /// or `None` if the key is not present in the map.
    ///
    /// ### Complexity:
    /// `O(1)` amortized
    #[inline]
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.map.get_mut(key)
    }

    /// Removes the oldest item from the map and returns the
    /// corresponding key-value pair, or returns `None` if the map
    /// is empty.
    ///
    /// The oldest item is that which was inserted in the map before all the others.
    ///
    /// ### Complexity:
    /// `O(1)` amortized
    #[inline]
    pub fn pop_oldest(&mut self) -> Option<(K, V)> {
        if let Some(k) = self.queue.pop_front() {
            self.map.remove(&k).map(|v| (k, v))
        } else {
            None
        }
    }

    /// Returns the number of elements in the map.
    ///
    /// ### Complexity:
    /// `O(1)`
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        debug_assert!(self.map.len() == self.queue.len());
        debug_assert!(
            std::collections::HashSet::<&K>::from_iter(self.map.keys())
                == std::collections::HashSet::from_iter(self.queue.iter())
        );
        self.map.len()
    }

    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl<K: Clone + Eq + Hash, V> Default for QueuedMap<K, V> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
