use std::hash::Hash;

use dashmap::DashMap;

pub type FastBuildHasher = ahash::RandomState;
pub type FastMap<K, V> = DashMap<K, V, FastBuildHasher>;
pub type FastMutex<T> = parking_lot::Mutex<T>;

#[inline]
pub fn fast_map<K: Eq + Hash, V>() -> FastMap<K, V> {
    DashMap::with_hasher(FastBuildHasher::new())
}

#[cfg(test)]
mod tests {
    use super::{FastMutex, fast_map};

    #[test]
    fn fast_map_basic_roundtrip() {
        let map = fast_map::<u64, u64>();
        map.insert(7, 11);
        assert_eq!(map.get(&7).map(|value| *value), Some(11));
        assert_eq!(map.remove(&7).map(|(_, value)| value), Some(11));
    }

    #[test]
    fn fast_mutex_basic_roundtrip() {
        let lock = FastMutex::new(5usize);
        *lock.lock() = 9;
        assert_eq!(*lock.lock(), 9);
    }
}
