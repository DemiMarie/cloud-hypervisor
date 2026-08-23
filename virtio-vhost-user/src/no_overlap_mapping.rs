//! A mapping that checks that there are no overlaps,
//! and allows efficient lookups by range.
//!
//! Used by the vhost-guest device to validate incoming
//! messages from the frontend.

use std::cmp::Ordering;
use std::collections::BTreeSet;

#[derive(Eq)]
pub(super) struct MapKey {
    base: u64,
    size: u64,
    is_lookup_key: Ordering,
}

impl PartialOrd for MapKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl PartialEq for MapKey {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Ord for MapKey {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.base.cmp(&other.base) {
            // This range is strictly below the other.
            Ordering::Less if other.base - self.base >= self.size => return Ordering::Less,
            // This range is strictly above the other.
            Ordering::Greater if self.base - other.base >= other.size => return Ordering::Greater,
            _ => match (self.is_lookup_key, other.is_lookup_key) {
                (Ordering::Less, Ordering::Less) | (Ordering::Greater, Ordering::Greater) => {
                    // This cannot happen: the only time overlapping keys exist
                    // is during lookups, and those never have
                    panic!("Overlapping keys with equal is_lookup_key detected")
                }
                (Ordering::Less, Ordering::Greater)
                | (Ordering::Greater, Ordering::Less)
                | (Ordering::Equal, Ordering::Equal) => {
                    // Two entries overlap.
                    // Only can happen during lookups, where base and size are identical.
                    assert_eq!(self.base, other.base);
                    assert_eq!(self.size, other.size);
                }
                _ => {}
            },
        }
        self.is_lookup_key.cmp(&other.is_lookup_key)
    }
}

#[derive(Default)]
pub(super) struct RangeMap {
    data: BTreeSet<MapKey>,
}

impl RangeMap {
    pub fn insert(&mut self, low: u64, length: u64) -> Result<(), ()> {
        let Some(key) = self.contains_range(low, length) else {
            return Err(());
        };
        assert!(self.data.insert(key));
        Ok(())
    }

    pub fn contains_range(&self, base: u64, size: u64) -> Option<MapKey> {
        // Check for overflow
        if u64::MAX - size < base {
            return None;
        }
        let key = MapKey {
            is_lookup_key: Ordering::Equal,
            base,
            size,
        };
        let range = MapKey {
            is_lookup_key: Ordering::Less,
            ..key
        }..MapKey {
            is_lookup_key: Ordering::Greater,
            ..key
        };
        if self.data.range(range).next().is_some() {
            return None;
        }
        Some(key)
    }

    pub(super) fn remove(&mut self, base: u64, size: u64) -> bool {
        self.data.remove(&MapKey {
            base,
            size,
            is_lookup_key: Ordering::Equal,
        })
    }
}
