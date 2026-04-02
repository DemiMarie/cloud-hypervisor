//! A mapping that checks that there are no overlaps,
//! and allows efficient lookups by range.
//!
//! Used by the vhost-guest device to validate incoming
//! messages from the frontend.

use std::cmp::Ordering;
use std::collections::{BTreeMap, btree_map};

#[derive(Eq)]
pub(super) struct MapKey {
    base: u64,
    end: u64,
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
        assert!(self.base <= self.end);
        assert!(other.base <= other.end);
        match (self.is_lookup_key, other.is_lookup_key) {
            (Ordering::Less, Ordering::Less) | (Ordering::Greater, Ordering::Greater) => {
                panic!("Cannot have more than one Less or Greater key at a time")
            }
            (Ordering::Equal, Ordering::Equal) => {
                // Must be equal or non-overlapping.
                let o = <u64 as Ord>::cmp(&self.base, &other.base);
                match o {
                    Ordering::Equal => assert_eq!(self.end, other.end),
                    Ordering::Less => assert!(self.end < other.base),
                    Ordering::Greater => assert!(self.base > other.end),
                }
                o
            }
            (a @ Ordering::Less, Ordering::Greater) | (a @ Ordering::Greater, Ordering::Less) => {
                // Two entries overlap.
                // Only can happen during range lookups, where base and size are identical.
                assert_eq!(self.base, other.base);
                assert_eq!(self.end, other.end);
                a
            }
            ordering @ ((Ordering::Less, Ordering::Equal)
            | (Ordering::Equal, Ordering::Less)
            | (Ordering::Equal, Ordering::Greater)
            | (Ordering::Greater, Ordering::Equal)) => {
                if self.end >= other.base && self.base <= other.end {
                    ordering.0.cmp(&ordering.1)
                } else {
                    self.base.cmp(&other.base)
                }
            }
        }
    }
}

#[derive(Default)]
pub(super) struct RangeMap {
    data: BTreeMap<MapKey, u64>,
}

fn get_end(base: u64, size: u64) -> Option<u64> {
    base.checked_add(size.checked_sub(1)?)
}

impl RangeMap {
    pub(super) fn insert(&mut self, base: u64, length: u64, offset: u64) -> Result<(), ()> {
        let end = get_end(base, length).ok_or(())?;
        if u64::MAX - length < offset || !self.does_not_contain_range(base, length) {
            return Err(());
        }
        let key = MapKey {
            is_lookup_key: Ordering::Equal,
            base,
            end,
        };
        assert!(self.data.insert(key, offset).is_none());
        Ok(())
    }

    pub(super) fn does_not_contain_range(&self, base: u64, size: u64) -> bool {
        match self.lookup_range(base, size) {
            Ok(mut range) => range.next().is_none(),
            Err(()) => false,
        }
    }

    fn lookup_range(&self, base: u64, size: u64) -> Result<btree_map::Range<'_, MapKey, u64>, ()> {
        let end = get_end(base, size).ok_or(())?;
        let range = MapKey {
            is_lookup_key: Ordering::Less,
            base,
            end,
        }..MapKey {
            is_lookup_key: Ordering::Greater,
            base,
            end,
        };
        Ok(self.data.range(range))
    }

    fn get_first_entry(
        &self,
        base: u64,
        size: u64,
    ) -> Option<(btree_map::Range<'_, MapKey, u64>, MapKey, u64)> {
        let mut range = self.lookup_range(base, size).ok()?;
        let (key, &offset) = range.next()?;
        assert_eq!(key.is_lookup_key, Ordering::Equal);
        Some((range, MapKey { ..*key }, offset))
    }

    pub(super) fn lookup(&self, base: u64, size: u64) -> Option<u64> {
        let end = get_end(base, size)?;
        let (mut range, key, offset) = self.get_first_entry(base, size)?;
        if base < key.base || end > key.end {
            return None;
        }
        assert!(
            range.next().is_none(),
            "key cannot be contained in multiple non-overlapping ranges"
        );
        Some(offset + (base - key.base))
    }

    pub(super) fn remove(&mut self, base: u64, size: u64) -> bool {
        let Some(end) = get_end(base, size) else {
            return false;
        };
        let Some((mut range, key, offset)) = self.get_first_entry(base, size) else {
            return false;
        };
        if key.base != base || end != key.end {
            return false;
        }
        assert!(range.next().is_none());
        assert_eq!(self.data.remove(&key), Some(offset));
        true
    }
}
