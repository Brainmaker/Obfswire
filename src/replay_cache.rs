use std::{
    collections::{HashSet, VecDeque},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::error::{BadDataReceived, Error};

/// The acceptable time range [-r, +r] for a timestamp to be considered valid.
const ACCEPTABLE_TIME_RANGE_IN_SECOND: u64 = 90; // 90 seconds

/// Divisor (in seconds) for the Unix epoch.
const GRANULARITY: u64 = 10; // 10 seconds

pub(crate) const TIME_TORLERANCE: u64 = ACCEPTABLE_TIME_RANGE_IN_SECOND / GRANULARITY;

/// Returns the current Unix epoch timestamp divided by `EPOCH_GRANULARITY`.
///
/// This deliberately reduces the precision of the timestamp to avoid exposing
/// exact timestamps at communication endpoints, which helps protect privacy.
pub(crate) fn current_timestamp_with_granularity() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("SystemTime before UNIX EPOCH")
        .as_secs()
        / GRANULARITY
}

#[derive(Debug)]
pub(crate) struct ReplayCache(Mutex<Inner>);

#[derive(Debug)]
struct Inner {
    salts: HashSet<[u8; 32]>,
    oldest: VecDeque<(u64, [u8; 32])>,
}

impl ReplayCache {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        ReplayCache(Mutex::new(Inner {
            salts: HashSet::with_capacity(capacity),
            oldest: VecDeque::with_capacity(capacity),
        }))
    }

    /// Insert a new salt and its corresponded timestamp to the replay cache.
    /// Returns `Ok(())` if the salt does not exist (i.e., accepted).
    pub(crate) fn check_or_insert(
        &self,
        salt: [u8; 32],
        timestamp: u64,
        now: u64,
    ) -> Result<(), Error> {
        let mut inner = self.0.lock().unwrap();

        if inner.salts.contains(&salt) {
            return Err(BadDataReceived::ReusedSalt.into());
        }

        inner.salts.insert(salt);
        inner.oldest.push_back((timestamp, salt));

        while let Some(&(oldest_timestamp, salt)) = inner.oldest.front() {
            if now - oldest_timestamp <= TIME_TORLERANCE + 2 {
                break;
            }
            inner.salts.remove(&salt);
            inner.oldest.pop_front();
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_replay_cache_in_accept_time_range() {
        let cache = ReplayCache::with_capacity(16);

        let now = current_timestamp_with_granularity();
        let salt = [1u8; 32];
        assert!(cache.check_or_insert(salt, now, now).is_ok());
        assert!(cache.check_or_insert(salt, now, now).is_err());
    }

    #[test]
    fn test_replay_cache_clean_old() {
        let cache = ReplayCache::with_capacity(16);
        let t0 = 1000;
        let t1 = 1000 + 1;
        let t2 = 1000 + 2;
        let t3 = 1000 + 3;
        let t4 = 1000 + 4;
        assert!(cache.check_or_insert([0u8; 32], t0, t0).is_ok());
        assert!(cache.check_or_insert([1u8; 32], t1, t1).is_ok());
        assert!(cache.check_or_insert([2u8; 32], t2, t2).is_ok());
        assert!(cache.check_or_insert([3u8; 32], t3, t3).is_ok());
        assert!(cache.check_or_insert([4u8; 32], t4, t4).is_ok());
        assert_eq!(
            cache.0.lock().unwrap().oldest.clone(),
            VecDeque::from(vec![
                (t0, [0u8; 32]),
                (t1, [1u8; 32]),
                (t2, [2u8; 32]),
                (t3, [3u8; 32]),
                (t4, [4u8; 32]),
            ])
        );
        assert_eq!(
            cache.0.lock().unwrap().salts.clone(),
            HashSet::from_iter(vec![[0u8; 32], [1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32],])
        );

        let t5 = 1000 + TIME_TORLERANCE + 2;
        let t6 = 1000 + TIME_TORLERANCE + 3;

        assert!(cache.check_or_insert([5u8; 32], t5, t5).is_ok());
        assert_eq!(
            cache.0.lock().unwrap().oldest.clone(),
            VecDeque::from(vec![
                (t0, [0u8; 32]),
                (t1, [1u8; 32]),
                (t2, [2u8; 32]),
                (t3, [3u8; 32]),
                (t4, [4u8; 32]),
                (t5, [5u8; 32]),
            ])
        );
        assert_eq!(
            cache.0.lock().unwrap().salts.clone(),
            HashSet::from_iter(vec![
                [0u8; 32], [1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32],
            ])
        );

        assert!(cache.check_or_insert([6u8; 32], t6, t6).is_ok());
        assert_eq!(
            cache.0.lock().unwrap().oldest.clone(),
            VecDeque::from(vec![
                (t1, [1u8; 32]),
                (t2, [2u8; 32]),
                (t3, [3u8; 32]),
                (t4, [4u8; 32]),
                (t5, [5u8; 32]),
                (t6, [6u8; 32]),
            ])
        );
        assert_eq!(
            cache.0.lock().unwrap().salts.clone(),
            HashSet::from_iter(vec![
                [1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32], [6u8; 32],
            ])
        );

        let t7 = 1000 + TIME_TORLERANCE + 5;
        assert!(cache.check_or_insert([7u8; 32], t7, t7).is_ok());
        assert_eq!(
            cache.0.lock().unwrap().oldest.clone(),
            VecDeque::from(vec![
                (t3, [3u8; 32]),
                (t4, [4u8; 32]),
                (t5, [5u8; 32]),
                (t6, [6u8; 32]),
                (t7, [7u8; 32]),
            ])
        );
        assert_eq!(
            cache.0.lock().unwrap().salts.clone(),
            HashSet::from_iter(vec![[3u8; 32], [4u8; 32], [5u8; 32], [6u8; 32], [7u8; 32],])
        );
    }
}
