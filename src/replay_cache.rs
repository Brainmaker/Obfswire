use std::{
    collections::{HashSet, VecDeque},
    time::{SystemTime, UNIX_EPOCH}
};
use std::sync::Mutex;

use crate::error::{Error, BadDataReceived};

/// The acceptable time range [-r, +r] for a timestamp to be considered valid.
const ACCEPTABLE_TIME_RANGE_IN_SECOND: u64 = 90;  // 90 seconds

/// Divisor (in seconds) for the Unix epoch.
const GRANULARITY: u64 = 10;  // 10 seconds

pub(crate) const TIME_TORLERANCE: u64 = ACCEPTABLE_TIME_RANGE_IN_SECOND / GRANULARITY;

/// Returns the current Unix epoch timestamp divided by `EPOCH_GRANULARITY`.
/// 
/// This deliberately reduces the precision of the timestamp to avoid exposing 
/// exact timestamps at communication endpoints, which helps protect privacy.
pub(crate) fn current_timestamp_with_granularity() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("SystemTime before UNIX EPOCH")
        .as_secs() / GRANULARITY
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
        now: u64
    ) -> Result<(), Error> {
        let mut inner = self.0.lock().unwrap();
        
        if inner.salts.contains(&salt) {
            return Err(BadDataReceived::ReusedNonce.into());
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
