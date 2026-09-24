//! `SystemTime` has no built-in serde impl (it can predate `UNIX_EPOCH` on some
//! platforms, so serde deliberately doesn't assume a canonical representation) -
//! these helpers pin it to milliseconds since the epoch, which is precise enough
//! for session timers and portable across a serialize/deserialize round trip
//! (e.g. a live session handed off between two processes).

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn to_millis(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_millis() as i64,
        Err(e) => -(e.duration().as_millis() as i64),
    }
}

fn from_millis(millis: i64) -> SystemTime {
    if millis >= 0 {
        UNIX_EPOCH + Duration::from_millis(millis as u64)
    } else {
        UNIX_EPOCH - Duration::from_millis((-millis) as u64)
    }
}

pub fn serialize<S: Serializer>(t: &SystemTime, s: S) -> Result<S::Ok, S::Error> {
    to_millis(*t).serialize(s)
}

pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SystemTime, D::Error> {
    Ok(from_millis(i64::deserialize(d)?))
}

pub mod map {
    use super::*;

    pub fn serialize<S: Serializer>(
        map: &HashMap<u32, SystemTime>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let as_millis: HashMap<u32, i64> =
            map.iter().map(|(k, v)| (*k, to_millis(*v))).collect();
        as_millis.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<HashMap<u32, SystemTime>, D::Error> {
        let as_millis = HashMap::<u32, i64>::deserialize(d)?;
        Ok(as_millis
            .into_iter()
            .map(|(k, v)| (k, from_millis(v)))
            .collect())
    }
}
