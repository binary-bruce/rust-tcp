use std::{collections::BTreeMap, time};

pub(crate) struct Timers {
    pub send_times: BTreeMap<u32, time::Instant>,
    pub srtt: f64,
}
