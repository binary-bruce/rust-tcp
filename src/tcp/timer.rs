use std::{collections::BTreeMap, time};

pub(crate) struct Timers {
    pub send_times: BTreeMap<u32, time::Instant>,
    pub srtt: f64,
}

impl Timers {
    pub fn default() -> Self {
        Self {
            send_times: Default::default(),
            srtt: time::Duration::from_secs(1 * 60).as_secs_f64(),
        }
    }

    pub fn insert_send_timer(&mut self, seq: u32) {
        self.send_times.insert(seq, time::Instant::now());
    }
}
