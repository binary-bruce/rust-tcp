use std::collections::{HashMap, VecDeque};

use crate::{quad::Quad, tcp::connection::Connection};

#[derive(Default)]
pub(crate) struct ConnectionManager {
    pub terminate: bool,
    pub connections: HashMap<Quad, Connection>,
    pub pending: HashMap<u16, VecDeque<Quad>>,
}
