use std::collections::{HashMap, VecDeque};

use crate::{tcp::connection::Connection, Quad};

#[derive(Default)]
pub(crate) struct ConnectionManager {
    pub terminate: bool,
    pub connections: HashMap<Quad, Connection>,
    pub pending: HashMap<u16, VecDeque<Quad>>,
}
