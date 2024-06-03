use std::{
    collections::{HashMap, VecDeque},
    io,
};

use crate::{quad::Quad, tcp::connection::Connection};

#[derive(Default)]
pub(crate) struct ConnectionManager {
    pub terminate: bool,
    pub connections: HashMap<Quad, Connection>,
    pub pending: HashMap<u16, VecDeque<Quad>>,
}

impl ConnectionManager {
    pub fn terminate(&mut self) {
        self.terminate = true
    }

    pub fn handle_empty_data(&mut self, nic: &mut tun_tap::Iface) -> io::Result<()> {
        for connection in self.connections.values_mut() {
            // XXX: don't die on errors?
            connection.on_tick(nic)?
        }
        Ok(())
    }
}
