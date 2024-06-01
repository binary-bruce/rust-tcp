use std::io;

use crate::{interface_handle::InterfaceHandle, tcp_stream::TcpStream};

pub struct TcpListener {
    pub port: u16,
    pub(crate) h: InterfaceHandle,
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        let mut cm = self.h.manager.lock().unwrap();

        let pending = cm
            .pending
            .remove(&self.port)
            .expect("port closed while listener still active");

        for quad in pending {
            // TODO: terminate cm.connections[quad]
            unimplemented!();
        }
    }
}

impl TcpListener {
    pub fn accept(&mut self) -> io::Result<TcpStream> {
        let mut cm = self.h.manager.lock().unwrap();
        loop {
            if let Some(quad) = cm
                .pending
                .get_mut(&self.port)
                .expect("port closed while listener still active")
                .pop_front()
            {
                return Ok(TcpStream {
                    quad,
                    h: self.h.clone(),
                });
            }

            cm = self.h.pending_var.wait(cm).unwrap();
        }
    }
}
