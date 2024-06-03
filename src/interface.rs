use std::collections::VecDeque;
use std::io;
use std::sync::Arc;
use std::thread;

use crate::interface_handle::InterfaceHandle;
use crate::packet_loop::packet_loop;
use crate::tcp_listener::TcpListener;

pub struct Interface {
    interface_handle: Option<InterfaceHandle>,
    join_handle: Option<thread::JoinHandle<io::Result<()>>>,
}

impl Interface {
    pub fn new() -> io::Result<Self> {
        let nic = tun_tap::Iface::without_packet_info("tun0", tun_tap::Mode::Tun)?;

        let ih: InterfaceHandle = Arc::default();

        let jh = {
            let ih = ih.clone();
            thread::spawn(move || packet_loop(nic, ih))
        };

        Ok(Interface {
            interface_handle: Some(ih),
            join_handle: Some(jh),
        })
    }

    pub fn bind(&mut self, port: u16) -> io::Result<TcpListener> {
        use std::collections::hash_map::Entry;
        let mut cm = self
            .interface_handle
            .as_mut()
            .unwrap()
            .manager
            .lock()
            .unwrap();
        match cm.pending.entry(port) {
            Entry::Vacant(v) => {
                v.insert(VecDeque::new());
            }
            Entry::Occupied(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "port already bound",
                ));
            }
        };
        drop(cm);
        Ok(TcpListener {
            port,
            interface_handle: self.interface_handle.as_mut().unwrap().clone(),
        })
    }
}

impl Drop for Interface {
    fn drop(&mut self) {
        self.interface_handle.as_mut().unwrap().terminate();

        drop(self.interface_handle.take());
        self.join_handle
            .take()
            .expect("interface dropped more than once")
            .join()
            .unwrap()
            .unwrap();
    }
}
