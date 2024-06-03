use std::{
    io,
    sync::{Arc, Condvar, Mutex},
};

use etherparse::Ipv4HeaderSlice;

use crate::{
    conn_manager::ConnectionManager,
    quad::Quad,
    tcp::{available::Available, connection::Connection},
};

pub(crate) type InterfaceHandle = Arc<_InterfaceHandle>;

#[derive(Default)]
pub(crate) struct _InterfaceHandle {
    pub manager: Mutex<ConnectionManager>,
    pub pending_var: Condvar,
    pub rcv_var: Condvar,
}

impl _InterfaceHandle {
    pub fn terminate(&self) {
        self.manager.lock().unwrap().terminate()
    }

    pub fn handle_empty_data(&self, nic: &mut tun_tap::Iface) -> io::Result<()> {
        self.manager.lock().unwrap().handle_empty_data(nic)
    }

    pub fn handle_ip_packet(
        &self,
        buf: &[u8],
        nbytes: usize,
        nic: &mut tun_tap::Iface,
    ) -> io::Result<()> {
        // TODO: if self.terminate && Arc::get_strong_refs(ih) == 1; then tear down all connections and return.

        // if s/without_packet_info/new/:
        //
        // let _eth_flags = u16::from_be_bytes([buf[0], buf[1]]);
        // let eth_proto = u16::from_be_bytes([buf[2], buf[3]]);
        // if eth_proto != 0x0800 {
        //     // not ipv4
        //     continue;
        // }
        //
        // and also include on send

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[..nbytes]) {
            Ok(iph) => {
                if iph.protocol() != 0x06 {
                    eprintln!("BAD PROTOCOL");
                    // not tcp, ignore
                    return Ok(());
                }

                self.handle_tcp_packet(buf, nbytes, nic, iph)?
            }
            Err(e) => {
                // eprintln!("ignoring weird packet {:?}", e);
            }
        }

        Ok(())
    }

    fn handle_tcp_packet(
        &self,
        buf: &[u8],
        nbytes: usize,
        nic: &mut tun_tap::Iface,
        iph: Ipv4HeaderSlice,
    ) -> io::Result<()> {
        let src = iph.source_addr();
        let dst = iph.destination_addr();

        match etherparse::TcpHeaderSlice::from_slice(&buf[iph.slice().len()..nbytes]) {
            Ok(tcph) => {
                use std::collections::hash_map::Entry;
                let datai = iph.slice().len() + tcph.slice().len();
                let mut cmg = self.manager.lock().unwrap();
                let cm = &mut *cmg;
                let q = Quad {
                    src: (src, tcph.source_port()),
                    dst: (dst, tcph.destination_port()),
                };

                match cm.connections.entry(q) {
                    Entry::Occupied(mut c) => {
                        eprintln!("got packet for known quad {:?}", q);
                        let a = c.get_mut().on_packet(nic, iph, tcph, &buf[datai..nbytes])?;

                        // TODO: compare before/after
                        drop(cmg);
                        if a.contains(Available::READ) {
                            self.rcv_var.notify_all()
                        }
                        if a.contains(Available::WRITE) {
                            // TODO: ih.snd_var.notify_all()
                        }
                    }
                    Entry::Vacant(e) => {
                        eprintln!("got packet for unknown quad {:?}", q);
                        if let Some(pending) = cm.pending.get_mut(&tcph.destination_port()) {
                            eprintln!("listening, so accepting");
                            if let Some(c) =
                                Connection::accept(nic, iph, tcph, &buf[datai..nbytes])?
                            {
                                e.insert(c);
                                pending.push_back(q);
                                drop(cmg);
                                self.pending_var.notify_all()
                            }
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("ignoring weird tcp packet {:?}", e);
            }
        }

        Ok(())
    }
}
