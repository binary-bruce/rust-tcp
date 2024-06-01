use interface_handle::InterfaceHandle;
use std::collections::VecDeque;
use std::io;
use std::io::prelude::*;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::thread;
use tcp::available::Available;
use tcp::connection::Connection;
use tcp_listener::TcpListener;

mod conn_manager;
mod interface_handle;
mod tcp;
mod tcp_listener;
mod tcp_stream;

const SENDQUEUE_SIZE: usize = 1024;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
struct Quad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

pub struct Interface {
    ih: Option<InterfaceHandle>,
    jh: Option<thread::JoinHandle<io::Result<()>>>,
}

impl Drop for Interface {
    fn drop(&mut self) {
        self.ih.as_mut().unwrap().manager.lock().unwrap().terminate = true;

        drop(self.ih.take());
        self.jh
            .take()
            .expect("interface dropped more than once")
            .join()
            .unwrap()
            .unwrap();
    }
}

fn packet_loop(mut nic: tun_tap::Iface, ih: InterfaceHandle) -> io::Result<()> {
    let mut buf = [0u8; 1504];

    loop {
        // we want to read from nic, but we want to make sure that we'll wake up when the next
        // timer has to be triggered!
        use std::os::unix::io::AsRawFd;
        let mut pfd = [nix::poll::PollFd::new(
            nic.as_raw_fd(),
            nix::poll::EventFlags::POLLIN,
        )];
        let n = nix::poll::poll(&mut pfd[..], 10).map_err(|e| e.as_errno().unwrap())?;
        assert_ne!(n, -1);
        if n == 0 {
            let mut cmg = ih.manager.lock().unwrap();
            for connection in cmg.connections.values_mut() {
                // XXX: don't die on errors?
                connection.on_tick(&mut nic)?;
            }
            continue;
        }
        assert_eq!(n, 1);
        let nbytes = nic.recv(&mut buf[..])?;

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
                let src = iph.source_addr();
                let dst = iph.destination_addr();
                if iph.protocol() != 0x06 {
                    eprintln!("BAD PROTOCOL");
                    // not tcp
                    continue;
                }

                match etherparse::TcpHeaderSlice::from_slice(&buf[iph.slice().len()..nbytes]) {
                    Ok(tcph) => {
                        use std::collections::hash_map::Entry;
                        let datai = iph.slice().len() + tcph.slice().len();
                        let mut cmg = ih.manager.lock().unwrap();
                        let cm = &mut *cmg;
                        let q = Quad {
                            src: (src, tcph.source_port()),
                            dst: (dst, tcph.destination_port()),
                        };

                        match cm.connections.entry(q) {
                            Entry::Occupied(mut c) => {
                                eprintln!("got packet for known quad {:?}", q);
                                let a = c.get_mut().on_packet(
                                    &mut nic,
                                    iph,
                                    tcph,
                                    &buf[datai..nbytes],
                                )?;

                                // TODO: compare before/after
                                drop(cmg);
                                if a.contains(Available::READ) {
                                    ih.rcv_var.notify_all()
                                }
                                if a.contains(Available::WRITE) {
                                    // TODO: ih.snd_var.notify_all()
                                }
                            }
                            Entry::Vacant(e) => {
                                eprintln!("got packet for unknown quad {:?}", q);
                                if let Some(pending) = cm.pending.get_mut(&tcph.destination_port())
                                {
                                    eprintln!("listening, so accepting");
                                    if let Some(c) = Connection::accept(
                                        &mut nic,
                                        iph,
                                        tcph,
                                        &buf[datai..nbytes],
                                    )? {
                                        e.insert(c);
                                        pending.push_back(q);
                                        drop(cmg);
                                        ih.pending_var.notify_all()
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("ignoring weird tcp packet {:?}", e);
                    }
                }
            }
            Err(e) => {
                // eprintln!("ignoring weird packet {:?}", e);
            }
        }
    }
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
            ih: Some(ih),
            jh: Some(jh),
        })
    }

    pub fn bind(&mut self, port: u16) -> io::Result<TcpListener> {
        use std::collections::hash_map::Entry;
        let mut cm = self.ih.as_mut().unwrap().manager.lock().unwrap();
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
            h: self.ih.as_mut().unwrap().clone(),
        })
    }
}
