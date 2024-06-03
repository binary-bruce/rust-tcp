use std::io;

use crate::interface_handle::InterfaceHandle;

pub(crate) fn packet_loop(mut nic: tun_tap::Iface, ih: InterfaceHandle) -> io::Result<()> {
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
            ih.handle_empty_data(&mut nic)?;
            continue;
        }
        assert_eq!(n, 1);
        let nbytes = nic.recv(&mut buf[..])?;

        ih.handle_ip_packet(&buf, nbytes, &mut nic)?
    }
}
