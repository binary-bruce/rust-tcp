pub(crate) fn wrapping_lt(lhs: u32, rhs: u32) -> bool {
    // From RFC1323:
    //     TCP determines if a data segment is "old" or "new" by testing
    //     whether its sequence number is within 2**31 bytes of the left edge
    //     of the window, and if it is not, discarding the data as "old".  To
    //     insure that new data is never mistakenly considered old and vice-
    //     versa, the left edge of the sender's window has to be at most
    //     2**31 away from the right edge of the receiver's window.
    lhs.wrapping_sub(rhs) > (1 << 31)
}

pub(crate) fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    wrapping_lt(start, x) && wrapping_lt(x, end)
}

pub(crate) fn construct_ip_header<'a>(
    iph: etherparse::Ipv4HeaderSlice<'a>,
) -> etherparse::Ipv4Header {
    let dst = iph.destination();
    let src = iph.source();

    etherparse::Ipv4Header::new(
        0,
        64,
        etherparse::IpTrafficClass::Tcp,
        [dst[0], dst[1], dst[2], dst[3]],
        [src[0], src[1], src[2], src[3]],
    )
}

pub(crate) fn construct_tcp_header<'a>(
    tcph: etherparse::TcpHeaderSlice<'a>,
    iss: u32,
    wnd: u16,
) -> etherparse::TcpHeader {
    etherparse::TcpHeader::new(tcph.destination_port(), tcph.source_port(), iss, wnd)
}
