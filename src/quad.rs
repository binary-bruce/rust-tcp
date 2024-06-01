use std::net::Ipv4Addr;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub(crate) struct Quad {
    pub src: (Ipv4Addr, u16),
    pub dst: (Ipv4Addr, u16),
}
