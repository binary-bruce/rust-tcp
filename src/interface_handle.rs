use std::sync::{Arc, Condvar, Mutex};

use crate::conn_manager::ConnectionManager;

#[derive(Default)]
pub(crate) struct Handle {
    pub manager: Mutex<ConnectionManager>,
    pub pending_var: Condvar,
    pub rcv_var: Condvar,
}

pub(crate) type InterfaceHandle = Arc<Handle>;
