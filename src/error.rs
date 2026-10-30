#[derive(Debug)]
pub enum Error {
    NotConnected,
    KeyLoad,
    Control(tm_control::ControlError),
    InternalFailure,
    RuntimeDegraded,
    Pin(tm_control::pin::PinError),
    /// A `Config` setter rejected its argument; the text says why.
    InvalidConfig(&'static str),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {}
