pub mod capture;
pub mod engine;
pub mod error;
pub mod lifecycle;
pub mod protocol;
pub mod sensor;
pub mod server;
pub mod sgx;
mod state;

pub type Secret = zeroize::Zeroizing<Vec<u8>>;

/// TLS records remain opaque to the host. A zero-length read means WANT_READ.
pub trait TlsIo {
    fn receive(&mut self, output: &mut [u8]) -> error::Result<usize>;
    fn send(&mut self, input: &[u8]) -> error::Result<usize>;
}

/// Cancellation is checked by device waits and enclave transitions, not a timer
/// limiting how long a person may take to touch or release the sensor.
pub trait Cancellation {
    fn check(&self) -> error::Result<()>;
    fn check_wait(&self) -> error::Result<()> {
        self.check()
    }
    fn descriptors(&self) -> Vec<std::os::fd::RawFd>;
}
