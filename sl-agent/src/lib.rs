//! The SerenLink agent: a Linux shell around `sl_core::device::Device` for boats that run a
//! SignalK server (architecture spec 4, D12; agent spec 3).
pub mod cached;
pub mod clock;
pub mod defines;
pub mod file_store;
pub mod identity;
pub mod policy;
pub mod run;
pub mod signalk;
pub mod sink;
pub mod transport;
