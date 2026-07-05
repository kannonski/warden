//! warden-caps — capability-type implementations.
//!
//! One module per capability-type; each is just a [`warden_core::Capability`] + its
//! [`warden_core::Broker`]. The kernel never changes when a type is added here.

pub mod exec;
pub mod fs;
pub mod pty;
