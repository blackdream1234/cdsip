//! Nmap tool integration module.
//!
//! This module provides a SAFE, CONTROLLED Nmap wrapper.
//!
//! ## Security Rules
//! - Only approved scan profiles are allowed (no arbitrary flags)
//! - Only explicitly registered targets can be scanned
//! - All executions have timeouts
//! - Raw output is captured and stored for audit
//! - Results are parsed into normalized structured findings

pub mod parser;
pub mod profiles;
pub mod runner;

pub use runner::NmapExecutor;
