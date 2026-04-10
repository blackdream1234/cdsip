//! CDSIP Risk Engine
//!
//! Transparent, explainable risk scoring for assets.
//! Every score includes factor breakdown and rationale.
//! No opaque AI — pure deterministic calculation.

pub mod calculator;
pub mod factors;
pub mod types;

pub use calculator::RiskCalculator;
pub use types::RiskError;
