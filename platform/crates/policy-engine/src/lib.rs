//! CDSIP Policy Engine
//!
//! The Policy Governor is a first-class subsystem that evaluates every
//! sensitive action against defined policy rules. It is the single
//! authority for allow/deny/require_approval/escalate decisions.
//!
//! ## Security Invariants
//! - Default action is DENY if no rule matches
//! - Every evaluation produces a PolicyDecision with rationale
//! - Every decision is traceable to a specific rule or the default deny
//! - Environment boundaries are enforced (production vs lab)
//! - Role-based restrictions are enforced

pub mod evaluator;
pub mod governor;
pub mod rules;
pub mod types;

pub use governor::PolicyGovernor;
pub use types::PolicyError;
