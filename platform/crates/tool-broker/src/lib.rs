//! CDSIP Tool Broker
//!
//! The Tool Broker is the single controlled gateway for ALL tool execution.
//! No tool can be invoked without passing through the broker.
//!
//! ## Execution Flow
//! 1. Request received with tool ID + input params
//! 2. Input schema validated against tool definition
//! 3. Target authorization checked against policy
//! 4. Policy Governor evaluates the request
//! 5. If allowed, tool is executed in sandboxed context
//! 6. Output normalized through tool adapter
//! 7. Results stored with full provenance
//! 8. Audit event generated
//!
//! ## Security Invariants
//! - No raw command execution from user input
//! - Only registered tools with defined schemas
//! - Only approved scan profiles (no arbitrary flags)
//! - All executions are tracked and auditable
//! - Timeouts enforced on all executions

pub mod broker;
pub mod executor;
pub mod nmap;
pub mod registry;
pub mod types;

pub use broker::ToolBroker;
pub use types::ToolError;
