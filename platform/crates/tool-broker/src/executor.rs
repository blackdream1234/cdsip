//! Tool executor trait — the interface all tool adapters must implement.

use async_trait::async_trait;
use serde_json::Value;

use crate::types::ToolError;

/// Result of a tool execution.
#[derive(Debug, Clone)]
pub struct ToolOutput {
    /// Normalized structured output.
    pub data: Value,
    /// Raw output (stored separately for forensic/audit purposes).
    pub raw_output: Option<String>,
    /// Summary for audit log.
    pub summary: String,
}

/// Trait that all tool executors must implement.
/// Each tool adapter (Nmap, future tools) implements this trait.
#[async_trait]
pub trait ToolExecutorTrait: Send + Sync + std::fmt::Debug {
    /// Validate the input parameters against the tool's schema.
    fn validate_input(&self, params: &Value) -> Result<(), ToolError>;

    /// Execute the tool with validated parameters.
    /// The executor is responsible for:
    /// - Building the command safely (no user-controlled flags)
    /// - Running with timeouts
    /// - Capturing output
    /// - Normalizing results
    async fn execute(&self, params: &Value) -> Result<ToolOutput, ToolError>;

    /// Return the tool ID.
    fn tool_id(&self) -> &str;

    /// Return the tool version.
    fn tool_version(&self) -> &str;
}

// We need async_trait since the workspace doesn't have it yet.
// Use the trait object approach with Pin<Box<Future>> instead.
// Actually, let's add it properly. For now, let's use a manual approach.

// Re-implementing without async_trait macro for simplicity:
// The trait above uses async_trait which we need to add to dependencies.
// For V1, we'll use a boxed future approach.
