//! Tool registry — defines available tools and their metadata.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use crate::executor::ToolExecutorTrait;

/// Metadata describing a registered tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub tool_id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub allowed_environments: Vec<String>,
    pub allowed_roles: Vec<String>,
    pub timeout_secs: u64,
    pub max_concurrent: usize,
}

/// The tool registry holds all available tool definitions and their executors.
pub struct ToolRegistry {
    definitions: HashMap<String, ToolDefinition>,
    executors: HashMap<String, Arc<dyn ToolExecutorTrait>>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self {
            definitions: HashMap::new(),
            executors: HashMap::new(),
        }
    }

    /// Register a tool with its definition and executor.
    pub fn register(
        &mut self,
        definition: ToolDefinition,
        executor: Arc<dyn ToolExecutorTrait>,
    ) {
        let tool_id = definition.tool_id.clone();
        self.definitions.insert(tool_id.clone(), definition);
        self.executors.insert(tool_id, executor);
    }

    /// Get a tool definition by ID.
    pub fn get_definition(&self, tool_id: &str) -> Option<&ToolDefinition> {
        self.definitions.get(tool_id)
    }

    /// Get a tool executor by ID.
    pub fn get_executor(&self, tool_id: &str) -> Option<Arc<dyn ToolExecutorTrait>> {
        self.executors.get(tool_id).cloned()
    }

    /// List all registered tools.
    pub fn list_tools(&self) -> Vec<&ToolDefinition> {
        self.definitions.values().collect()
    }

    /// Check if a tool is registered.
    pub fn has_tool(&self, tool_id: &str) -> bool {
        self.definitions.contains_key(tool_id)
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}
