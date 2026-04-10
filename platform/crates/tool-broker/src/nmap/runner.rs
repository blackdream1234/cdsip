//! Nmap runner — safe, sandboxed Nmap execution.
//!
//! ## Security
//! - Only executes with pre-approved profile flags
//! - Target must be an explicitly registered scan target
//! - Execution has hard timeout
//! - No shell interpolation (uses Command directly)
//! - Output captured and parsed, raw XML stored for audit

use std::path::PathBuf;
use std::time::Duration;
use tokio::process::Command;
use tracing::{info, warn, error};
use serde_json::Value;
use uuid::Uuid;

use cdsip_domain_models::scan::ScanProfile;
use crate::executor::{ToolExecutorTrait, ToolOutput};
use crate::nmap::parser::parse_nmap_xml;
use crate::nmap::profiles::build_nmap_args;
use crate::types::ToolError;

/// Configuration for the Nmap executor.
#[derive(Debug, Clone)]
pub struct NmapConfig {
    /// Path to the nmap binary.
    pub binary_path: String,
    /// Maximum execution time in seconds.
    pub timeout_secs: u64,
    /// Directory for storing scan output artifacts.
    pub artifact_dir: String,
}

impl Default for NmapConfig {
    fn default() -> Self {
        Self {
            binary_path: "/usr/bin/nmap".to_string(),
            timeout_secs: 300,
            artifact_dir: "/app/artifacts".to_string(),
        }
    }
}

/// Safe Nmap executor. Implements ToolExecutorTrait.
#[derive(Debug)]
pub struct NmapExecutor {
    config: NmapConfig,
}

impl NmapExecutor {
    pub fn new(config: NmapConfig) -> Self {
        Self { config }
    }

    /// Parse the scan profile from input params.
    fn parse_profile(params: &Value) -> Result<ScanProfile, ToolError> {
        let profile_str = params
            .get("profile")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput("Missing 'profile' parameter".to_string()))?;

        match profile_str {
            "host_discovery" => Ok(ScanProfile::HostDiscovery),
            "safe_tcp_scan" => Ok(ScanProfile::SafeTcpScan),
            "service_detection" => Ok(ScanProfile::ServiceDetection),
            _ => Err(ToolError::InvalidInput(format!(
                "Unknown scan profile: '{profile_str}'. Allowed: host_discovery, safe_tcp_scan, service_detection"
            ))),
        }
    }

    /// Extract and validate the target from params.
    fn parse_target(params: &Value) -> Result<String, ToolError> {
        let target = params
            .get("target")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput("Missing 'target' parameter".to_string()))?;

        // Basic target validation — no shell metacharacters
        if target.contains(';')
            || target.contains('|')
            || target.contains('&')
            || target.contains('`')
            || target.contains('$')
            || target.contains('(')
            || target.contains(')')
            || target.contains('\n')
            || target.contains('\r')
        {
            return Err(ToolError::InvalidInput(
                "Target contains forbidden characters".to_string(),
            ));
        }

        if target.is_empty() || target.len() > 255 {
            return Err(ToolError::InvalidInput(
                "Target must be 1-255 characters".to_string(),
            ));
        }

        Ok(target.to_string())
    }
}

#[async_trait::async_trait]
impl ToolExecutorTrait for NmapExecutor {
    fn validate_input(&self, params: &Value) -> Result<(), ToolError> {
        Self::parse_profile(params)?;
        Self::parse_target(params)?;
        Ok(())
    }

    async fn execute(&self, params: &Value) -> Result<ToolOutput, ToolError> {
        let profile = Self::parse_profile(params)?;
        let target = Self::parse_target(params)?;
        let scan_id = Uuid::now_v7();

        // Create output file path
        let output_file = format!("{}/nmap_{}_{}.xml", self.config.artifact_dir, scan_id, chrono::Utc::now().format("%Y%m%d_%H%M%S"));

        info!(
            scan_id = %scan_id,
            profile = %profile,
            target = %target,
            output_file = %output_file,
            "Starting Nmap execution"
        );

        // Build safe command arguments
        let args = build_nmap_args(&profile, &target, &output_file);

        info!(
            scan_id = %scan_id,
            binary = %self.config.binary_path,
            args = ?args,
            "Nmap command constructed"
        );

        // Execute Nmap with timeout — using Command (no shell)
        let result = tokio::time::timeout(
            Duration::from_secs(self.config.timeout_secs),
            Command::new(&self.config.binary_path)
                .args(&args)
                .output(),
        )
        .await;

        let output = match result {
            Ok(Ok(output)) => output,
            Ok(Err(e)) => {
                error!(scan_id = %scan_id, error = %e, "Nmap execution IO error");
                return Err(ToolError::ExecutionFailed(format!("Nmap IO error: {e}")));
            }
            Err(_) => {
                error!(
                    scan_id = %scan_id,
                    timeout = self.config.timeout_secs,
                    "Nmap execution timed out"
                );
                return Err(ToolError::Timeout(self.config.timeout_secs));
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if !output.status.success() {
            warn!(
                scan_id = %scan_id,
                exit_code = ?output.status.code(),
                stderr = %stderr,
                "Nmap exited with non-zero status"
            );
            // Non-zero can still produce valid partial results, so we continue
        }

        // Read the XML output file
        let xml_content = match tokio::fs::read_to_string(&output_file).await {
            Ok(content) => content,
            Err(e) => {
                error!(scan_id = %scan_id, error = %e, "Failed to read Nmap XML output");
                return Err(ToolError::ParseError(format!(
                    "Failed to read Nmap output file: {e}"
                )));
            }
        };

        // Parse XML into structured findings
        let hosts = parse_nmap_xml(&xml_content)?;

        let total_ports: usize = hosts.iter().map(|h| h.ports.len()).sum();
        let hosts_up: usize = hosts.iter().filter(|h| h.status == "up").count();

        let summary = format!(
            "Scan complete: {} hosts found ({} up), {} ports detected",
            hosts.len(),
            hosts_up,
            total_ports
        );

        info!(scan_id = %scan_id, summary = %summary, "Nmap scan completed");

        // Convert to JSON for normalized output
        let data = serde_json::json!({
            "scan_id": scan_id.to_string(),
            "profile": profile.to_string(),
            "target": target,
            "hosts_total": hosts.len(),
            "hosts_up": hosts_up,
            "total_ports": total_ports,
            "hosts": hosts.iter().map(|h| serde_json::json!({
                "ip_address": h.ip_address,
                "hostname": h.hostname,
                "status": h.status,
                "os_fingerprint": h.os_fingerprint,
                "ports": h.ports.iter().map(|p| serde_json::json!({
                    "port": p.port_number,
                    "protocol": p.protocol,
                    "state": p.state,
                    "service_name": p.service_name,
                    "service_version": p.service_version,
                    "service_product": p.service_product,
                })).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
        });

        Ok(ToolOutput {
            data,
            raw_output: Some(xml_content),
            summary,
        })
    }

    fn tool_id(&self) -> &str {
        "nmap"
    }

    fn tool_version(&self) -> &str {
        "1.0.0"
    }
}
