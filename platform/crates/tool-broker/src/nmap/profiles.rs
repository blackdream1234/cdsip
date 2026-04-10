//! Nmap scan profiles — the ONLY allowed scan configurations.
//!
//! No arbitrary Nmap flags are ever accepted from users.
//! Each profile maps to a fixed set of safe arguments.

use cdsip_domain_models::scan::ScanProfile;

/// Build the full Nmap command arguments for a given profile and target.
/// The target is appended last. The -oX flag is always added for XML output.
pub fn build_nmap_args(profile: &ScanProfile, target: &str, output_file: &str) -> Vec<String> {
    let mut args: Vec<String> = Vec::new();

    // Profile-specific flags (hardcoded, not user-controlled)
    for flag in profile.nmap_flags() {
        args.push(flag.to_string());
    }

    // Always output XML for parsing
    args.push("-oX".to_string());
    args.push(output_file.to_string());

    // Target is always the last argument
    args.push(target.to_string());

    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_discovery_args() {
        let args = build_nmap_args(
            &ScanProfile::HostDiscovery,
            "192.168.100.0/24",
            "/tmp/scan.xml",
        );
        assert!(args.contains(&"-sn".to_string()));
        assert!(args.contains(&"-oX".to_string()));
        assert!(args.contains(&"/tmp/scan.xml".to_string()));
        assert_eq!(args.last().unwrap(), "192.168.100.0/24");
        // Must NOT contain any dangerous flags
        assert!(!args.contains(&"-O".to_string()));
        assert!(!args.contains(&"--script".to_string()));
        assert!(!args.iter().any(|a| a.contains("--script")));
    }

    #[test]
    fn test_safe_tcp_scan_args() {
        let args = build_nmap_args(
            &ScanProfile::SafeTcpScan,
            "192.168.100.10",
            "/tmp/scan.xml",
        );
        assert!(args.contains(&"-sT".to_string()));
        assert!(args.contains(&"--top-ports".to_string()));
        assert!(args.contains(&"1000".to_string()));
    }

    #[test]
    fn test_service_detection_args() {
        let args = build_nmap_args(
            &ScanProfile::ServiceDetection,
            "192.168.100.10",
            "/tmp/scan.xml",
        );
        assert!(args.contains(&"-sV".to_string()));
        assert!(args.contains(&"--version-intensity".to_string()));
    }
}
