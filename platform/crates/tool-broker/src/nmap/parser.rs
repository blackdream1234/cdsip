//! Nmap XML output parser.
//!
//! Parses Nmap XML output into normalized scan findings.

use serde::Deserialize;
use crate::types::ToolError;

/// Parsed host from Nmap XML.
#[derive(Debug, Clone)]
pub struct ParsedHost {
    pub ip_address: String,
    pub hostname: Option<String>,
    pub status: String,
    pub ports: Vec<ParsedPort>,
    pub os_fingerprint: Option<String>,
}

/// Parsed port from Nmap XML.
#[derive(Debug, Clone)]
pub struct ParsedPort {
    pub port_number: i32,
    pub protocol: String,
    pub state: String,
    pub service_name: Option<String>,
    pub service_version: Option<String>,
    pub service_product: Option<String>,
}

/// Parse Nmap XML output into structured findings.
pub fn parse_nmap_xml(xml_content: &str) -> Result<Vec<ParsedHost>, ToolError> {
    let mut hosts = Vec::new();

    // Use a simple state-machine parser for reliability
    // (quick-xml with serde can be fragile with Nmap's varying XML schema)
    let mut reader = quick_xml::Reader::from_str(xml_content);
    reader.config_mut().trim_text(true);

    let mut current_host: Option<ParsedHost> = None;
    let mut current_port: Option<ParsedPort> = None;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(quick_xml::events::Event::Start(ref e)) | Ok(quick_xml::events::Event::Empty(ref e)) => {
                match e.name().as_ref() {
                    b"host" => {
                        current_host = Some(ParsedHost {
                            ip_address: String::new(),
                            hostname: None,
                            status: "unknown".to_string(),
                            ports: Vec::new(),
                            os_fingerprint: None,
                        });
                    }
                    b"status" => {
                        if let Some(ref mut host) = current_host {
                            for attr in e.attributes().flatten() {
                                if attr.key.as_ref() == b"state" {
                                    host.status = String::from_utf8_lossy(&attr.value).to_string();
                                }
                            }
                        }
                    }
                    b"address" => {
                        if let Some(ref mut host) = current_host {
                            let mut addr_type = String::new();
                            let mut addr = String::new();
                            for attr in e.attributes().flatten() {
                                match attr.key.as_ref() {
                                    b"addrtype" => addr_type = String::from_utf8_lossy(&attr.value).to_string(),
                                    b"addr" => addr = String::from_utf8_lossy(&attr.value).to_string(),
                                    _ => {}
                                }
                            }
                            if addr_type == "ipv4" || addr_type == "ipv6" {
                                host.ip_address = addr;
                            }
                        }
                    }
                    b"hostname" => {
                        if let Some(ref mut host) = current_host {
                            for attr in e.attributes().flatten() {
                                if attr.key.as_ref() == b"name" {
                                    host.hostname = Some(String::from_utf8_lossy(&attr.value).to_string());
                                }
                            }
                        }
                    }
                    b"port" => {
                        let mut port = ParsedPort {
                            port_number: 0,
                            protocol: "tcp".to_string(),
                            state: "unknown".to_string(),
                            service_name: None,
                            service_version: None,
                            service_product: None,
                        };
                        for attr in e.attributes().flatten() {
                            match attr.key.as_ref() {
                                b"portid" => {
                                    port.port_number = String::from_utf8_lossy(&attr.value)
                                        .parse()
                                        .unwrap_or(0);
                                }
                                b"protocol" => {
                                    port.protocol = String::from_utf8_lossy(&attr.value).to_string();
                                }
                                _ => {}
                            }
                        }
                        current_port = Some(port);
                    }
                    b"state" => {
                        if let Some(ref mut port) = current_port {
                            for attr in e.attributes().flatten() {
                                if attr.key.as_ref() == b"state" {
                                    port.state = String::from_utf8_lossy(&attr.value).to_string();
                                }
                            }
                        }
                    }
                    b"service" => {
                        if let Some(ref mut port) = current_port {
                            for attr in e.attributes().flatten() {
                                match attr.key.as_ref() {
                                    b"name" => {
                                        port.service_name = Some(String::from_utf8_lossy(&attr.value).to_string());
                                    }
                                    b"version" => {
                                        port.service_version = Some(String::from_utf8_lossy(&attr.value).to_string());
                                    }
                                    b"product" => {
                                        port.service_product = Some(String::from_utf8_lossy(&attr.value).to_string());
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    b"osmatch" => {
                        if let Some(ref mut host) = current_host {
                            for attr in e.attributes().flatten() {
                                if attr.key.as_ref() == b"name" {
                                    host.os_fingerprint = Some(String::from_utf8_lossy(&attr.value).to_string());
                                    break; // Take the first (highest confidence) match
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(quick_xml::events::Event::End(ref e)) => {
                match e.name().as_ref() {
                    b"host" => {
                        if let Some(host) = current_host.take() {
                            if !host.ip_address.is_empty() {
                                hosts.push(host);
                            }
                        }
                    }
                    b"port" => {
                        if let (Some(ref mut host), Some(port)) = (&mut current_host, current_port.take()) {
                            host.ports.push(port);
                        }
                    }
                    _ => {}
                }
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Err(e) => {
                return Err(ToolError::ParseError(format!(
                    "Failed to parse Nmap XML: {e}"
                )));
            }
            _ => {}
        }
        buf.clear();
    }

    Ok(hosts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_nmap_xml() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.100.10" addrtype="ipv4"/>
    <hostnames><hostname name="test-host" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="up"/>
    <address addr="192.168.100.11" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="3306">
        <state state="open"/>
        <service name="mysql" product="MySQL" version="8.0"/>
      </port>
    </ports>
  </host>
</nmaprun>"#;

        let hosts = parse_nmap_xml(xml).unwrap();
        assert_eq!(hosts.len(), 2);

        let host1 = &hosts[0];
        assert_eq!(host1.ip_address, "192.168.100.10");
        assert_eq!(host1.hostname.as_deref(), Some("test-host"));
        assert_eq!(host1.status, "up");
        assert_eq!(host1.ports.len(), 3);

        let ssh = &host1.ports[0];
        assert_eq!(ssh.port_number, 22);
        assert_eq!(ssh.state, "open");
        assert_eq!(ssh.service_name.as_deref(), Some("ssh"));
        assert_eq!(ssh.service_version.as_deref(), Some("8.9"));

        let host2 = &hosts[1];
        assert_eq!(host2.ip_address, "192.168.100.11");
        assert_eq!(host2.ports.len(), 1);
        assert_eq!(host2.ports[0].service_name.as_deref(), Some("mysql"));
    }

    #[test]
    fn test_parse_discovery_only() {
        let xml = r#"<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.100.1" addrtype="ipv4"/>
  </host>
  <host>
    <status state="down"/>
    <address addr="192.168.100.2" addrtype="ipv4"/>
  </host>
</nmaprun>"#;

        let hosts = parse_nmap_xml(xml).unwrap();
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].status, "up");
        assert_eq!(hosts[1].status, "down");
        assert!(hosts[0].ports.is_empty());
    }

    #[test]
    fn test_parse_empty_xml() {
        let xml = r#"<?xml version="1.0"?><nmaprun></nmaprun>"#;
        let hosts = parse_nmap_xml(xml).unwrap();
        assert!(hosts.is_empty());
    }
}
