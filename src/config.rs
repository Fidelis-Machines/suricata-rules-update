// Copyright 2024-2025. Fidelis Machines, LLC
// SPDX-License-Identifier: GPL-2.0-only

//! Configuration handling for suricata-update

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Main configuration for suricata-update
#[derive(Debug, Deserialize, Serialize, Default)]
pub struct UpdateConfig {
    /// Enabled rule sources
    #[serde(default)]
    pub sources: Vec<String>,

    /// Disabled rule SIDs
    #[serde(default)]
    pub disable_sid: Vec<u64>,

    /// Enabled rule SIDs (overrides disabled)
    #[serde(default)]
    pub enable_sid: Vec<u64>,

    /// Rule modifications (sid -> action)
    #[serde(default)]
    pub modify_sid: Vec<SidModification>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SidModification {
    pub sid: u64,
    pub action: String,
}

/// Rule source definition
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuleSource {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub vendor: Option<String>,
    #[serde(default)]
    pub summary: Option<String>,
}

/// Source index containing available rule sources
#[derive(Debug, Deserialize, Serialize, Default)]
pub struct SourceIndex {
    pub version: u32,
    pub sources: Vec<RuleSource>,
}

impl UpdateConfig {
    /// Load configuration from YAML file
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config: {}", path.display()))?;

        serde_yaml::from_str(&content)
            .with_context(|| format!("Failed to parse config: {}", path.display()))
    }

    /// Save configuration to YAML file
    pub fn save(&self, path: &Path) -> Result<()> {
        let content = serde_yaml::to_string(self).context("Failed to serialize config")?;

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(path, content)
            .with_context(|| format!("Failed to write config: {}", path.display()))
    }
}

impl SourceIndex {
    /// Load source index from YAML file
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read source index: {}", path.display()))?;

        serde_yaml::from_str(&content)
            .with_context(|| format!("Failed to parse source index: {}", path.display()))
    }

    /// Save source index to YAML file
    pub fn save(&self, path: &Path) -> Result<()> {
        let content = serde_yaml::to_string(self).context("Failed to serialize source index")?;

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(path, content)
            .with_context(|| format!("Failed to write source index: {}", path.display()))
    }

    /// Get built-in source index (ET Open rules)
    pub fn builtin() -> Self {
        Self {
            version: 1,
            sources: vec![
                RuleSource {
                    name: "et/open".to_string(),
                    url: "https://rules.emergingthreats.net/open/suricata-%version%/emerging.rules.tar.gz".to_string(),
                    enabled: true,
                    license: Some("MIT".to_string()),
                    vendor: Some("Proofpoint".to_string()),
                    summary: Some("Emerging Threats Open Ruleset".to_string()),
                },
                RuleSource {
                    name: "oisf/trafficid".to_string(),
                    url: "https://openinfosecfoundation.org/rules/trafficid/trafficid.rules".to_string(),
                    enabled: false,
                    license: Some("MIT".to_string()),
                    vendor: Some("OISF".to_string()),
                    summary: Some("Traffic ID rules for protocol detection".to_string()),
                },
                RuleSource {
                    name: "ptresearch/attackdetection".to_string(),
                    url: "https://raw.githubusercontent.com/ptresearch/AttackDetection/master/pt.rules.tar.gz".to_string(),
                    enabled: false,
                    license: Some("Custom".to_string()),
                    vendor: Some("Positive Technologies".to_string()),
                    summary: Some("PT Attack Detection Team ruleset".to_string()),
                },
                RuleSource {
                    name: "sslbl/ssl-fp-blacklist".to_string(),
                    url: "https://sslbl.abuse.ch/blacklist/sslblacklist.rules".to_string(),
                    enabled: false,
                    license: Some("Non-Commercial".to_string()),
                    vendor: Some("abuse.ch".to_string()),
                    summary: Some("SSL Fingerprint Blacklist".to_string()),
                },
            ],
        }
    }
}

/// Parse Suricata version from suricata.yaml
pub fn get_suricata_version(config_path: &Path) -> Result<String> {
    // Try to run suricata --build-info first
    if let Ok(output) = std::process::Command::new("suricata")
        .arg("--build-info")
        .output()
    {
        let output_str = String::from_utf8_lossy(&output.stdout);
        for line in output_str.lines() {
            if line.contains("Suricata version:") {
                if let Some(version) = line.split(':').nth(1) {
                    let version = version.trim();
                    // Extract major.minor (e.g., "7.0" from "7.0.3")
                    let parts: Vec<&str> = version.split('.').collect();
                    if parts.len() >= 2 {
                        return Ok(format!("{}.{}", parts[0], parts[1]));
                    }
                }
            }
        }
    }

    // Fallback to reading from yaml
    let content = fs::read_to_string(config_path)
        .with_context(|| format!("Failed to read Suricata config: {}", config_path.display()))?;

    // Look for a version hint in the config, default to 7.0
    if content.contains("suricata-7") || content.contains("7.0") {
        Ok("7.0".to_string())
    } else if content.contains("suricata-8") || content.contains("8.0") {
        Ok("8.0".to_string())
    } else {
        Ok("7.0".to_string()) // Default
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_update_config_default() {
        let config = UpdateConfig::default();
        assert!(config.sources.is_empty());
        assert!(config.disable_sid.is_empty());
        assert!(config.enable_sid.is_empty());
        assert!(config.modify_sid.is_empty());
    }

    #[test]
    fn test_update_config_load_nonexistent() {
        let path = Path::new("/nonexistent/config.yaml");
        let config = UpdateConfig::load(path).unwrap();
        assert!(config.sources.is_empty());
    }

    #[test]
    fn test_update_config_save_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.yaml");

        let config = UpdateConfig {
            sources: vec!["et/open".to_string(), "oisf/trafficid".to_string()],
            disable_sid: vec![1000001, 1000002],
            enable_sid: vec![2000001],
            modify_sid: vec![SidModification {
                sid: 3000001,
                action: "drop".to_string(),
            }],
        };

        config.save(&config_path).unwrap();
        let loaded = UpdateConfig::load(&config_path).unwrap();

        assert_eq!(loaded.sources, config.sources);
        assert_eq!(loaded.disable_sid, config.disable_sid);
        assert_eq!(loaded.enable_sid, config.enable_sid);
        assert_eq!(loaded.modify_sid.len(), 1);
        assert_eq!(loaded.modify_sid[0].sid, 3000001);
        assert_eq!(loaded.modify_sid[0].action, "drop");
    }

    #[test]
    fn test_source_index_default() {
        let index = SourceIndex::default();
        assert_eq!(index.version, 0);
        assert!(index.sources.is_empty());
    }

    #[test]
    fn test_source_index_builtin() {
        let index = SourceIndex::builtin();
        assert_eq!(index.version, 1);
        assert!(!index.sources.is_empty());

        let et_open = index.sources.iter().find(|s| s.name == "et/open");
        assert!(et_open.is_some());
        assert!(et_open.unwrap().enabled);
    }

    #[test]
    fn test_source_index_save_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let index_path = temp_dir.path().join("sources.yaml");

        let index = SourceIndex {
            version: 2,
            sources: vec![RuleSource {
                name: "test/source".to_string(),
                url: "https://example.com/rules.tar.gz".to_string(),
                enabled: true,
                license: Some("MIT".to_string()),
                vendor: Some("Test Vendor".to_string()),
                summary: Some("Test ruleset".to_string()),
            }],
        };

        index.save(&index_path).unwrap();
        let loaded = SourceIndex::load(&index_path).unwrap();

        assert_eq!(loaded.version, 2);
        assert_eq!(loaded.sources.len(), 1);
        assert_eq!(loaded.sources[0].name, "test/source");
        assert!(loaded.sources[0].enabled);
    }

    #[test]
    fn test_source_index_load_nonexistent() {
        let path = Path::new("/nonexistent/sources.yaml");
        let index = SourceIndex::load(path).unwrap();
        assert_eq!(index.version, 0);
        assert!(index.sources.is_empty());
    }

    #[test]
    fn test_rule_source_optional_fields() {
        let yaml = r#"
name: minimal/source
url: https://example.com/rules
"#;
        let source: RuleSource = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(source.name, "minimal/source");
        assert!(!source.enabled);
        assert!(source.license.is_none());
        assert!(source.vendor.is_none());
        assert!(source.summary.is_none());
    }

    #[test]
    fn test_get_suricata_version_from_config() {
        let temp_dir = TempDir::new().unwrap();

        // Test suricata-7 detection
        let config7 = temp_dir.path().join("suricata7.yaml");
        let mut f = std::fs::File::create(&config7).unwrap();
        writeln!(f, "# suricata-7 config").unwrap();
        assert_eq!(get_suricata_version(&config7).unwrap(), "7.0");

        // Test suricata-8 detection
        let config8 = temp_dir.path().join("suricata8.yaml");
        let mut f = std::fs::File::create(&config8).unwrap();
        writeln!(f, "# suricata-8 config").unwrap();
        assert_eq!(get_suricata_version(&config8).unwrap(), "8.0");

        // Test default version
        let config_default = temp_dir.path().join("suricata.yaml");
        let mut f = std::fs::File::create(&config_default).unwrap();
        writeln!(f, "# generic config").unwrap();
        assert_eq!(get_suricata_version(&config_default).unwrap(), "7.0");
    }
}
