// Copyright 2024-2025. Fidelis Machines, LLC
// SPDX-License-Identifier: GPL-2.0-only

//! Rule source management

use crate::config::{RuleSource, SourceIndex, UpdateConfig};
use anyhow::{bail, Context, Result};
use std::path::Path;

const SOURCE_INDEX_URL: &str =
    "https://www.openinfosecfoundation.org/rules/index.yaml";

/// List all available sources
pub fn list_sources(data_dir: &str) -> Result<()> {
    let index_path = Path::new(data_dir).join("update").join("sources.yaml");
    let config_path = Path::new(data_dir).join("update").join("config.yaml");

    // Load source index (use builtin if not downloaded yet)
    let index = if index_path.exists() {
        SourceIndex::load(&index_path)?
    } else {
        SourceIndex::builtin()
    };

    // Load user config to see what's enabled
    let config = UpdateConfig::load(&config_path).unwrap_or_default();
    let enabled_sources: std::collections::HashSet<_> = config.sources.iter().collect();

    println!("Available rule sources:\n");
    println!("{:<30} {:<10} {}", "Name", "Status", "Summary");
    println!("{}", "-".repeat(70));

    for source in &index.sources {
        let status = if enabled_sources.contains(&source.name) || source.enabled {
            "enabled"
        } else {
            "disabled"
        };

        let summary = source.summary.as_deref().unwrap_or("");
        println!("{:<30} {:<10} {}", source.name, status, summary);
    }

    println!("\nUse 'suricata-rules-update enable-source <name>' to enable a source");
    println!("Use 'suricata-rules-update disable-source <name>' to disable a source");

    Ok(())
}

/// Enable a rule source
pub fn enable_source(data_dir: &str, name: &str) -> Result<()> {
    let index_path = Path::new(data_dir).join("update").join("sources.yaml");
    let config_path = Path::new(data_dir).join("update").join("config.yaml");

    // Load source index
    let index = if index_path.exists() {
        SourceIndex::load(&index_path)?
    } else {
        SourceIndex::builtin()
    };

    // Verify source exists
    if !index.sources.iter().any(|s| s.name == name) {
        bail!("Unknown source: {}. Use 'list-sources' to see available sources.", name);
    }

    // Update config
    let mut config = UpdateConfig::load(&config_path).unwrap_or_default();

    if !config.sources.contains(&name.to_string()) {
        config.sources.push(name.to_string());
        config.save(&config_path)?;
        log::info!("Enabled source: {}", name);
        println!("Enabled source: {}", name);
    } else {
        println!("Source {} is already enabled", name);
    }

    Ok(())
}

/// Disable a rule source
pub fn disable_source(data_dir: &str, name: &str) -> Result<()> {
    let config_path = Path::new(data_dir).join("update").join("config.yaml");

    let mut config = UpdateConfig::load(&config_path).unwrap_or_default();

    if let Some(pos) = config.sources.iter().position(|s| s == name) {
        config.sources.remove(pos);
        config.save(&config_path)?;
        log::info!("Disabled source: {}", name);
        println!("Disabled source: {}", name);
    } else {
        println!("Source {} is not enabled", name);
    }

    Ok(())
}

/// Update the source index from OISF
pub fn update_index(data_dir: &str) -> Result<()> {
    let index_path = Path::new(data_dir).join("update").join("sources.yaml");

    log::info!("Downloading source index from {}", SOURCE_INDEX_URL);
    println!("Downloading source index...");

    let response = reqwest::blocking::get(SOURCE_INDEX_URL)
        .context("Failed to download source index")?;

    if !response.status().is_success() {
        bail!("Failed to download source index: HTTP {}", response.status());
    }

    let content = response.text()?;

    // Validate it's valid YAML
    let _: serde_yaml::Value = serde_yaml::from_str(&content)
        .context("Downloaded index is not valid YAML")?;

    // Save to disk
    if let Some(parent) = index_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&index_path, &content)?;

    println!("Updated source index at {}", index_path.display());

    Ok(())
}

/// Add a custom source
pub fn add_source(data_dir: &str, source: &str) -> Result<()> {
    let index_path = Path::new(data_dir).join("update").join("sources.yaml");
    let config_path = Path::new(data_dir).join("update").join("config.yaml");

    // Determine if it's a URL or local file
    let is_url = source.starts_with("http://") || source.starts_with("https://");

    // Create a source name from the path/URL
    let name = if is_url {
        let url = url::Url::parse(source).context("Invalid URL")?;
        format!("custom/{}", url.host_str().unwrap_or("unknown"))
    } else {
        format!("local/{}", Path::new(source)
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "custom".to_string()))
    };

    // Load or create source index
    let mut index = if index_path.exists() {
        SourceIndex::load(&index_path)?
    } else {
        SourceIndex::builtin()
    };

    // Check if already exists
    if index.sources.iter().any(|s| s.url == source) {
        println!("Source already exists in index");
    } else {
        let new_source = RuleSource {
            name: name.clone(),
            url: source.to_string(),
            enabled: false,
            license: None,
            vendor: Some("Custom".to_string()),
            summary: Some(format!("Custom source: {}", source)),
        };

        index.sources.push(new_source);
        index.save(&index_path)?;
        println!("Added source: {}", name);
    }

    // Enable it
    let mut config = UpdateConfig::load(&config_path).unwrap_or_default();
    if !config.sources.contains(&name) {
        config.sources.push(name.clone());
        config.save(&config_path)?;
        println!("Enabled source: {}", name);
    }

    Ok(())
}

/// Get enabled sources with their URLs
pub fn get_enabled_sources(data_dir: &str) -> Result<Vec<RuleSource>> {
    let index_path = Path::new(data_dir).join("update").join("sources.yaml");
    let config_path = Path::new(data_dir).join("update").join("config.yaml");

    let index = if index_path.exists() {
        SourceIndex::load(&index_path)?
    } else {
        SourceIndex::builtin()
    };

    let config = UpdateConfig::load(&config_path).unwrap_or_default();

    let mut enabled = Vec::new();

    for source in &index.sources {
        // Source is enabled if:
        // 1. It's in the config.sources list, OR
        // 2. It has enabled=true by default AND not explicitly disabled
        if config.sources.contains(&source.name) || source.enabled {
            enabled.push(source.clone());
        }
    }

    Ok(enabled)
}
