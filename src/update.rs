// Copyright 2024-2025. Fidelis Machines, LLC
// SPDX-License-Identifier: GPL-2.0-only

//! Rule update logic

use crate::config::{get_suricata_version, UpdateConfig};
use crate::rules::{load_rules_directory, RuleSet};
use crate::sources::get_enabled_sources;
use anyhow::{bail, Context, Result};
use flate2::read::GzDecoder;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;
use tar::Archive;

/// Run the full update process
pub fn run_update(
    config_path: &str,
    output_dir: &str,
    data_dir: &str,
    force: bool,
) -> Result<()> {
    let config_path = Path::new(config_path);
    let output_path = Path::new(output_dir);
    let data_path = Path::new(data_dir);
    let cache_path = data_path.join("update").join("cache");
    let rules_cache = data_path.join("update").join("rules");

    // Create directories
    fs::create_dir_all(&cache_path)?;
    fs::create_dir_all(&rules_cache)?;
    fs::create_dir_all(output_path)?;

    // Get Suricata version for URL substitution
    let version = get_suricata_version(config_path).unwrap_or_else(|_| "7.0".to_string());
    log::info!("Detected Suricata version: {}", version);

    // Get enabled sources
    let sources = get_enabled_sources(data_dir)?;

    if sources.is_empty() {
        println!("No sources enabled. Use 'suricata-update enable-source et/open' to enable a source.");
        return Ok(());
    }

    println!("Updating rules from {} source(s)...", sources.len());

    // Download each source
    for source in &sources {
        let url = source.url.replace("%version%", &version);
        println!("\nSource: {}", source.name);
        println!("  URL: {}", url);

        match download_source(&url, &source.name, &cache_path, &rules_cache, force) {
            Ok(()) => println!("  Downloaded successfully"),
            Err(e) => {
                log::warn!("Failed to download {}: {}", source.name, e);
                println!("  Failed: {}", e);
            }
        }
    }

    // Load all downloaded rules
    println!("\nLoading rules...");
    let mut ruleset = load_rules_directory(&rules_cache)?;
    println!("Loaded {} rules ({} enabled)", ruleset.len(), ruleset.enabled_count());

    // Apply user modifications
    let user_config_path = data_path.join("update").join("config.yaml");
    if let Ok(user_config) = UpdateConfig::load(&user_config_path) {
        apply_modifications(&mut ruleset, &user_config);
    }

    // Load local rules
    let local_rules = data_path.join("rules").join("local.rules");
    if local_rules.exists() {
        let count = ruleset.load_file(&local_rules)?;
        println!("Loaded {} local rules", count);
    }

    // Write merged rules
    let output_file = output_path.join("suricata.rules");
    ruleset.write_file(&output_file)?;
    println!("\nWrote {} rules to {}", ruleset.enabled_count(), output_file.display());

    // Generate classification.config and reference.config if we have them
    copy_support_files(&rules_cache, output_path)?;

    Ok(())
}

/// Download a rule source
fn download_source(
    url: &str,
    name: &str,
    cache_path: &Path,
    rules_path: &Path,
    force: bool,
) -> Result<()> {
    // Generate a safe filename from the source name
    let safe_name = name.replace('/', "-");
    let cache_file = cache_path.join(&safe_name);

    // Check if we have a cached copy and it's recent (unless forced)
    if !force && cache_file.exists() {
        if let Ok(metadata) = cache_file.metadata() {
            if let Ok(modified) = metadata.modified() {
                let age = std::time::SystemTime::now()
                    .duration_since(modified)
                    .unwrap_or_default();

                // Skip if less than 1 hour old
                if age.as_secs() < 3600 {
                    log::debug!("Using cached version ({}s old)", age.as_secs());
                    return Ok(());
                }
            }
        }
    }

    // Download the file
    let response = reqwest::blocking::get(url)
        .with_context(|| format!("Failed to connect to {}", url))?;

    if !response.status().is_success() {
        bail!("HTTP error: {}", response.status());
    }

    let content = response.bytes()?;

    // Save to cache
    fs::write(&cache_file, &content)?;

    // Extract if it's a tarball
    if url.ends_with(".tar.gz") || url.ends_with(".tgz") {
        extract_tarball(&content, name, rules_path)?;
    } else if url.ends_with(".rules") {
        // Single rules file - copy directly
        let dest = rules_path.join(format!("{}.rules", safe_name));
        fs::write(&dest, &content)?;
    } else if url.ends_with(".gz") {
        // Gzipped single file
        let mut decoder = GzDecoder::new(&content[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)?;

        let dest = rules_path.join(format!("{}.rules", safe_name));
        fs::write(&dest, &decompressed)?;
    } else {
        // Assume it's a raw rules file
        let dest = rules_path.join(format!("{}.rules", safe_name));
        fs::write(&dest, &content)?;
    }

    Ok(())
}

/// Extract a .tar.gz archive
fn extract_tarball(data: &[u8], name: &str, rules_path: &Path) -> Result<()> {
    let decoder = GzDecoder::new(data);
    let mut archive = Archive::new(decoder);

    // Create a subdirectory for this source
    let safe_name = name.replace('/', "-");
    let extract_path = rules_path.join(&safe_name);
    fs::create_dir_all(&extract_path)?;

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;

        // Only extract .rules files and config files
        if let Some(ext) = path.extension() {
            let ext_str = ext.to_string_lossy();
            if ext_str == "rules" || ext_str == "config" {
                // Flatten the path - put files directly in extract_path
                if let Some(file_name) = path.file_name() {
                    let dest = extract_path.join(file_name);
                    let mut file = File::create(&dest)?;
                    io::copy(&mut entry, &mut file)?;
                }
            }
        }
    }

    Ok(())
}

/// Apply user modifications (disable, enable, modify)
fn apply_modifications(ruleset: &mut RuleSet, config: &UpdateConfig) {
    // Disable SIDs
    for sid in &config.disable_sid {
        ruleset.disable(*sid);
    }

    // Enable SIDs (overrides disable)
    for sid in &config.enable_sid {
        ruleset.enable(*sid);
    }

    // Modify actions
    for modification in &config.modify_sid {
        ruleset.modify_action(modification.sid, &modification.action);
    }
}

/// Copy classification.config and reference.config if available
fn copy_support_files(rules_cache: &Path, output_path: &Path) -> Result<()> {
    for filename in &["classification.config", "reference.config"] {
        // Search for the file in the rules cache
        for entry in walkdir::WalkDir::new(rules_cache)
            .max_depth(3)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_name().to_string_lossy() == *filename {
                let dest = output_path.join(filename);
                if !dest.exists() {
                    fs::copy(entry.path(), &dest)?;
                    log::info!("Copied {} to {}", filename, output_path.display());
                }
                break;
            }
        }
    }

    Ok(())
}

/// Check for available updates without downloading
pub fn check_version(data_dir: &str) -> Result<()> {
    let sources = get_enabled_sources(data_dir)?;

    if sources.is_empty() {
        println!("No sources enabled.");
        return Ok(());
    }

    println!("Checking {} source(s)...\n", sources.len());

    for source in &sources {
        print!("{}: ", source.name);
        io::stdout().flush()?;

        // Do a HEAD request to check if available
        let client = reqwest::blocking::Client::new();
        match client.head(&source.url).send() {
            Ok(response) => {
                if response.status().is_success() {
                    if let Some(len) = response.headers().get("content-length") {
                        println!("available ({} bytes)", len.to_str().unwrap_or("?"));
                    } else {
                        println!("available");
                    }
                } else {
                    println!("error: HTTP {}", response.status());
                }
            }
            Err(e) => println!("error: {}", e),
        }
    }

    Ok(())
}

/// Reload Suricata using suricatasc
pub fn reload_suricata() -> Result<()> {
    println!("Reloading Suricata rules...");

    let output = std::process::Command::new("suricatasc")
        .args(["-c", "reload-rules"])
        .output()
        .context("Failed to run suricatasc")?;

    if output.status.success() {
        println!("Rules reloaded successfully");
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        log::warn!("suricatasc returned error: {}", stderr);
        println!("Warning: suricatasc returned an error");
    }

    Ok(())
}
