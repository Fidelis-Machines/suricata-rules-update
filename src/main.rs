// Copyright 2024-2025. Fidelis Machines, LLC
// SPDX-License-Identifier: GPL-2.0-only

//! Suricata Update - Rule management tool for Suricata
//!
//! Downloads, merges, and manages Suricata rule files from various sources.

mod config;
mod rules;
mod sources;
mod update;

use anyhow::Result;
use clap::Parser;
use log::info;

#[derive(Parser, Debug)]
#[command(name = "suricata-rules-update")]
#[command(about = "Update Suricata rules from various sources (Rust implementation)")]
#[command(version)]
struct Args {
    /// Path to suricata.yaml configuration
    #[arg(short = 'c', long, default_value = "/etc/suricata/suricata.yaml")]
    config: String,

    /// Output directory for rules
    #[arg(short = 'o', long, default_value = "/var/lib/suricata/rules")]
    output: String,

    /// Data directory for caches and state
    #[arg(long, default_value = "/var/lib/suricata")]
    data_dir: String,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Force update even if rules are current
    #[arg(short, long)]
    force: bool,

    /// Reload Suricata after update
    #[arg(long)]
    reload: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// List available rule sources
    ListSources,

    /// Enable a rule source
    EnableSource {
        /// Source name to enable
        name: String,
    },

    /// Disable a rule source
    DisableSource {
        /// Source name to disable
        name: String,
    },

    /// Update source index
    UpdateSources,

    /// Check for rule updates without downloading
    CheckVersion,

    /// Add a local rule file
    AddSource {
        /// Path or URL to rule source
        source: String,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let log_level = if args.verbose { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();

    info!("Suricata Update starting");

    match args.command {
        Some(Commands::ListSources) => {
            sources::list_sources(&args.data_dir)?;
        }
        Some(Commands::EnableSource { name }) => {
            sources::enable_source(&args.data_dir, &name)?;
        }
        Some(Commands::DisableSource { name }) => {
            sources::disable_source(&args.data_dir, &name)?;
        }
        Some(Commands::UpdateSources) => {
            sources::update_index(&args.data_dir)?;
        }
        Some(Commands::CheckVersion) => {
            update::check_version(&args.data_dir)?;
        }
        Some(Commands::AddSource { source }) => {
            sources::add_source(&args.data_dir, &source)?;
        }
        None => {
            // Default: update rules
            update::run_update(&args.config, &args.output, &args.data_dir, args.force)?;

            if args.reload {
                update::reload_suricata()?;
            }
        }
    }

    Ok(())
}
