// Copyright 2024-2025. Fidelis Machines, LLC
// SPDX-License-Identifier: GPL-2.0-only

//! Suricata rule parsing and manipulation

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

/// A parsed Suricata rule
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Rule {
    /// Full original rule text
    pub raw: String,
    /// Rule SID
    pub sid: u64,
    /// Rule GID (default 1)
    pub gid: u32,
    /// Rule revision
    pub rev: u32,
    /// Rule message
    pub msg: String,
    /// Whether the rule is enabled (not commented out)
    pub enabled: bool,
    /// Rule action (alert, drop, pass, etc.)
    pub action: String,
    /// Source file
    pub source: String,
}

impl Rule {
    /// Parse a rule from a line of text
    pub fn parse(line: &str, source: &str) -> Option<Self> {
        let trimmed = line.trim();

        // Skip empty lines and pure comments
        if trimmed.is_empty() {
            return None;
        }

        // Check if rule is disabled (commented out)
        let (enabled, rule_text) = if trimmed.starts_with('#') {
            // Check if it's a commented-out rule vs a regular comment
            let uncommented = trimmed.trim_start_matches('#').trim();
            if is_rule_line(uncommented) {
                (false, uncommented)
            } else {
                return None; // Regular comment, not a rule
            }
        } else if is_rule_line(trimmed) {
            (true, trimmed)
        } else {
            return None;
        };

        // Extract action
        let action = rule_text.split_whitespace().next()?.to_string();

        // Extract SID
        let sid = extract_option(rule_text, "sid")
            .and_then(|s| s.parse().ok())?;

        // Extract other fields
        let gid = extract_option(rule_text, "gid")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);

        let rev = extract_option(rule_text, "rev")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);

        let msg = extract_option(rule_text, "msg")
            .map(|s| s.trim_matches('"').to_string())
            .unwrap_or_default();

        Some(Rule {
            raw: line.to_string(),
            sid,
            gid,
            rev,
            msg,
            enabled,
            action,
            source: source.to_string(),
        })
    }

    /// Render the rule as a string
    pub fn render(&self) -> String {
        if self.enabled {
            // Return raw without leading # if it had one
            self.raw.trim_start_matches('#').trim().to_string()
        } else {
            // Ensure it's commented
            if self.raw.trim().starts_with('#') {
                self.raw.clone()
            } else {
                format!("# {}", self.raw)
            }
        }
    }
}

/// Check if a line looks like a Suricata rule
fn is_rule_line(line: &str) -> bool {
    let actions = ["alert", "drop", "pass", "reject", "rejectsrc", "rejectdst", "rejectboth"];
    let first_word = line.split_whitespace().next().unwrap_or("");
    actions.contains(&first_word)
}

/// Extract an option value from a rule
fn extract_option(rule: &str, option: &str) -> Option<String> {
    let pattern = format!("{}:", option);

    if let Some(start) = rule.find(&pattern) {
        let after = &rule[start + pattern.len()..];
        // Find the end of the value (semicolon or end of string)
        let end = after.find(';').unwrap_or(after.len());
        Some(after[..end].trim().to_string())
    } else {
        None
    }
}

/// Collection of rules indexed by SID
#[derive(Debug, Default)]
pub struct RuleSet {
    /// Rules indexed by SID
    rules: HashMap<u64, Rule>,
    /// Original order of SIDs
    order: Vec<u64>,
}

#[allow(dead_code)]
impl RuleSet {
    /// Create a new empty ruleset
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a rule to the set (replaces if SID exists)
    pub fn add(&mut self, rule: Rule) {
        let sid = rule.sid;
        if !self.rules.contains_key(&sid) {
            self.order.push(sid);
        }
        self.rules.insert(sid, rule);
    }

    /// Get a rule by SID
    pub fn get(&self, sid: u64) -> Option<&Rule> {
        self.rules.get(&sid)
    }

    /// Get a mutable rule by SID
    pub fn get_mut(&mut self, sid: u64) -> Option<&mut Rule> {
        self.rules.get_mut(&sid)
    }

    /// Disable a rule by SID
    pub fn disable(&mut self, sid: u64) {
        if let Some(rule) = self.rules.get_mut(&sid) {
            rule.enabled = false;
        }
    }

    /// Enable a rule by SID
    pub fn enable(&mut self, sid: u64) {
        if let Some(rule) = self.rules.get_mut(&sid) {
            rule.enabled = true;
        }
    }

    /// Modify a rule's action by SID
    pub fn modify_action(&mut self, sid: u64, action: &str) {
        if let Some(rule) = self.rules.get_mut(&sid) {
            // Replace the action in the raw rule
            let old_action = &rule.action;
            rule.raw = rule.raw.replacen(old_action, action, 1);
            rule.action = action.to_string();
        }
    }

    /// Number of rules
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Number of enabled rules
    pub fn enabled_count(&self) -> usize {
        self.rules.values().filter(|r| r.enabled).count()
    }

    /// Iterate over rules in original order
    pub fn iter(&self) -> impl Iterator<Item = &Rule> {
        self.order.iter().filter_map(|sid| self.rules.get(sid))
    }

    /// Load rules from a .rules file
    pub fn load_file(&mut self, path: &Path) -> Result<usize> {
        let file = File::open(path)
            .with_context(|| format!("Failed to open rules file: {}", path.display()))?;

        let source = path.file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let reader = BufReader::new(file);
        let mut count = 0;

        for line in reader.lines() {
            let line = line?;
            if let Some(rule) = Rule::parse(&line, &source) {
                self.add(rule);
                count += 1;
            }
        }

        Ok(count)
    }

    /// Write rules to a file
    pub fn write_file(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut file = File::create(path)
            .with_context(|| format!("Failed to create rules file: {}", path.display()))?;

        for rule in self.iter() {
            writeln!(file, "{}", rule.render())?;
        }

        Ok(())
    }
}

/// Load all .rules files from a directory
pub fn load_rules_directory(dir: &Path) -> Result<RuleSet> {
    let mut ruleset = RuleSet::new();

    if !dir.exists() {
        return Ok(ruleset);
    }

    for entry in walkdir::WalkDir::new(dir)
        .max_depth(2)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if path.extension().map_or(false, |e| e == "rules") {
            match ruleset.load_file(path) {
                Ok(count) => log::debug!("Loaded {} rules from {}", count, path.display()),
                Err(e) => log::warn!("Failed to load {}: {}", path.display(), e),
            }
        }
    }

    Ok(ruleset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rule() {
        let line = r#"alert http any any -> any any (msg:"Test rule"; sid:1000001; rev:1;)"#;
        let rule = Rule::parse(line, "test.rules").unwrap();

        assert_eq!(rule.sid, 1000001);
        assert_eq!(rule.rev, 1);
        assert_eq!(rule.action, "alert");
        assert!(rule.enabled);
    }

    #[test]
    fn test_parse_disabled_rule() {
        let line = r#"# alert http any any -> any any (msg:"Disabled"; sid:1000002; rev:1;)"#;
        let rule = Rule::parse(line, "test.rules").unwrap();

        assert_eq!(rule.sid, 1000002);
        assert!(!rule.enabled);
    }

    #[test]
    fn test_extract_option() {
        let rule = r#"alert tcp any any -> any any (msg:"Test"; sid:12345; rev:3;)"#;

        assert_eq!(extract_option(rule, "sid"), Some("12345".to_string()));
        assert_eq!(extract_option(rule, "rev"), Some("3".to_string()));
        assert_eq!(extract_option(rule, "msg"), Some("\"Test\"".to_string()));
    }

    #[test]
    fn test_parse_drop_rule() {
        let line = r#"drop tcp any any -> any 443 (msg:"Block HTTPS"; sid:2000001; rev:2;)"#;
        let rule = Rule::parse(line, "test.rules").unwrap();

        assert_eq!(rule.sid, 2000001);
        assert_eq!(rule.rev, 2);
        assert_eq!(rule.action, "drop");
        assert!(rule.enabled);
    }

    #[test]
    fn test_parse_rule_with_gid() {
        let line = r#"alert dns any any -> any any (msg:"DNS query"; gid:3; sid:3000001; rev:1;)"#;
        let rule = Rule::parse(line, "test.rules").unwrap();

        assert_eq!(rule.sid, 3000001);
        assert_eq!(rule.gid, 3);
    }

    #[test]
    fn test_parse_comment_not_rule() {
        let line = "# This is just a comment";
        assert!(Rule::parse(line, "test.rules").is_none());
    }

    #[test]
    fn test_parse_empty_line() {
        assert!(Rule::parse("", "test.rules").is_none());
        assert!(Rule::parse("   ", "test.rules").is_none());
    }

    #[test]
    fn test_is_rule_line() {
        assert!(is_rule_line("alert tcp any any -> any any ()"));
        assert!(is_rule_line("drop udp any any -> any any ()"));
        assert!(is_rule_line("pass icmp any any -> any any ()"));
        assert!(is_rule_line("reject tcp any any -> any any ()"));
        assert!(!is_rule_line("# comment"));
        assert!(!is_rule_line("random text"));
    }

    #[test]
    fn test_ruleset_add_and_len() {
        let mut ruleset = RuleSet::new();
        assert_eq!(ruleset.len(), 0);

        let rule1 = Rule::parse(
            r#"alert tcp any any -> any any (msg:"Test1"; sid:1; rev:1;)"#,
            "test.rules",
        )
        .unwrap();
        ruleset.add(rule1);
        assert_eq!(ruleset.len(), 1);

        let rule2 = Rule::parse(
            r#"alert tcp any any -> any any (msg:"Test2"; sid:2; rev:1;)"#,
            "test.rules",
        )
        .unwrap();
        ruleset.add(rule2);
        assert_eq!(ruleset.len(), 2);
    }

    #[test]
    fn test_ruleset_disable_enable() {
        let mut ruleset = RuleSet::new();
        let rule = Rule::parse(
            r#"alert tcp any any -> any any (msg:"Test"; sid:100; rev:1;)"#,
            "test.rules",
        )
        .unwrap();
        ruleset.add(rule);

        assert!(ruleset.get(100).unwrap().enabled);

        ruleset.disable(100);
        assert!(!ruleset.get(100).unwrap().enabled);

        ruleset.enable(100);
        assert!(ruleset.get(100).unwrap().enabled);
    }

    #[test]
    fn test_ruleset_modify_action() {
        let mut ruleset = RuleSet::new();
        let rule = Rule::parse(
            r#"alert tcp any any -> any any (msg:"Test"; sid:200; rev:1;)"#,
            "test.rules",
        )
        .unwrap();
        ruleset.add(rule);

        assert_eq!(ruleset.get(200).unwrap().action, "alert");

        ruleset.modify_action(200, "drop");
        assert_eq!(ruleset.get(200).unwrap().action, "drop");
    }

    #[test]
    fn test_ruleset_enabled_count() {
        let mut ruleset = RuleSet::new();

        let rule1 = Rule::parse(
            r#"alert tcp any any -> any any (msg:"Enabled"; sid:1; rev:1;)"#,
            "test.rules",
        )
        .unwrap();
        let rule2 = Rule::parse(
            r#"# alert tcp any any -> any any (msg:"Disabled"; sid:2; rev:1;)"#,
            "test.rules",
        )
        .unwrap();

        ruleset.add(rule1);
        ruleset.add(rule2);

        assert_eq!(ruleset.len(), 2);
        assert_eq!(ruleset.enabled_count(), 1);
    }

    #[test]
    fn test_rule_render_enabled() {
        let rule = Rule::parse(
            r#"alert tcp any any -> any any (msg:"Test"; sid:1; rev:1;)"#,
            "test.rules",
        )
        .unwrap();

        let rendered = rule.render();
        assert!(rendered.starts_with("alert"));
        assert!(!rendered.starts_with("#"));
    }

    #[test]
    fn test_rule_render_disabled() {
        let rule = Rule::parse(
            r#"# alert tcp any any -> any any (msg:"Test"; sid:1; rev:1;)"#,
            "test.rules",
        )
        .unwrap();

        let rendered = rule.render();
        assert!(rendered.starts_with("#"));
    }
}
