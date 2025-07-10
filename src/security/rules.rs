use crate::core::ProcessInfo;
use crate::security::analyzer::{SecurityFinding, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Security rule for process evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub enabled: bool,
    pub condition: RuleCondition,
    pub recommendations: Vec<String>,
}

/// Rule condition for evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RuleCondition {
    ProcessName { pattern: String },
    ProcessPath { pattern: String },
    NetworkPort { port: u16, direction: String },
    MemoryUsage { threshold_mb: u64 },
    CpuUsage { threshold_percent: f64 },
    UserContext { username: String },
    And { conditions: Vec<RuleCondition> },
    Or { conditions: Vec<RuleCondition> },
    Not { condition: Box<RuleCondition> },
}

/// Collection of security rules
#[derive(Debug, Clone)]
pub struct RuleSet {
    rules: Vec<SecurityRule>,
}

impl RuleSet {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }
    
    pub fn add_rule(&mut self, rule: SecurityRule) {
        self.rules.push(rule);
    }
    
    pub fn evaluate(&self, process: &ProcessInfo) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        
        for rule in &self.rules {
            if rule.enabled && self.evaluate_condition(&rule.condition, process) {
                findings.push(SecurityFinding {
                    pid: process.pid,
                    process_name: process.name.clone(),
                    severity: rule.severity,
                    rule_id: rule.id.clone(),
                    title: rule.name.clone(),
                    description: rule.description.clone(),
                    details: HashMap::new(),
                    recommendations: rule.recommendations.clone(),
                });
            }
        }
        
        findings
    }
    
    fn evaluate_condition(&self, condition: &RuleCondition, process: &ProcessInfo) -> bool {
        match condition {
            RuleCondition::ProcessName { pattern } => {
                process.name.contains(pattern)
            },
            RuleCondition::ProcessPath { pattern } => {
                process.exe_path.as_ref()
                    .map(|p| p.to_string_lossy().contains(pattern))
                    .unwrap_or(false)
            },
            RuleCondition::NetworkPort { port, direction } => {
                match direction.as_str() {
                    "local" => process.connections.iter()
                        .any(|c| c.local_port == *port),
                    "remote" => process.connections.iter()
                        .any(|c| c.remote_port == Some(*port)),
                    _ => false,
                }
            },
            RuleCondition::MemoryUsage { threshold_mb } => {
                process.memory_rss > threshold_mb * 1024 * 1024
            },
            RuleCondition::CpuUsage { threshold_percent } => {
                process.cpu_percent > *threshold_percent
            },
            RuleCondition::UserContext { username } => {
                process.username.as_ref() == Some(username)
            },
            RuleCondition::And { conditions } => {
                conditions.iter().all(|c| self.evaluate_condition(c, process))
            },
            RuleCondition::Or { conditions } => {
                conditions.iter().any(|c| self.evaluate_condition(c, process))
            },
            RuleCondition::Not { condition } => {
                !self.evaluate_condition(condition, process)
            },
        }
    }
}

impl Default for RuleSet {
    fn default() -> Self {
        let mut ruleset = Self::new();
        
        // Add default rules
        ruleset.add_rule(SecurityRule {
            id: "CRON_SUSPICIOUS".to_string(),
            name: "Suspicious Cron Job".to_string(),
            description: "Cron process with unusual characteristics".to_string(),
            severity: Severity::Medium,
            enabled: true,
            condition: RuleCondition::And {
                conditions: vec![
                    RuleCondition::ProcessName { pattern: "cron".to_string() },
                    RuleCondition::Not {
                        condition: Box::new(RuleCondition::UserContext { 
                            username: "root".to_string() 
                        }),
                    },
                ],
            },
            recommendations: vec![
                "Verify cron job legitimacy".to_string(),
                "Check crontab entries".to_string(),
            ],
        });
        
        ruleset.add_rule(SecurityRule {
            id: "HIGH_MEMORY_USAGE".to_string(),
            name: "Excessive Memory Usage".to_string(),
            description: "Process consuming excessive memory".to_string(),
            severity: Severity::Medium,
            enabled: true,
            condition: RuleCondition::MemoryUsage { threshold_mb: 4096 },
            recommendations: vec![
                "Monitor for memory leaks".to_string(),
                "Consider process limits".to_string(),
            ],
        });
        
        ruleset
    }
}