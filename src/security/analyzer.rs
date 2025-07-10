use crate::core::{ProcessInfo, ProcessState};
use crate::security::rules::RuleSet;
use std::collections::{HashMap, HashSet};
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Security finding severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Security finding for a process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub pid: u32,
    pub process_name: String,
    pub severity: Severity,
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub details: HashMap<String, String>,
    pub recommendations: Vec<String>,
}

/// Security analyzer for process inspection
pub struct SecurityAnalyzer {
    rules: RuleSet,
    known_malware_hashes: HashSet<String>,
    suspicious_paths: Vec<Regex>,
    suspicious_names: Vec<Regex>,
    #[allow(dead_code)]
    privileged_ports: HashSet<u16>,
}

impl SecurityAnalyzer {
    pub fn new() -> Self {
        Self {
            rules: RuleSet::default(),
            known_malware_hashes: HashSet::new(),
            suspicious_paths: Self::default_suspicious_paths(),
            suspicious_names: Self::default_suspicious_names(),
            privileged_ports: (1..1024).collect(),
        }
    }
    
    pub fn with_rules(rules: RuleSet) -> Self {
        Self {
            rules,
            ..Self::new()
        }
    }
    
    pub fn add_malware_hash(&mut self, hash: String) {
        self.known_malware_hashes.insert(hash);
    }
    
    pub fn analyze_process(&self, process: &ProcessInfo) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        
        // Check for zombie processes
        if process.state == ProcessState::Zombie {
            findings.push(SecurityFinding {
                pid: process.pid,
                process_name: process.name.clone(),
                severity: Severity::Low,
                rule_id: "PROC_ZOMBIE".to_string(),
                title: "Zombie Process Detected".to_string(),
                description: format!("Process {} (PID {}) is in zombie state", process.name, process.pid),
                details: HashMap::from([
                    ("ppid".to_string(), process.ppid.to_string()),
                    ("state".to_string(), "zombie".to_string()),
                ]),
                recommendations: vec![
                    "Investigate parent process for proper child handling".to_string(),
                    "Consider restarting the parent process".to_string(),
                ],
            });
        }
        
        // Check for suspicious process names
        for pattern in &self.suspicious_names {
            if pattern.is_match(&process.name) {
                findings.push(SecurityFinding {
                    pid: process.pid,
                    process_name: process.name.clone(),
                    severity: Severity::High,
                    rule_id: "PROC_SUSPICIOUS_NAME".to_string(),
                    title: "Suspicious Process Name".to_string(),
                    description: format!("Process has suspicious name: {}", process.name),
                    details: HashMap::from([
                        ("pattern".to_string(), pattern.as_str().to_string()),
                    ]),
                    recommendations: vec![
                        "Investigate process origin and purpose".to_string(),
                        "Check for malware indicators".to_string(),
                    ],
                });
            }
        }
        
        // Check for suspicious paths
        if let Some(ref exe_path) = process.exe_path {
            for pattern in &self.suspicious_paths {
                if pattern.is_match(&exe_path.to_string_lossy()) {
                    findings.push(SecurityFinding {
                        pid: process.pid,
                        process_name: process.name.clone(),
                        severity: Severity::High,
                        rule_id: "PROC_SUSPICIOUS_PATH".to_string(),
                        title: "Process Running from Suspicious Location".to_string(),
                        description: format!("Process executable in suspicious location: {}", exe_path.display()),
                        details: HashMap::from([
                            ("path".to_string(), exe_path.display().to_string()),
                        ]),
                        recommendations: vec![
                            "Verify process legitimacy".to_string(),
                            "Check file permissions and ownership".to_string(),
                        ],
                    });
                }
            }
        }
        
        // Check for known malware hashes
        if let Some(ref checksum) = process.checksum {
            if self.known_malware_hashes.contains(checksum) {
                findings.push(SecurityFinding {
                    pid: process.pid,
                    process_name: process.name.clone(),
                    severity: Severity::Critical,
                    rule_id: "PROC_KNOWN_MALWARE".to_string(),
                    title: "Known Malware Detected".to_string(),
                    description: format!("Process matches known malware signature"),
                    details: HashMap::from([
                        ("hash".to_string(), checksum.clone()),
                    ]),
                    recommendations: vec![
                        "Immediately terminate the process".to_string(),
                        "Quarantine the executable file".to_string(),
                        "Perform full system scan".to_string(),
                    ],
                });
            }
        }
        
        // Check for privilege escalation indicators
        if process.uid == 0 && process.ruid != 0 {
            findings.push(SecurityFinding {
                pid: process.pid,
                process_name: process.name.clone(),
                severity: Severity::High,
                rule_id: "PROC_PRIV_ESCALATION".to_string(),
                title: "Potential Privilege Escalation".to_string(),
                description: format!("Process running as root but started by non-root user"),
                details: HashMap::from([
                    ("euid".to_string(), process.uid.to_string()),
                    ("ruid".to_string(), process.ruid.to_string()),
                ]),
                recommendations: vec![
                    "Verify if setuid is intended".to_string(),
                    "Check for exploitation attempts".to_string(),
                ],
            });
        }
        
        // Check for hidden processes
        if process.name.starts_with('.') || 
           (process.exe_path.is_some() && process.exe_path.as_ref().unwrap().to_string_lossy().contains("/.")) {
            findings.push(SecurityFinding {
                pid: process.pid,
                process_name: process.name.clone(),
                severity: Severity::Medium,
                rule_id: "PROC_HIDDEN".to_string(),
                title: "Hidden Process Detected".to_string(),
                description: format!("Process appears to be hidden"),
                details: HashMap::new(),
                recommendations: vec![
                    "Investigate process purpose".to_string(),
                    "Check for rootkit activity".to_string(),
                ],
            });
        }
        
        // Check for processes without executable path
        if process.exe_path.is_none() && process.state != ProcessState::Zombie {
            findings.push(SecurityFinding {
                pid: process.pid,
                process_name: process.name.clone(),
                severity: Severity::Medium,
                rule_id: "PROC_NO_EXE".to_string(),
                title: "Process Without Executable Path".to_string(),
                description: format!("Process has no associated executable file"),
                details: HashMap::new(),
                recommendations: vec![
                    "Investigate if process is kernel thread".to_string(),
                    "Check for process injection".to_string(),
                ],
            });
        }
        
        // Check for suspicious network connections
        for conn in &process.connections {
            // Check for privileged port binding by non-root
            if conn.local_port < 1024 && process.uid != 0 {
                findings.push(SecurityFinding {
                    pid: process.pid,
                    process_name: process.name.clone(),
                    severity: Severity::High,
                    rule_id: "NET_PRIV_PORT".to_string(),
                    title: "Non-root Process on Privileged Port".to_string(),
                    description: format!("Non-root process bound to privileged port {}", conn.local_port),
                    details: HashMap::from([
                        ("port".to_string(), conn.local_port.to_string()),
                        ("uid".to_string(), process.uid.to_string()),
                    ]),
                    recommendations: vec![
                        "Verify port binding legitimacy".to_string(),
                        "Check for capability abuse".to_string(),
                    ],
                });
            }
            
            // Check for reverse shell indicators
            if conn.remote_port.is_some() && 
               (conn.remote_port.unwrap() == 4444 || 
                conn.remote_port.unwrap() == 1337 ||
                conn.remote_port.unwrap() == 31337) {
                findings.push(SecurityFinding {
                    pid: process.pid,
                    process_name: process.name.clone(),
                    severity: Severity::High,
                    rule_id: "NET_REVERSE_SHELL".to_string(),
                    title: "Potential Reverse Shell Connection".to_string(),
                    description: format!("Process connected to suspicious port {}", conn.remote_port.unwrap()),
                    details: HashMap::from([
                        ("remote_addr".to_string(), conn.remote_addr.clone().unwrap_or_default()),
                        ("remote_port".to_string(), conn.remote_port.unwrap().to_string()),
                    ]),
                    recommendations: vec![
                        "Immediately investigate connection".to_string(),
                        "Block outbound connection if unauthorized".to_string(),
                    ],
                });
            }
        }
        
        // Apply custom rules
        findings.extend(self.rules.evaluate(process));
        
        findings
    }
    
    pub fn analyze_all(&self, processes: &[ProcessInfo]) -> Vec<SecurityFinding> {
        let mut all_findings = Vec::new();
        
        // Individual process analysis
        for process in processes {
            all_findings.extend(self.analyze_process(process));
        }
        
        // Cross-process analysis
        all_findings.extend(self.analyze_process_relationships(processes));
        
        all_findings
    }
    
    fn analyze_process_relationships(&self, processes: &[ProcessInfo]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        
        // Build process tree
        let mut children_map: HashMap<u32, Vec<&ProcessInfo>> = HashMap::new();
        for process in processes {
            children_map.entry(process.ppid).or_insert_with(Vec::new).push(process);
        }
        
        // Check for process spawning anomalies
        for process in processes {
            if let Some(children) = children_map.get(&process.pid) {
                // Check for excessive child processes
                if children.len() > 100 {
                    findings.push(SecurityFinding {
                        pid: process.pid,
                        process_name: process.name.clone(),
                        severity: Severity::Medium,
                        rule_id: "PROC_FORK_BOMB".to_string(),
                        title: "Potential Fork Bomb".to_string(),
                        description: format!("Process has {} child processes", children.len()),
                        details: HashMap::from([
                            ("child_count".to_string(), children.len().to_string()),
                        ]),
                        recommendations: vec![
                            "Monitor system resources".to_string(),
                            "Consider limiting process creation".to_string(),
                        ],
                    });
                }
                
                // Check for suspicious parent-child relationships
                for child in children {
                    if Self::is_suspicious_parent_child(&process.name, &child.name) {
                        findings.push(SecurityFinding {
                            pid: child.pid,
                            process_name: child.name.clone(),
                            severity: Severity::High,
                            rule_id: "PROC_SUSPICIOUS_PARENT".to_string(),
                            title: "Suspicious Process Parentage".to_string(),
                            description: format!("{} spawned by {}", child.name, process.name),
                            details: HashMap::from([
                                ("parent".to_string(), process.name.clone()),
                                ("parent_pid".to_string(), process.pid.to_string()),
                            ]),
                            recommendations: vec![
                                "Investigate process injection".to_string(),
                                "Check for exploitation".to_string(),
                            ],
                        });
                    }
                }
            }
        }
        
        findings
    }
    
    fn is_suspicious_parent_child(parent: &str, child: &str) -> bool {
        // Common suspicious parent-child relationships
        match (parent, child) {
            ("services.exe", "cmd.exe") => true,
            ("services.exe", "powershell.exe") => true,
            ("svchost.exe", "cmd.exe") => true,
            ("winlogon.exe", "cmd.exe") => true,
            ("explorer.exe", "svchost.exe") => true,
            _ => false,
        }
    }
    
    fn default_suspicious_paths() -> Vec<Regex> {
        vec![
            Regex::new(r"/tmp/\.[^/]+").unwrap(),
            Regex::new(r"/var/tmp/\.[^/]+").unwrap(),
            Regex::new(r"/dev/shm/").unwrap(),
            Regex::new(r"\\Windows\\Temp\\").unwrap(),
            Regex::new(r"\\Users\\[^\\]+\\AppData\\Local\\Temp\\").unwrap(),
        ]
    }
    
    fn default_suspicious_names() -> Vec<Regex> {
        vec![
            Regex::new(r"^[a-z]{8}$").unwrap(), // Random 8-char names
            Regex::new(r"^[0-9a-f]{32}$").unwrap(), // MD5-like names
            Regex::new(r"miner").unwrap(),
            Regex::new(r"xmrig").unwrap(),
            Regex::new(r"mimikatz").unwrap(),
        ]
    }
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
}