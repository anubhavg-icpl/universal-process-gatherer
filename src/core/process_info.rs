use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Core process information structure with all fields from Wazuh requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    /// Process ID
    pub pid: u32,
    
    /// Parent process ID
    pub ppid: u32,
    
    /// Process name
    pub name: String,
    
    /// Full command line with arguments
    pub cmdline: Vec<String>,
    
    /// Executable path
    pub exe_path: Option<PathBuf>,
    
    /// Current working directory
    pub cwd: Option<PathBuf>,
    
    /// Process state (Running, Sleeping, Stopped, Zombie, etc.)
    pub state: ProcessState,
    
    /// User ID (effective)
    pub uid: u32,
    
    /// Group ID (effective)
    pub gid: u32,
    
    /// Real user ID
    pub ruid: u32,
    
    /// Real group ID
    pub rgid: u32,
    
    /// Saved user ID
    pub suid: Option<u32>,
    
    /// Saved group ID
    pub sgid: Option<u32>,
    
    /// Username
    pub username: Option<String>,
    
    /// Group name
    pub groupname: Option<String>,
    
    /// Process priority
    pub priority: i32,
    
    /// Nice value
    pub nice: i32,
    
    /// Number of threads
    pub threads: u32,
    
    /// Process start time
    pub start_time: DateTime<Utc>,
    
    /// CPU usage percentage
    pub cpu_percent: f64,
    
    /// Memory usage in bytes
    pub memory_rss: u64,
    
    /// Virtual memory size in bytes
    pub memory_vms: u64,
    
    /// Shared memory size in bytes
    pub memory_shared: u64,
    
    /// TTY device
    pub tty: Option<String>,
    
    /// Session ID
    pub session_id: u32,
    
    /// Process group ID
    pub pgrp: u32,
    
    /// Environment variables
    pub environ: HashMap<String, String>,
    
    /// Open file descriptors
    pub open_files: Vec<OpenFile>,
    
    /// Network connections
    pub connections: Vec<NetworkConnection>,
    
    /// Process checksum (SHA256 of executable)
    pub checksum: Option<String>,
    
    /// Security attributes
    pub security_attrs: SecurityAttributes,
    
    /// Platform-specific data
    pub platform_data: PlatformData,
}

/// Process state enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessState {
    Running,
    Sleeping,
    Stopped,
    Zombie,
    Dead,
    TracingStop,
    Idle,
    Unknown,
}

/// Open file descriptor information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenFile {
    pub fd: i32,
    pub path: PathBuf,
    pub mode: String,
    pub flags: u32,
}

/// Network connection information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub protocol: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: Option<String>,
    pub remote_port: Option<u16>,
    pub state: String,
}

/// Security attributes for process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAttributes {
    /// SELinux context (Linux)
    pub selinux_context: Option<String>,
    
    /// AppArmor profile (Linux)
    pub apparmor_profile: Option<String>,
    
    /// Seccomp mode (Linux)
    pub seccomp_mode: Option<u32>,
    
    /// Capabilities (Linux)
    pub capabilities: Option<Capabilities>,
    
    /// Windows security descriptor
    pub security_descriptor: Option<String>,
    
    /// AIX security attributes
    pub aix_security: Option<AixSecurity>,
}

/// Linux capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capabilities {
    pub effective: Vec<String>,
    pub permitted: Vec<String>,
    pub inheritable: Vec<String>,
    pub bounding: Vec<String>,
    pub ambient: Vec<String>,
}

/// AIX-specific security attributes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AixSecurity {
    pub privilege_set: Vec<String>,
    pub auth_domains: Vec<String>,
    pub security_flags: u64,
}

/// Platform-specific process data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "platform")]
pub enum PlatformData {
    Linux(LinuxProcessData),
    Windows(WindowsProcessData),
    MacOS(MacOSProcessData),
    AIX(AIXProcessData),
    Unknown,
}

/// Linux-specific process data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxProcessData {
    /// Number of voluntary context switches
    pub voluntary_ctxt_switches: u64,
    
    /// Number of involuntary context switches
    pub nonvoluntary_ctxt_switches: u64,
    
    /// OOM score
    pub oom_score: i32,
    
    /// OOM score adjustment
    pub oom_score_adj: i32,
    
    /// Control groups
    pub cgroups: Vec<String>,
    
    /// Namespace IDs
    pub namespaces: HashMap<String, u64>,
}

/// Windows-specific process data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsProcessData {
    /// Process creation flags
    pub creation_flags: u32,
    
    /// Handle count
    pub handle_count: u32,
    
    /// Peak working set size
    pub peak_working_set: u64,
    
    /// Page fault count
    pub page_fault_count: u32,
    
    /// Kernel time in milliseconds
    pub kernel_time: u64,
    
    /// User time in milliseconds
    pub user_time: u64,
    
    /// Windows Station
    pub window_station: Option<String>,
    
    /// Desktop
    pub desktop: Option<String>,
}

/// macOS-specific process data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacOSProcessData {
    /// Process flags
    pub flags: u32,
    
    /// Process status
    pub status: u32,
    
    /// Resident set size
    pub resident_size: u64,
    
    /// Virtual size
    pub virtual_size: u64,
    
    /// User time
    pub user_time: u64,
    
    /// System time
    pub system_time: u64,
}

/// AIX-specific process data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIXProcessData {
    /// Process flags from pstatus
    pub pr_flag: u32,
    
    /// Process flags2 from pstatus
    pub pr_flag2: u32,
    
    /// Number of LWPs
    pub pr_nlwp: u32,
    
    /// Process class ID
    pub pr_clid: i32,
    
    /// Wait channel
    pub pr_wchan: u64,
    
    /// Size of process image in pages
    pub pr_size: u64,
    
    /// Resident set size in pages
    pub pr_rssize: u64,
    
    /// Process contract ID
    pub pr_contract: i32,
    
    /// Zone ID
    pub pr_zoneid: i32,
    
    /// Process model (32/64 bit)
    pub pr_dmodel: String,
}

/// Process collection options
#[derive(Debug, Clone, Default)]
pub struct CollectionOptions {
    /// Include environment variables
    pub include_environ: bool,
    
    /// Include open files
    pub include_open_files: bool,
    
    /// Include network connections
    pub include_connections: bool,
    
    /// Calculate executable checksums
    pub calculate_checksums: bool,
    
    /// Include child processes
    pub include_children: bool,
    
    /// Filter by user
    pub filter_user: Option<String>,
    
    /// Filter by process name pattern
    pub filter_name: Option<String>,
    
    /// Filter by minimum PID
    pub min_pid: Option<u32>,
}

impl ProcessState {
    pub fn from_char(c: char) -> Self {
        match c {
            'R' => ProcessState::Running,
            'S' => ProcessState::Sleeping,
            'D' => ProcessState::Sleeping, // Uninterruptible sleep
            'T' => ProcessState::Stopped,
            'Z' => ProcessState::Zombie,
            'X' => ProcessState::Dead,
            't' => ProcessState::TracingStop,
            'I' => ProcessState::Idle,
            _ => ProcessState::Unknown,
        }
    }
    
    pub fn as_str(&self) -> &'static str {
        match self {
            ProcessState::Running => "Running",
            ProcessState::Sleeping => "Sleeping",
            ProcessState::Stopped => "Stopped",
            ProcessState::Zombie => "Zombie",
            ProcessState::Dead => "Dead",
            ProcessState::TracingStop => "TracingStop",
            ProcessState::Idle => "Idle",
            ProcessState::Unknown => "Unknown",
        }
    }
}

impl Default for ProcessInfo {
    fn default() -> Self {
        Self {
            pid: 0,
            ppid: 0,
            name: String::new(),
            cmdline: Vec::new(),
            exe_path: None,
            cwd: None,
            state: ProcessState::Unknown,
            uid: 0,
            gid: 0,
            ruid: 0,
            rgid: 0,
            suid: None,
            sgid: None,
            username: None,
            groupname: None,
            priority: 0,
            nice: 0,
            threads: 1,
            start_time: Utc::now(),
            cpu_percent: 0.0,
            memory_rss: 0,
            memory_vms: 0,
            memory_shared: 0,
            tty: None,
            session_id: 0,
            pgrp: 0,
            environ: HashMap::new(),
            open_files: Vec::new(),
            connections: Vec::new(),
            checksum: None,
            security_attrs: SecurityAttributes {
                selinux_context: None,
                apparmor_profile: None,
                seccomp_mode: None,
                capabilities: None,
                security_descriptor: None,
                aix_security: None,
            },
            platform_data: PlatformData::Unknown,
        }
    }
}