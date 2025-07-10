use crate::core::{
    ProcessInfo, ProcessState, PlatformData, LinuxProcessData, OpenFile, 
    NetworkConnection, SecurityAttributes, Capabilities, ProcessError, Result,
    CollectionOptions
};
use crate::collectors::traits::ProcessCollector;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use chrono::{DateTime, Utc};
use procfs::process::{Process, Stat};
use sha2::{Sha256, Digest};
use std::io::Read;
use std::os::unix::fs::MetadataExt;

pub struct LinuxCollector;

impl LinuxCollector {
    pub fn new() -> Self {
        Self
    }
    
    fn read_stat(&self, pid: u32) -> Result<Stat> {
        let proc = Process::new(pid as i32)
            .map_err(|e| ProcessError::ProcfsError(e.to_string()))?;
        proc.stat()
            .map_err(|e| ProcessError::ProcfsError(e.to_string()))
    }
    
    fn read_status(&self, pid: u32) -> Result<HashMap<String, String>> {
        let path = format!("/proc/{}/status", pid);
        let content = fs::read_to_string(&path)
            .map_err(|e| ProcessError::ProcfsError(format!("Failed to read {}: {}", path, e)))?;
        
        let mut status = HashMap::new();
        for line in content.lines() {
            if let Some((key, value)) = line.split_once(':') {
                status.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
        Ok(status)
    }
    
    fn read_cmdline(&self, pid: u32) -> Result<Vec<String>> {
        let path = format!("/proc/{}/cmdline", pid);
        let content = fs::read(&path)
            .map_err(|_| ProcessError::ProcessNotFound { pid })?;
        
        if content.is_empty() {
            return Ok(vec![]);
        }
        
        let cmdline = content
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).to_string())
            .collect();
        
        Ok(cmdline)
    }
    
    fn read_environ(&self, pid: u32) -> Result<HashMap<String, String>> {
        let path = format!("/proc/{}/environ", pid);
        let content = fs::read(&path)
            .unwrap_or_default();
        
        let mut environ = HashMap::new();
        for var in content.split(|&b| b == 0) {
            if let Ok(s) = std::str::from_utf8(var) {
                if let Some((key, value)) = s.split_once('=') {
                    environ.insert(key.to_string(), value.to_string());
                }
            }
        }
        Ok(environ)
    }
    
    fn read_exe_path(&self, pid: u32) -> Option<PathBuf> {
        let path = format!("/proc/{}/exe", pid);
        fs::read_link(&path).ok()
    }
    
    fn read_cwd(&self, pid: u32) -> Option<PathBuf> {
        let path = format!("/proc/{}/cwd", pid);
        fs::read_link(&path).ok()
    }
    
    fn calculate_checksum(&self, exe_path: &Path) -> Option<String> {
        let mut file = fs::File::open(exe_path).ok()?;
        let mut hasher = Sha256::new();
        let mut buffer = [0; 8192];
        
        loop {
            match file.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => hasher.update(&buffer[..n]),
                Err(_) => return None,
            }
        }
        
        Some(hex::encode(hasher.finalize()))
    }
    
    fn read_open_files(&self, pid: u32) -> Vec<OpenFile> {
        let fd_dir = format!("/proc/{}/fd", pid);
        let mut files = Vec::new();
        
        if let Ok(entries) = fs::read_dir(&fd_dir) {
            for entry in entries.filter_map(|e| e.ok()) {
                if let Some(fd_str) = entry.file_name().to_str() {
                    if let Ok(fd) = fd_str.parse::<i32>() {
                        if let Ok(path) = fs::read_link(entry.path()) {
                            files.push(OpenFile {
                                fd,
                                path,
                                mode: String::new(),
                                flags: 0,
                            });
                        }
                    }
                }
            }
        }
        
        files
    }
    
    fn read_network_connections(&self, pid: u32) -> Vec<NetworkConnection> {
        let mut connections = Vec::new();
        
        // Read TCP connections
        if let Ok(tcp) = self.read_net_file("/proc/net/tcp", "tcp", pid) {
            connections.extend(tcp);
        }
        if let Ok(tcp6) = self.read_net_file("/proc/net/tcp6", "tcp6", pid) {
            connections.extend(tcp6);
        }
        
        // Read UDP connections  
        if let Ok(udp) = self.read_net_file("/proc/net/udp", "udp", pid) {
            connections.extend(udp);
        }
        if let Ok(udp6) = self.read_net_file("/proc/net/udp6", "udp6", pid) {
            connections.extend(udp6);
        }
        
        connections
    }
    
    fn read_net_file(&self, path: &str, protocol: &str, _pid: u32) -> Result<Vec<NetworkConnection>> {
        let content = fs::read_to_string(path)
            .map_err(|e| ProcessError::Io(e))?;
        
        let mut connections = Vec::new();
        for (i, line) in content.lines().enumerate() {
            if i == 0 { continue; } // Skip header
            
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 10 { continue; }
            
            // Parse local address
            let local_parts: Vec<&str> = parts[1].split(':').collect();
            if local_parts.len() != 2 { continue; }
            
            let local_addr = self.parse_hex_addr(local_parts[0]);
            let local_port = u16::from_str_radix(local_parts[1], 16).unwrap_or(0);
            
            // Parse remote address
            let remote_parts: Vec<&str> = parts[2].split(':').collect();
            let (remote_addr, remote_port) = if remote_parts.len() == 2 {
                (
                    Some(self.parse_hex_addr(remote_parts[0])),
                    Some(u16::from_str_radix(remote_parts[1], 16).unwrap_or(0))
                )
            } else {
                (None, None)
            };
            
            let state = if protocol.starts_with("tcp") {
                self.parse_tcp_state(parts[3])
            } else {
                "ACTIVE".to_string()
            };
            
            connections.push(NetworkConnection {
                protocol: protocol.to_string(),
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                state,
            });
        }
        
        Ok(connections)
    }
    
    fn parse_hex_addr(&self, hex: &str) -> String {
        if hex.len() == 8 {
            // IPv4
            let bytes = (0..4)
                .map(|i| u8::from_str_radix(&hex[i*2..i*2+2], 16).unwrap_or(0))
                .collect::<Vec<_>>();
            format!("{}.{}.{}.{}", bytes[3], bytes[2], bytes[1], bytes[0])
        } else {
            // IPv6
            hex.to_string()
        }
    }
    
    fn parse_tcp_state(&self, state: &str) -> String {
        match state {
            "01" => "ESTABLISHED",
            "02" => "SYN_SENT",
            "03" => "SYN_RECV",
            "04" => "FIN_WAIT1",
            "05" => "FIN_WAIT2",
            "06" => "TIME_WAIT",
            "07" => "CLOSE",
            "08" => "CLOSE_WAIT",
            "09" => "LAST_ACK",
            "0A" => "LISTEN",
            "0B" => "CLOSING",
            _ => "UNKNOWN",
        }.to_string()
    }
    
    fn read_security_attributes(&self, pid: u32) -> SecurityAttributes {
        let mut attrs = SecurityAttributes {
            selinux_context: None,
            apparmor_profile: None,
            seccomp_mode: None,
            capabilities: None,
            security_descriptor: None,
            aix_security: None,
        };
        
        // SELinux context
        if let Ok(context) = fs::read_to_string(format!("/proc/{}/attr/current", pid)) {
            attrs.selinux_context = Some(context.trim_end_matches('\0').to_string());
        }
        
        // AppArmor profile
        if let Ok(profile) = fs::read_to_string(format!("/proc/{}/attr/apparmor/current", pid)) {
            attrs.apparmor_profile = Some(profile.trim().to_string());
        }
        
        // Seccomp mode
        if let Ok(status) = self.read_status(pid) {
            if let Some(seccomp) = status.get("Seccomp") {
                attrs.seccomp_mode = seccomp.parse().ok();
            }
            
            // Capabilities
            if let (Some(cap_eff), Some(cap_prm), Some(cap_inh), Some(cap_bnd), Some(cap_amb)) = (
                status.get("CapEff"),
                status.get("CapPrm"),
                status.get("CapInh"),
                status.get("CapBnd"),
                status.get("CapAmb"),
            ) {
                attrs.capabilities = Some(Capabilities {
                    effective: self.parse_capabilities(cap_eff),
                    permitted: self.parse_capabilities(cap_prm),
                    inheritable: self.parse_capabilities(cap_inh),
                    bounding: self.parse_capabilities(cap_bnd),
                    ambient: self.parse_capabilities(cap_amb),
                });
            }
        }
        
        attrs
    }
    
    fn parse_capabilities(&self, cap_hex: &str) -> Vec<String> {
        // This is a simplified version. In production, you'd map the hex values
        // to actual capability names
        vec![cap_hex.to_string()]
    }
    
    fn read_linux_specific_data(&self, pid: u32) -> Result<LinuxProcessData> {
        let mut data = LinuxProcessData {
            voluntary_ctxt_switches: 0,
            nonvoluntary_ctxt_switches: 0,
            oom_score: 0,
            oom_score_adj: 0,
            cgroups: Vec::new(),
            namespaces: HashMap::new(),
        };
        
        // Context switches from status
        if let Ok(status) = self.read_status(pid) {
            if let Some(vol) = status.get("voluntary_ctxt_switches") {
                data.voluntary_ctxt_switches = vol.parse().unwrap_or(0);
            }
            if let Some(nonvol) = status.get("nonvoluntary_ctxt_switches") {
                data.nonvoluntary_ctxt_switches = nonvol.parse().unwrap_or(0);
            }
        }
        
        // OOM scores
        if let Ok(score) = fs::read_to_string(format!("/proc/{}/oom_score", pid)) {
            data.oom_score = score.trim().parse().unwrap_or(0);
        }
        if let Ok(adj) = fs::read_to_string(format!("/proc/{}/oom_score_adj", pid)) {
            data.oom_score_adj = adj.trim().parse().unwrap_or(0);
        }
        
        // Cgroups
        if let Ok(cgroups) = fs::read_to_string(format!("/proc/{}/cgroup", pid)) {
            data.cgroups = cgroups.lines().map(|s| s.to_string()).collect();
        }
        
        // Namespaces
        let ns_dir = format!("/proc/{}/ns", pid);
        if let Ok(entries) = fs::read_dir(&ns_dir) {
            for entry in entries.filter_map(|e| e.ok()) {
                if let Some(name) = entry.file_name().to_str() {
                    if let Ok(metadata) = entry.metadata() {
                        data.namespaces.insert(name.to_string(), metadata.ino());
                    }
                }
            }
        }
        
        Ok(data)
    }
}

impl ProcessCollector for LinuxCollector {
    fn collect_all(&self, options: &CollectionOptions) -> Result<Vec<ProcessInfo>> {
        let mut processes = Vec::new();
        
        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            let name = entry.file_name();
            
            if let Some(pid_str) = name.to_str() {
                if let Ok(pid) = pid_str.parse::<u32>() {
                    match self.collect_process(pid, options) {
                        Ok(proc_info) => {
                            // Apply filters
                            if let Some(ref filter_name) = options.filter_name {
                                if !proc_info.name.contains(filter_name) {
                                    continue;
                                }
                            }
                            if let Some(ref filter_user) = options.filter_user {
                                if proc_info.username.as_ref() != Some(filter_user) {
                                    continue;
                                }
                            }
                            if let Some(min_pid) = options.min_pid {
                                if proc_info.pid < min_pid {
                                    continue;
                                }
                            }
                            
                            processes.push(proc_info);
                        }
                        Err(ProcessError::ProcessNotFound { .. }) => continue,
                        Err(ProcessError::PermissionDenied { .. }) => continue,
                        Err(e) => log::warn!("Failed to collect process {}: {}", pid, e),
                    }
                }
            }
        }
        
        Ok(processes)
    }
    
    fn collect_process(&self, pid: u32, options: &CollectionOptions) -> Result<ProcessInfo> {
        let stat = self.read_stat(pid)?;
        let status = self.read_status(pid)?;
        let cmdline = self.read_cmdline(pid)?;
        
        let mut proc_info = ProcessInfo {
            pid,
            ppid: stat.ppid as u32,
            name: stat.comm.clone(),
            cmdline,
            exe_path: self.read_exe_path(pid),
            cwd: self.read_cwd(pid),
            state: ProcessState::from_char(stat.state),
            uid: 0,
            gid: 0,
            ruid: 0,
            rgid: 0,
            suid: None,
            sgid: None,
            username: None,
            groupname: None,
            priority: stat.priority as i32,
            nice: stat.nice as i32,
            threads: stat.num_threads as u32,
            start_time: self.boot_time_to_utc(stat.starttime)?,
            cpu_percent: 0.0, // Would need to calculate over time
            memory_rss: stat.rss * 4096, // Convert pages to bytes
            memory_vms: stat.vsize,
            memory_shared: 0, // Would need to read from smaps
            tty: if stat.tty_nr != 0 { Some(format!("{}", stat.tty_nr)) } else { None },
            session_id: stat.session as u32,
            pgrp: stat.pgrp as u32,
            environ: HashMap::new(),
            open_files: Vec::new(),
            connections: Vec::new(),
            checksum: None,
            security_attrs: self.read_security_attributes(pid),
            platform_data: PlatformData::Unknown,
        };
        
        // Parse UIDs/GIDs from status
        if let Some(uid_line) = status.get("Uid") {
            let uids: Vec<u32> = uid_line.split_whitespace()
                .filter_map(|s| s.parse().ok())
                .collect();
            if uids.len() >= 4 {
                proc_info.ruid = uids[0];
                proc_info.uid = uids[1];
                proc_info.suid = Some(uids[2]);
            }
        }
        
        if let Some(gid_line) = status.get("Gid") {
            let gids: Vec<u32> = gid_line.split_whitespace()
                .filter_map(|s| s.parse().ok())
                .collect();
            if gids.len() >= 4 {
                proc_info.rgid = gids[0];
                proc_info.gid = gids[1];
                proc_info.sgid = Some(gids[2]);
            }
        }
        
        // Get username/groupname
        if let Some(user) = users::get_user_by_uid(proc_info.uid) {
            proc_info.username = Some(user.name().to_string_lossy().to_string());
        }
        if let Some(group) = users::get_group_by_gid(proc_info.gid) {
            proc_info.groupname = Some(group.name().to_string_lossy().to_string());
        }
        
        // Optional data collection
        if options.include_environ {
            proc_info.environ = self.read_environ(pid)?;
        }
        
        if options.include_open_files {
            proc_info.open_files = self.read_open_files(pid);
        }
        
        if options.include_connections {
            proc_info.connections = self.read_network_connections(pid);
        }
        
        if options.calculate_checksums {
            if let Some(ref exe_path) = proc_info.exe_path {
                proc_info.checksum = self.calculate_checksum(exe_path);
            }
        }
        
        // Linux-specific data
        if let Ok(linux_data) = self.read_linux_specific_data(pid) {
            proc_info.platform_data = PlatformData::Linux(linux_data);
        }
        
        Ok(proc_info)
    }
    
    fn is_supported(&self) -> bool {
        cfg!(target_os = "linux")
    }
}

impl LinuxCollector {
    fn boot_time_to_utc(&self, ticks: u64) -> Result<DateTime<Utc>> {
        let boot_time = procfs::boot_time_secs()
            .map_err(|e| ProcessError::ProcfsError(e.to_string()))?;
        
        let ticks_per_sec = procfs::ticks_per_second() as u64;
        
        let start_secs = boot_time + (ticks / ticks_per_sec);
        let start_time = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(start_secs);
        
        Ok(DateTime::<Utc>::from(start_time))
    }
}