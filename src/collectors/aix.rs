use crate::core::{
    ProcessInfo, ProcessState, PlatformData, AIXProcessData, AixSecurity, 
    SecurityAttributes, ProcessError, Result, CollectionOptions
};
use crate::collectors::traits::ProcessCollector;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::mem;
use chrono::{DateTime, Utc, TimeZone};
use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Cursor, Read};
use libc::{pid_t, uid_t, gid_t};

// AIX pstatus structure constants
const PSTATUS_SIZE: usize = 256;
const PR_FNAME_SIZE: usize = 16;
const PR_PSARGS_SIZE: usize = 80;

// Process state constants for AIX
const SSLEEP: u8 = 1;
const SRUN: u8 = 2;
const SZOMB: u8 = 3;
const SSTOP: u8 = 4;
const SIDL: u8 = 5;
const SONPROC: u8 = 6;

/// AIX pstatus structure representation
#[repr(C)]
struct Pstatus {
    pr_flag: u32,
    pr_flag2: u32,
    pr_nlwp: u32,
    pr_uid: uid_t,
    pr_gid: gid_t,
    pr_pid: pid_t,
    pr_ppid: pid_t,
    pr_pgid: pid_t,
    pr_sid: pid_t,
    pr_clid: i32,
    pr_pri: i32,
    pr_nice: i32,
    pr_wchan: u64,
    pr_fname: [u8; PR_FNAME_SIZE],
    pr_psargs: [u8; PR_PSARGS_SIZE],
    pr_utime: u64,
    pr_stime: u64,
    pr_size: u64,
    pr_rssize: u64,
    pr_contract: i32,
    pr_zoneid: i32,
    pr_state: u8,
    pr_sname: u8,
    pr_ttydev: u32,
    pr_dmodel: u32,
}

pub struct AixCollector;

impl AixCollector {
    pub fn new() -> Self {
        Self
    }
    
    fn read_pstatus(&self, pid: u32) -> Result<Pstatus> {
        let path = format!("/proc/{}/status", pid);
        let data = fs::read(&path)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => ProcessError::ProcessNotFound { pid },
                std::io::ErrorKind::PermissionDenied => ProcessError::PermissionDenied { pid },
                _ => ProcessError::Io(e),
            })?;
        
        if data.len() < PSTATUS_SIZE {
            return Err(ProcessError::AixParseError(
                format!("Invalid pstatus size: {} bytes", data.len())
            ));
        }
        
        self.parse_pstatus(&data)
    }
    
    fn parse_pstatus(&self, data: &[u8]) -> Result<Pstatus> {
        let mut cursor = Cursor::new(data);
        
        let pstatus = Pstatus {
            pr_flag: cursor.read_u32::<BigEndian>()
                .map_err(|e| ProcessError::AixParseError(format!("Failed to read pr_flag: {}", e)))?,
            pr_flag2: cursor.read_u32::<BigEndian>()
                .map_err(|e| ProcessError::AixParseError(format!("Failed to read pr_flag2: {}", e)))?,
            pr_nlwp: cursor.read_u32::<BigEndian>()
                .map_err(|e| ProcessError::AixParseError(format!("Failed to read pr_nlwp: {}", e)))?,
            pr_uid: cursor.read_u32::<BigEndian>()? as uid_t,
            pr_gid: cursor.read_u32::<BigEndian>()? as gid_t,
            pr_pid: cursor.read_u32::<BigEndian>()? as pid_t,
            pr_ppid: cursor.read_u32::<BigEndian>()? as pid_t,
            pr_pgid: cursor.read_u32::<BigEndian>()? as pid_t,
            pr_sid: cursor.read_u32::<BigEndian>()? as pid_t,
            pr_clid: cursor.read_i32::<BigEndian>()?,
            pr_pri: cursor.read_i32::<BigEndian>()?,
            pr_nice: cursor.read_i32::<BigEndian>()?,
            pr_wchan: cursor.read_u64::<BigEndian>()?,
            pr_fname: {
                let mut fname = [0u8; PR_FNAME_SIZE];
                cursor.read_exact(&mut fname)
                    .map_err(|e| ProcessError::AixParseError(format!("Failed to read pr_fname: {}", e)))?;
                fname
            },
            pr_psargs: {
                let mut psargs = [0u8; PR_PSARGS_SIZE];
                cursor.read_exact(&mut psargs)
                    .map_err(|e| ProcessError::AixParseError(format!("Failed to read pr_psargs: {}", e)))?;
                psargs
            },
            pr_utime: cursor.read_u64::<BigEndian>()?,
            pr_stime: cursor.read_u64::<BigEndian>()?,
            pr_size: cursor.read_u64::<BigEndian>()?,
            pr_rssize: cursor.read_u64::<BigEndian>()?,
            pr_contract: cursor.read_i32::<BigEndian>()?,
            pr_zoneid: cursor.read_i32::<BigEndian>()?,
            pr_state: cursor.read_u8()?,
            pr_sname: cursor.read_u8()?,
            pr_ttydev: cursor.read_u32::<BigEndian>()?,
            pr_dmodel: cursor.read_u32::<BigEndian>()?,
        };
        
        Ok(pstatus)
    }
    
    fn parse_process_name(&self, fname: &[u8]) -> String {
        let end = fname.iter().position(|&b| b == 0).unwrap_or(fname.len());
        String::from_utf8_lossy(&fname[..end]).to_string()
    }
    
    fn parse_cmdline(&self, psargs: &[u8]) -> Vec<String> {
        let end = psargs.iter().position(|&b| b == 0).unwrap_or(psargs.len());
        let cmdline_str = String::from_utf8_lossy(&psargs[..end]);
        
        // Simple argument parsing - in production would need more sophisticated parsing
        cmdline_str.split_whitespace()
            .map(|s| s.to_string())
            .collect()
    }
    
    fn state_from_aix(&self, state: u8) -> ProcessState {
        match state {
            SSLEEP => ProcessState::Sleeping,
            SRUN | SONPROC => ProcessState::Running,
            SZOMB => ProcessState::Zombie,
            SSTOP => ProcessState::Stopped,
            SIDL => ProcessState::Idle,
            _ => ProcessState::Unknown,
        }
    }
    
    fn read_psinfo(&self, pid: u32) -> Result<HashMap<String, String>> {
        let path = format!("/proc/{}/psinfo", pid);
        let data = fs::read(&path)?;
        
        // Parse psinfo structure for additional information
        // This is simplified - actual implementation would parse the full structure
        let mut info = HashMap::new();
        
        // Extract some basic fields from psinfo
        if data.len() >= 336 {
            let fname_start = 236;
            let fname_end = fname_start + 16;
            if let Ok(fname) = std::str::from_utf8(&data[fname_start..fname_end]) {
                info.insert("fname".to_string(), fname.trim_matches('\0').to_string());
            }
        }
        
        Ok(info)
    }
    
    fn read_cred(&self, pid: u32) -> Result<(uid_t, gid_t, uid_t, gid_t)> {
        let path = format!("/proc/{}/cred", pid);
        let data = fs::read(&path)?;
        
        if data.len() < 32 {
            return Err(ProcessError::AixParseError("Invalid cred structure".to_string()));
        }
        
        let mut cursor = Cursor::new(&data);
        
        // AIX cred structure layout
        let ruid = cursor.read_u32::<BigEndian>()? as uid_t;
        let rgid = cursor.read_u32::<BigEndian>()? as gid_t;
        let euid = cursor.read_u32::<BigEndian>()? as uid_t;
        let egid = cursor.read_u32::<BigEndian>()? as gid_t;
        
        Ok((euid, egid, ruid, rgid))
    }
    
    fn read_environ(&self, pid: u32) -> Result<HashMap<String, String>> {
        let path = format!("/proc/{}/environ", pid);
        let data = fs::read(&path).unwrap_or_default();
        
        let mut environ = HashMap::new();
        let mut start = 0;
        
        for (i, &byte) in data.iter().enumerate() {
            if byte == 0 {
                if let Ok(var) = std::str::from_utf8(&data[start..i]) {
                    if let Some((key, value)) = var.split_once('=') {
                        environ.insert(key.to_string(), value.to_string());
                    }
                }
                start = i + 1;
            }
        }
        
        Ok(environ)
    }
    
    fn read_aix_security(&self, pid: u32) -> Option<AixSecurity> {
        // Read AIX-specific security attributes
        // This would involve reading from /proc/{pid}/privileges and other AIX-specific files
        Some(AixSecurity {
            privilege_set: vec![],
            auth_domains: vec![],
            security_flags: 0,
        })
    }
    
    fn get_exe_path(&self, pid: u32) -> Option<PathBuf> {
        // AIX doesn't have /proc/{pid}/exe symlink
        // We need to use other methods like reading from psinfo or using system calls
        let psinfo_path = format!("/proc/{}/object/a.out", pid);
        if Path::new(&psinfo_path).exists() {
            Some(PathBuf::from(psinfo_path))
        } else {
            None
        }
    }
    
    fn get_cwd(&self, pid: u32) -> Option<PathBuf> {
        let cwd_path = format!("/proc/{}/cwd", pid);
        fs::read_link(&cwd_path).ok()
    }
}

impl ProcessCollector for AixCollector {
    fn collect_all(&self, options: &CollectionOptions) -> Result<Vec<ProcessInfo>> {
        let mut processes = Vec::new();
        
        // Read /proc directory
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
        let pstatus = self.read_pstatus(pid)?;
        let (uid, gid, ruid, rgid) = self.read_cred(pid)
            .unwrap_or((pstatus.pr_uid as u32, pstatus.pr_gid as u32, 
                       pstatus.pr_uid as u32, pstatus.pr_gid as u32));
        
        let mut proc_info = ProcessInfo {
            pid,
            ppid: pstatus.pr_ppid as u32,
            name: self.parse_process_name(&pstatus.pr_fname),
            cmdline: self.parse_cmdline(&pstatus.pr_psargs),
            exe_path: self.get_exe_path(pid),
            cwd: self.get_cwd(pid),
            state: self.state_from_aix(pstatus.pr_state),
            uid,
            gid,
            ruid,
            rgid,
            suid: None,
            sgid: None,
            username: None,
            groupname: None,
            priority: pstatus.pr_pri,
            nice: pstatus.pr_nice,
            threads: pstatus.pr_nlwp,
            start_time: Utc::now(), // Would need to calculate from boot time
            cpu_percent: 0.0,
            memory_rss: pstatus.pr_rssize * 4096, // Convert pages to bytes
            memory_vms: pstatus.pr_size * 4096,
            memory_shared: 0,
            tty: if pstatus.pr_ttydev != 0 { 
                Some(format!("{}:{}", 
                    (pstatus.pr_ttydev >> 16) & 0xFFFF, 
                    pstatus.pr_ttydev & 0xFFFF))
            } else { 
                None 
            },
            session_id: pstatus.pr_sid as u32,
            pgrp: pstatus.pr_pgid as u32,
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
                aix_security: self.read_aix_security(pid),
            },
            platform_data: PlatformData::AIX(AIXProcessData {
                pr_flag: pstatus.pr_flag,
                pr_flag2: pstatus.pr_flag2,
                pr_nlwp: pstatus.pr_nlwp,
                pr_clid: pstatus.pr_clid,
                pr_wchan: pstatus.pr_wchan,
                pr_size: pstatus.pr_size,
                pr_rssize: pstatus.pr_rssize,
                pr_contract: pstatus.pr_contract,
                pr_zoneid: pstatus.pr_zoneid,
                pr_dmodel: match pstatus.pr_dmodel {
                    1 => "32-bit".to_string(),
                    2 => "64-bit".to_string(),
                    _ => "unknown".to_string(),
                },
            }),
        };
        
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
        
        // Note: Open files and network connections would require additional
        // AIX-specific implementations using lsof or similar approaches
        
        Ok(proc_info)
    }
    
    fn is_supported(&self) -> bool {
        cfg!(target_os = "aix")
    }
}