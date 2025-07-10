use crate::core::{ProcessInfo, ProcessError, Result};
use crate::security::analyzer::SecurityFinding;
use serde_json;
use csv::Writer;
use chrono::Utc;
use std::io::Write;
use std::fs::File;

/// Export format options
#[derive(Debug, Clone, Copy)]
pub enum ExportFormat {
    Json,
    JsonPretty,
    Csv,
    Yaml,
    Cef,  // Common Event Format for SIEM
}

/// Export options
#[derive(Debug, Clone)]
pub struct ExportOptions {
    pub format: ExportFormat,
    pub include_security_findings: bool,
    pub output_path: Option<String>,
}

/// Process exporter
pub struct Exporter;

impl Exporter {
    pub fn export_processes(
        processes: &[ProcessInfo],
        findings: &[SecurityFinding],
        options: &ExportOptions,
    ) -> Result<String> {
        let output = match options.format {
            ExportFormat::Json => Self::to_json(processes, findings, options, false)?,
            ExportFormat::JsonPretty => Self::to_json(processes, findings, options, true)?,
            ExportFormat::Csv => Self::to_csv(processes, options)?,
            ExportFormat::Yaml => Self::to_yaml(processes, findings, options)?,
            ExportFormat::Cef => Self::to_cef(processes, findings, options)?,
        };
        
        if let Some(ref path) = options.output_path {
            let mut file = File::create(path)
                .map_err(|e| ProcessError::ExportError(format!("Failed to create file: {}", e)))?;
            file.write_all(output.as_bytes())
                .map_err(|e| ProcessError::ExportError(format!("Failed to write file: {}", e)))?;
        }
        
        Ok(output)
    }
    
    fn to_json(
        processes: &[ProcessInfo],
        findings: &[SecurityFinding],
        options: &ExportOptions,
        pretty: bool,
    ) -> Result<String> {
        let data = if options.include_security_findings {
            serde_json::json!({
                "timestamp": Utc::now(),
                "process_count": processes.len(),
                "processes": processes,
                "security_findings": findings,
            })
        } else {
            serde_json::json!({
                "timestamp": Utc::now(),
                "process_count": processes.len(),
                "processes": processes,
            })
        };
        
        if pretty {
            serde_json::to_string_pretty(&data)
        } else {
            serde_json::to_string(&data)
        }
        .map_err(|e| ProcessError::ExportError(format!("JSON serialization failed: {}", e)))
    }
    
    fn to_csv(processes: &[ProcessInfo], _options: &ExportOptions) -> Result<String> {
        let mut wtr = Writer::from_writer(vec![]);
        
        // Write header
        wtr.write_record(&[
            "PID", "PPID", "Name", "State", "UID", "GID", "Username", 
            "Priority", "Nice", "Threads", "CPU%", "RSS(MB)", "VMS(MB)",
            "TTY", "Command", "Executable", "Start Time"
        ]).map_err(|e| ProcessError::ExportError(format!("CSV write failed: {}", e)))?;
        
        // Write process data
        for proc in processes {
            wtr.write_record(&[
                proc.pid.to_string(),
                proc.ppid.to_string(),
                proc.name.clone(),
                proc.state.as_str().to_string(),
                proc.uid.to_string(),
                proc.gid.to_string(),
                proc.username.clone().unwrap_or_else(|| "N/A".to_string()),
                proc.priority.to_string(),
                proc.nice.to_string(),
                proc.threads.to_string(),
                format!("{:.2}", proc.cpu_percent),
                format!("{:.2}", proc.memory_rss as f64 / 1024.0 / 1024.0),
                format!("{:.2}", proc.memory_vms as f64 / 1024.0 / 1024.0),
                proc.tty.clone().unwrap_or_else(|| "N/A".to_string()),
                proc.cmdline.join(" "),
                proc.exe_path.as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "N/A".to_string()),
                proc.start_time.to_rfc3339(),
            ]).map_err(|e| ProcessError::ExportError(format!("CSV write failed: {}", e)))?;
        }
        
        wtr.flush()
            .map_err(|e| ProcessError::ExportError(format!("CSV flush failed: {}", e)))?;
        
        String::from_utf8(wtr.into_inner()
            .map_err(|e| ProcessError::ExportError(format!("CSV finalization failed: {}", e)))?)
            .map_err(|e| ProcessError::ExportError(format!("CSV UTF-8 conversion failed: {}", e)))
    }
    
    fn to_yaml(
        processes: &[ProcessInfo],
        findings: &[SecurityFinding],
        options: &ExportOptions,
    ) -> Result<String> {
        let data = if options.include_security_findings {
            serde_yaml::to_string(&serde_json::json!({
                "timestamp": Utc::now(),
                "process_count": processes.len(),
                "processes": processes,
                "security_findings": findings,
            }))
        } else {
            serde_yaml::to_string(&serde_json::json!({
                "timestamp": Utc::now(),
                "process_count": processes.len(),
                "processes": processes,
            }))
        };
        
        data.map_err(|e| ProcessError::ExportError(format!("YAML serialization failed: {}", e)))
    }
    
    fn to_cef(
        processes: &[ProcessInfo],
        findings: &[SecurityFinding],
        options: &ExportOptions,
    ) -> Result<String> {
        let mut output = String::new();
        let _timestamp = Utc::now();
        
        // CEF header format: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|Extension
        
        if options.include_security_findings {
            for finding in findings {
                let cef_line = format!(
                    "CEF:0|UniversalProcessGatherer|ProcessMonitor|1.0|{}|{}|{}|pid={} proc={} msg={} act={}\n",
                    finding.rule_id,
                    finding.title,
                    Self::severity_to_cef(finding.severity),
                    finding.pid,
                    finding.process_name,
                    finding.description.replace('|', "\\|"),
                    finding.recommendations.join("; ").replace('|', "\\|")
                );
                output.push_str(&cef_line);
            }
        } else {
            // Export process information in CEF format
            for proc in processes {
                let cef_line = format!(
                    "CEF:0|UniversalProcessGatherer|ProcessMonitor|1.0|PROCESS_INFO|Process Information|3|pid={} ppid={} proc={} user={} cmd={} exe={} state={} mem={}\n",
                    proc.pid,
                    proc.ppid,
                    proc.name,
                    proc.username.as_ref().unwrap_or(&"N/A".to_string()),
                    proc.cmdline.join(" ").replace('|', "\\|"),
                    proc.exe_path.as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "N/A".to_string())
                        .replace('|', "\\|"),
                    proc.state.as_str(),
                    proc.memory_rss
                );
                output.push_str(&cef_line);
            }
        }
        
        Ok(output)
    }
    
    fn severity_to_cef(severity: crate::security::analyzer::Severity) -> u8 {
        match severity {
            crate::security::analyzer::Severity::Info => 1,
            crate::security::analyzer::Severity::Low => 3,
            crate::security::analyzer::Severity::Medium => 5,
            crate::security::analyzer::Severity::High => 7,
            crate::security::analyzer::Severity::Critical => 10,
        }
    }
}