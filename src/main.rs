use clap::{Parser, Subcommand};
use env_logger;
use log::{info, error};
use std::process;
use std::time::Duration;
use std::thread;
use universal_process_gatherer::{
    CollectionOptions, ExportFormat, ExportOptions, Exporter,
    SecurityAnalyzer, get_processes_with_options, get_process,
};

#[derive(Parser)]
#[command(name = "upgatherer")]
#[command(about = "Universal Process Gatherer - Cross-platform process monitoring and analysis")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List all processes
    List {
        /// Include environment variables
        #[arg(long, default_value = "false")]
        include_env: bool,
        
        /// Include open files
        #[arg(long, default_value = "false")]
        include_files: bool,
        
        /// Include network connections
        #[arg(long, default_value = "false")]
        include_connections: bool,
        
        /// Calculate executable checksums
        #[arg(long, default_value = "false")]
        checksums: bool,
        
        /// Filter by username
        #[arg(short, long)]
        user: Option<String>,
        
        /// Filter by process name pattern
        #[arg(short, long)]
        name: Option<String>,
        
        /// Output format (json, json-pretty, csv, yaml, cef)
        #[arg(short, long, default_value = "json-pretty")]
        format: String,
        
        /// Output file path
        #[arg(short, long)]
        output: Option<String>,
    },
    
    /// Monitor processes continuously
    Monitor {
        /// Update interval in seconds
        #[arg(short, long, default_value = "5")]
        interval: u64,
        
        /// Include security analysis
        #[arg(long, default_value = "false")]
        security: bool,
    },
    
    /// Analyze processes for security issues
    Analyze {
        /// Output format (json, json-pretty, yaml)
        #[arg(short, long, default_value = "json-pretty")]
        format: String,
        
        /// Output file path
        #[arg(short, long)]
        output: Option<String>,
        
        /// Only show findings of minimum severity (info, low, medium, high, critical)
        #[arg(long)]
        min_severity: Option<String>,
    },
    
    /// Watch specific process by PID
    Watch {
        /// Process ID to watch
        pid: u32,
        
        /// Update interval in seconds
        #[arg(short, long, default_value = "1")]
        interval: u64,
    },
    
    /// Export process data in various formats
    Export {
        /// Export format (json, csv, yaml, cef)
        #[arg(short, long)]
        format: String,
        
        /// Output file path
        #[arg(short, long)]
        output: String,
        
        /// Include security findings
        #[arg(long, default_value = "false")]
        security: bool,
    },
}

fn main() {
    env_logger::init();
    
    let cli = Cli::parse();
    
    match run(cli) {
        Ok(_) => {}
        Err(e) => {
            error!("Error: {}", e);
            process::exit(1);
        }
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Commands::List { 
            include_env, 
            include_files, 
            include_connections, 
            checksums, 
            user, 
            name, 
            format, 
            output 
        } => {
            let options = CollectionOptions {
                include_environ: include_env,
                include_open_files: include_files,
                include_connections,
                calculate_checksums: checksums,
                filter_user: user,
                filter_name: name,
                ..Default::default()
            };
            
            info!("Collecting processes...");
            let processes = get_processes_with_options(&options)?;
            info!("Found {} processes", processes.len());
            
            let export_format = parse_format(&format)?;
            let export_options = ExportOptions {
                format: export_format,
                include_security_findings: false,
                output_path: output,
            };
            
            let output = Exporter::export_processes(&processes, &[], &export_options)?;
            if export_options.output_path.is_none() {
                println!("{}", output);
            } else {
                println!("Exported to: {}", export_options.output_path.unwrap());
            }
        }
        
        Commands::Monitor { interval, security } => {
            println!("Starting process monitor (Ctrl+C to stop)...");
            
            loop {
                print!("\x1B[2J\x1B[1;1H"); // Clear screen
                
                let options = CollectionOptions::default();
                let processes = get_processes_with_options(&options)?;
                
                println!("=== Process Monitor === {} processes", processes.len());
                println!("{:<8} {:<8} {:<16} {:<10} {:<8} {:<10} {:<10}",
                    "PID", "PPID", "NAME", "STATE", "USER", "CPU%", "MEM(MB)");
                println!("{}", "-".repeat(80));
                
                for proc in processes.iter().take(50) {
                    println!("{:<8} {:<8} {:<16} {:<10} {:<8} {:<10.2} {:<10.2}",
                        proc.pid,
                        proc.ppid,
                        truncate(&proc.name, 16),
                        proc.state.as_str(),
                        proc.username.as_ref().unwrap_or(&"N/A".to_string()),
                        proc.cpu_percent,
                        proc.memory_rss as f64 / 1024.0 / 1024.0
                    );
                }
                
                if security {
                    let analyzer = SecurityAnalyzer::new();
                    let findings = analyzer.analyze_all(&processes);
                    if !findings.is_empty() {
                        println!("\n=== Security Findings ===");
                        for finding in findings.iter().take(10) {
                            println!("[{}] PID {} - {}: {}",
                                finding.severity.as_str(),
                                finding.pid,
                                finding.process_name,
                                finding.title
                            );
                        }
                    }
                }
                
                thread::sleep(Duration::from_secs(interval));
            }
        }
        
        Commands::Analyze { format, output, min_severity } => {
            info!("Analyzing processes for security issues...");
            
            let options = CollectionOptions {
                include_connections: true,
                include_open_files: true,
                calculate_checksums: true,
                ..Default::default()
            };
            
            let processes = get_processes_with_options(&options)?;
            let analyzer = SecurityAnalyzer::new();
            let mut findings = analyzer.analyze_all(&processes);
            
            // Filter by severity if specified
            if let Some(min_sev) = min_severity {
                let min_level = parse_severity(&min_sev)?;
                findings.retain(|f| f.severity >= min_level);
            }
            
            info!("Found {} security findings", findings.len());
            
            let export_format = parse_format(&format)?;
            let export_options = ExportOptions {
                format: export_format,
                include_security_findings: true,
                output_path: output,
            };
            
            let output = Exporter::export_processes(&[], &findings, &export_options)?;
            if export_options.output_path.is_none() {
                println!("{}", output);
            } else {
                println!("Exported to: {}", export_options.output_path.unwrap());
            }
        }
        
        Commands::Watch { pid, interval } => {
            println!("Watching process {} (Ctrl+C to stop)...", pid);
            
            loop {
                print!("\x1B[2J\x1B[1;1H"); // Clear screen
                
                match get_process(pid) {
                    Ok(proc) => {
                        println!("=== Process {} ===", pid);
                        println!("Name: {}", proc.name);
                        println!("State: {}", proc.state.as_str());
                        println!("Parent PID: {}", proc.ppid);
                        println!("User: {} (UID: {})", 
                            proc.username.as_ref().unwrap_or(&"N/A".to_string()), 
                            proc.uid
                        );
                        println!("Command: {}", proc.cmdline.join(" "));
                        if let Some(ref exe) = proc.exe_path {
                            println!("Executable: {}", exe.display());
                        }
                        println!("Threads: {}", proc.threads);
                        println!("CPU: {:.2}%", proc.cpu_percent);
                        println!("Memory RSS: {:.2} MB", proc.memory_rss as f64 / 1024.0 / 1024.0);
                        println!("Memory VMS: {:.2} MB", proc.memory_vms as f64 / 1024.0 / 1024.0);
                        println!("Start time: {}", proc.start_time.format("%Y-%m-%d %H:%M:%S"));
                        
                        if !proc.connections.is_empty() {
                            println!("\nNetwork Connections:");
                            for conn in &proc.connections {
                                println!("  {} {}:{} -> {}:{}",
                                    conn.protocol,
                                    conn.local_addr,
                                    conn.local_port,
                                    conn.remote_addr.as_ref().unwrap_or(&"*".to_string()),
                                    conn.remote_port.unwrap_or(0)
                                );
                            }
                        }
                    }
                    Err(e) => {
                        println!("Error: {}", e);
                        break;
                    }
                }
                
                thread::sleep(Duration::from_secs(interval));
            }
        }
        
        Commands::Export { format, output, security } => {
            info!("Exporting process data...");
            
            let options = CollectionOptions {
                include_connections: security,
                include_open_files: security,
                calculate_checksums: security,
                ..Default::default()
            };
            
            let processes = get_processes_with_options(&options)?;
            let findings = if security {
                let analyzer = SecurityAnalyzer::new();
                analyzer.analyze_all(&processes)
            } else {
                vec![]
            };
            
            let export_format = parse_format(&format)?;
            let export_options = ExportOptions {
                format: export_format,
                include_security_findings: security,
                output_path: Some(output.clone()),
            };
            
            Exporter::export_processes(&processes, &findings, &export_options)?;
            println!("Exported {} processes to: {}", processes.len(), output);
        }
    }
    
    Ok(())
}

fn parse_format(format: &str) -> Result<ExportFormat, String> {
    match format.to_lowercase().as_str() {
        "json" => Ok(ExportFormat::Json),
        "json-pretty" => Ok(ExportFormat::JsonPretty),
        "csv" => Ok(ExportFormat::Csv),
        "yaml" => Ok(ExportFormat::Yaml),
        "cef" => Ok(ExportFormat::Cef),
        _ => Err(format!("Unknown format: {}", format)),
    }
}

fn parse_severity(severity: &str) -> Result<universal_process_gatherer::Severity, String> {
    match severity.to_lowercase().as_str() {
        "info" => Ok(universal_process_gatherer::Severity::Info),
        "low" => Ok(universal_process_gatherer::Severity::Low),
        "medium" => Ok(universal_process_gatherer::Severity::Medium),
        "high" => Ok(universal_process_gatherer::Severity::High),
        "critical" => Ok(universal_process_gatherer::Severity::Critical),
        _ => Err(format!("Unknown severity: {}", severity)),
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len-3])
    }
}