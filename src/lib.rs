pub mod core;
pub mod collectors;
pub mod security;
pub mod export;
pub mod utils;
pub mod api;

pub use core::{ProcessInfo, ProcessState, CollectionOptions, ProcessError, Result};
pub use collectors::{ProcessCollector, get_collector};
pub use security::{SecurityAnalyzer, SecurityFinding, Severity};
pub use export::{Exporter, ExportFormat, ExportOptions};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Get all processes with default options
pub fn get_processes() -> Result<Vec<ProcessInfo>> {
    let collector = get_collector()?;
    let options = CollectionOptions::default();
    collector.collect_all(&options)
}

/// Get all processes with custom options
pub fn get_processes_with_options(options: &CollectionOptions) -> Result<Vec<ProcessInfo>> {
    let collector = get_collector()?;
    collector.collect_all(options)
}

/// Get a single process by PID
pub fn get_process(pid: u32) -> Result<ProcessInfo> {
    let collector = get_collector()?;
    let options = CollectionOptions::default();
    collector.collect_process(pid, &options)
}

/// Analyze processes for security issues
pub fn analyze_security(processes: &[ProcessInfo]) -> Vec<SecurityFinding> {
    let analyzer = SecurityAnalyzer::new();
    analyzer.analyze_all(processes)
}