use crate::core::{ProcessInfo, Result, CollectionOptions};

/// Trait for platform-specific process collectors
pub trait ProcessCollector: Send + Sync {
    /// Collect all processes based on the given options
    fn collect_all(&self, options: &CollectionOptions) -> Result<Vec<ProcessInfo>>;
    
    /// Collect a single process by PID
    fn collect_process(&self, pid: u32, options: &CollectionOptions) -> Result<ProcessInfo>;
    
    /// Check if this collector is supported on the current platform
    fn is_supported(&self) -> bool;
}