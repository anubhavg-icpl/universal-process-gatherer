use crate::core::{ProcessInfo, ProcessError, Result, CollectionOptions};
use crate::collectors::traits::ProcessCollector;

pub struct MacOSCollector;

impl MacOSCollector {
    pub fn new() -> Self {
        Self
    }
}

impl ProcessCollector for MacOSCollector {
    fn collect_all(&self, _options: &CollectionOptions) -> Result<Vec<ProcessInfo>> {
        // TODO: Implement macOS process collection using mach APIs
        Err(ProcessError::UnsupportedPlatform("macOS implementation pending".to_string()))
    }
    
    fn collect_process(&self, _pid: u32, _options: &CollectionOptions) -> Result<ProcessInfo> {
        // TODO: Implement macOS single process collection
        Err(ProcessError::UnsupportedPlatform("macOS implementation pending".to_string()))
    }
    
    fn is_supported(&self) -> bool {
        cfg!(target_os = "macos")
    }
}