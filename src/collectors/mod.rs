pub mod traits;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "aix")]
pub mod aix;

pub use traits::ProcessCollector;

use crate::core::Result;

/// Get the appropriate collector for the current platform
pub fn get_collector() -> Result<Box<dyn ProcessCollector>> {
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(linux::LinuxCollector::new()))
    }
    
    #[cfg(target_os = "windows")]
    {
        Ok(Box::new(windows::WindowsCollector::new()))
    }
    
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(macos::MacOSCollector::new()))
    }
    
    #[cfg(target_os = "aix")]
    {
        Ok(Box::new(aix::AixCollector::new()))
    }
    
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos", target_os = "aix")))]
    {
        Err(ProcessError::UnsupportedPlatform(
            format!("Platform {} is not supported", std::env::consts::OS)
        ))
    }
}