use thiserror::Error;
use std::io;

/// Process gathering errors
#[derive(Error, Debug)]
pub enum ProcessError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    
    #[error("Permission denied accessing process {pid}")]
    PermissionDenied { pid: u32 },
    
    #[error("Process {pid} not found")]
    ProcessNotFound { pid: u32 },
    
    #[error("Failed to parse process data: {0}")]
    ParseError(String),
    
    #[error("Platform not supported: {0}")]
    UnsupportedPlatform(String),
    
    #[error("Failed to access procfs: {0}")]
    ProcfsError(String),
    
    #[error("Failed to parse AIX binary data: {0}")]
    AixParseError(String),
    
    #[error("Invalid UTF-8 in process data: {0}")]
    Utf8Error(#[from] std::str::Utf8Error),
    
    #[error("Failed to get user/group info: {0}")]
    UserLookupError(String),
    
    #[error("System call failed: {0}")]
    SystemCallError(String),
    
    #[error("Timeout while collecting process data")]
    Timeout,
    
    #[error("Security analysis error: {0}")]
    SecurityError(String),
    
    #[error("Export format error: {0}")]
    ExportError(String),
}

pub type Result<T> = std::result::Result<T, ProcessError>;