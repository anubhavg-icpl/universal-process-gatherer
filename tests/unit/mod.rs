//! Unit tests for universal-process-gatherer

#[cfg(test)]
mod process_info_tests {
    use universal_process_gatherer::ProcessInfo;
    use std::time::SystemTime;

    #[test]
    fn test_process_info_creation() {
        let info = ProcessInfo {
            pid: 1234,
            name: "test_process".to_string(),
            parent_pid: Some(1),
            cpu_usage: 25.5,
            memory_usage: 1024 * 1024 * 50, // 50MB
            start_time: SystemTime::now(),
            user: "testuser".to_string(),
            command_line: vec!["test".to_string(), "--flag".to_string()],
        };
        
        assert_eq!(info.pid, 1234);
        assert_eq!(info.name, "test_process");
    }
}