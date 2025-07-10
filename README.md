# Universal Process Gatherer

[![Crates.io](https://img.shields.io/crates/v/universal-process-gatherer.svg)](https://crates.io/crates/universal-process-gatherer)
[![Documentation](https://docs.rs/universal-process-gatherer/badge.svg)](https://docs.rs/universal-process-gatherer)
[![Build Status](https://github.com/anubhavg-icpl/universal-process-gatherer/workflows/CI/badge.svg)](https://github.com/anubhavg-icpl/universal-process-gatherer/actions)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

A high-performance, cross-platform process information gathering tool designed for security monitoring and system administration. Built in Rust for reliability, memory safety, and performance.

## Features

### Core Capabilities
- **Cross-platform support**: Native implementations for Linux and AIX with fallback support for other platforms
- **Binary procfs parsing**: Full support for AIX's binary `/proc/<pid>/status` format
- **Comprehensive process information**: PID, name, state, CPU/memory usage, network connections, and more
- **High-performance**: Efficient process enumeration with minimal system impact

### Security Analysis
- **Suspicious process detection**: Identifies potentially malicious processes using behavioral patterns
- **Privilege escalation monitoring**: Detects unauthorized privilege changes
- **Network anomaly detection**: Identifies reverse shells and suspicious network activity
- **Custom security rules**: Extensible rule engine for organization-specific threats

### Integration & Export
- **Multiple output formats**: JSON, CSV, YAML, and CEF (Common Event Format) for SIEM integration
- **Real-time monitoring**: Continuous process tracking with configurable intervals
- **Baseline comparison**: Compare current state against known-good baselines
- **Library and CLI**: Use as a Rust library or standalone command-line tool

## Installation

### From Source
```bash
git clone https://github.com/anubhavg-icpl/universal-process-gatherer
cd universal-process-gatherer
cargo build --release
sudo cp target/release/procgather /usr/local/bin/
```

### Using Cargo
```bash
cargo install universal-process-gatherer
```

### Pre-built Binaries
Download pre-built binaries from the [releases page](https://github.com/anubhavg-icpl/universal-process-gatherer/releases).

## Usage

### List All Processes
```bash
# Basic process listing
procgather list

# With additional details
procgather list --include-network --include-files

# JSON output
procgather list --format json

# Filter by name
procgather list --name firefox
```

### Security Analysis
```bash
# Run security analysis
procgather analyze

# Filter by severity
procgather analyze --min-severity high

# Export analysis results
procgather analyze --format json > analysis.json
```

### Real-time Monitoring
```bash
# Monitor all processes
procgather monitor

# Monitor with security analysis
procgather monitor --analyze

# Custom interval
procgather monitor --interval 5
```

### Export for SIEM
```bash
# Export in CEF format for SIEM integration
procgather export --format cef > processes.cef

# Export with security context
procgather export --format json --include-security
```

## Library Usage

```rust
use universal_process_gatherer::{ProcessGatherer, CollectionOptions};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let gatherer = ProcessGatherer::new()?;

    let options = CollectionOptions {
        include_threads: true,
        include_memory_maps: true,
        include_open_files: true,
        include_network_connections: true,
        ..Default::default()
    };

    let processes = gatherer.get_all_processes(Some(options))?;

    for process in processes {
        println!("PID: {}, Name: {}", process.pid, process.name);
    }

    Ok(())
}
```

## Platform Support

| Platform | Status | Implementation |
|----------|--------|----------------|
| Linux | ✅ Full support | Native procfs parsing |
| AIX | ✅ Full support | Binary pstatus parsing |
| macOS | 🚧 In progress | sysctl-based |
| Windows | 🚧 Planned | WinAPI-based |
| FreeBSD | 🚧 Planned | procfs/sysctl |

## Security Considerations

This tool requires elevated privileges to gather complete process information:
- On Linux: CAP_SYS_PTRACE capability or root access for full functionality
- On AIX: Similar privileges required for accessing /proc
- Some security features may be limited without appropriate permissions

## Performance

- Process enumeration: ~10,000 processes/second on modern hardware
- Memory overhead: <50MB for tracking 10,000 processes
- Binary size: ~5MB (release build with all features)

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is dual-licensed under MIT and Apache 2.0. See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE) for details.

## Acknowledgments

- Inspired by the Wazuh process monitoring requirements
- Uses techniques from psutil and procfs libraries
- Security patterns based on MITRE ATT&CK framework
