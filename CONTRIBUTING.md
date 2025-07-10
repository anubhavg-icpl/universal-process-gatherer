# Contributing to Universal Process Gatherer

Thank you for your interest in contributing to Universal Process Gatherer! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct. Please read it before contributing.

## How to Contribute

### Reporting Issues

- Check existing issues before creating a new one
- Use issue templates when available
- Provide as much context as possible
- Include system information (OS, architecture, Rust version)

### Submitting Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass (`cargo test`)
6. Run clippy (`cargo clippy -- -D warnings`)
7. Format your code (`cargo fmt`)
8. Commit with clear messages
9. Push to your branch
10. Open a Pull Request

### Development Setup

```bash
# Clone your fork
git clone https://github.com/anubhavg-icpl/universal-process-gatherer
cd universal-process-gatherer

# Install Rust (if needed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build the project
cargo build

# Run tests
cargo test

# Run with debug output
RUST_LOG=debug cargo run -- list
```

### Testing

- Write unit tests for new functions
- Add integration tests for new features
- Test on multiple platforms if possible
- Include edge cases and error conditions

### Documentation

- Update documentation for API changes
- Add examples for new features
- Keep README.md up to date
- Use clear, descriptive comments

### Code Style

- Follow Rust naming conventions
- Use `rustfmt` for formatting
- Keep functions focused and small
- Prefer explicit error handling
- Document public APIs

### Platform-Specific Code

When adding platform-specific code:
- Use conditional compilation (`#[cfg(...)]`)
- Provide fallback implementations
- Test on target platform
- Document platform requirements

### Security Considerations

- Never log sensitive information
- Validate all inputs
- Handle errors gracefully
- Consider security implications
- Follow principle of least privilege

## Pull Request Process

1. Update documentation
2. Add tests for new features
3. Ensure CI passes
4. Request review from maintainers
5. Address review feedback
6. Squash commits if requested

## Release Process

Releases are managed by maintainers:
1. Version bump in Cargo.toml
2. Update CHANGELOG.md
3. Tag release
4. GitHub Actions builds binaries
5. Publish to crates.io

## Getting Help

- Open an issue for questions
- Join discussions in issues
- Check existing documentation
- Ask in pull request comments

Thank you for contributing!
