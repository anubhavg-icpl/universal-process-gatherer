//! Build script for universal-process-gatherer

fn main() {
    // Platform-specific build configuration
    let target_os = std::env::var("CARGO_CFG_TARGET_OS");
    
    match target_os.as_ref().map(|s| s.as_str()) {
        Ok("linux") => {
            println!("cargo:rerun-if-changed=src/collectors/linux.rs");
        }
        Ok("windows") => {
            println!("cargo:rerun-if-changed=src/collectors/windows.rs");
        }
        Ok("macos") => {
            println!("cargo:rerun-if-changed=src/collectors/macos.rs");
        }
        _ => {}
    }
}