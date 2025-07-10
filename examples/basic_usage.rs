//! Basic usage example

use universal_process_gatherer::ProcessGatherer;

fn main() {
    let gatherer = ProcessGatherer::new();
    
    match gatherer.get_all_processes() {
        Ok(processes) => {
            println!("Found {} processes", processes.len());
            for process in processes.iter().take(10) {
                println!("PID: {} - Name: {}", process.pid, process.name);
            }
        }
        Err(e) => eprintln!("Error: {}", e),
    }
}