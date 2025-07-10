use crate::core::ProcessInfo;

/// Format bytes to human-readable string
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;
    
    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }
    
    format!("{:.2} {}", size, UNITS[unit_index])
}

/// Format process tree
pub fn format_process_tree(processes: &[ProcessInfo]) -> String {
    let mut output = String::new();
    let mut children_map = std::collections::HashMap::new();
    
    for proc in processes {
        children_map.entry(proc.ppid).or_insert_with(Vec::new).push(proc);
    }
    
    // Find root processes (ppid = 0 or 1)
    let roots: Vec<&ProcessInfo> = processes.iter()
        .filter(|p| p.ppid == 0 || p.ppid == 1)
        .collect();
    
    for root in roots {
        format_tree_node(&mut output, root, &children_map, 0);
    }
    
    output
}

fn format_tree_node(
    output: &mut String,
    process: &ProcessInfo,
    children_map: &std::collections::HashMap<u32, Vec<&ProcessInfo>>,
    depth: usize,
) {
    let indent = "  ".repeat(depth);
    output.push_str(&format!(
        "{}├─ {} (PID: {}, User: {})\n",
        indent,
        process.name,
        process.pid,
        process.username.as_ref().unwrap_or(&"N/A".to_string())
    ));
    
    if let Some(children) = children_map.get(&process.pid) {
        for child in children {
            format_tree_node(output, child, children_map, depth + 1);
        }
    }
}