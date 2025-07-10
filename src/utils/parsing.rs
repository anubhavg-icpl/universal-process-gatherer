use std::str::FromStr;

/// Parse memory size from string (e.g., "1024K", "2M", "1G")
pub fn parse_memory_size(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    
    let (num_part, unit) = if s.chars().last()?.is_alphabetic() {
        let pos = s.rfind(|c: char| c.is_numeric())?;
        s.split_at(pos + 1)
    } else {
        (s, "")
    };
    
    let number = u64::from_str(num_part).ok()?;
    
    let multiplier = match unit.to_uppercase().as_str() {
        "" | "B" => 1,
        "K" | "KB" => 1024,
        "M" | "MB" => 1024 * 1024,
        "G" | "GB" => 1024 * 1024 * 1024,
        "T" | "TB" => 1024_u64.pow(4),
        _ => return None,
    };
    
    Some(number * multiplier)
}

/// Parse process ID from string
pub fn parse_pid(s: &str) -> Option<u32> {
    s.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_memory_size() {
        assert_eq!(parse_memory_size("1024"), Some(1024));
        assert_eq!(parse_memory_size("1K"), Some(1024));
        assert_eq!(parse_memory_size("2M"), Some(2 * 1024 * 1024));
        assert_eq!(parse_memory_size("1G"), Some(1024 * 1024 * 1024));
        assert_eq!(parse_memory_size(""), None);
        assert_eq!(parse_memory_size("invalid"), None);
    }
}