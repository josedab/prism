#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz YAML config parsing
    if let Ok(s) = std::str::from_utf8(data) {
        // Try to parse as YAML config
        let _ = serde_yaml::from_str::<serde_yaml::Value>(s);
    }
});
