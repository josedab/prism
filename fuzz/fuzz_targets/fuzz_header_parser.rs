#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz HTTP header parsing
    if let Ok(s) = std::str::from_utf8(data) {
        // Parse header lines
        for line in s.lines() {
            if let Some(colon_pos) = line.find(':') {
                let name = &line[..colon_pos];
                let value = line[colon_pos + 1..].trim();

                // Validate header name (ASCII, no control chars)
                let _ = name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');

                // Try to parse as http::HeaderName
                let _ = http::header::HeaderName::try_from(name);
                let _ = http::header::HeaderValue::try_from(value);
            }
        }
    }
});
