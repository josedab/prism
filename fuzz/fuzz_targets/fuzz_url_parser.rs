#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz URL parsing
    if let Ok(s) = std::str::from_utf8(data) {
        // Try parsing as URL
        let _ = url::Url::parse(s);

        // Try parsing as URI
        let _ = s.parse::<http::Uri>();

        // Try parsing as socket address
        let _ = s.parse::<std::net::SocketAddr>();
    }
});
