#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct PathMatchInput {
    pattern: String,
    path: String,
}

fuzz_target!(|input: PathMatchInput| {
    // Fuzz path matching logic
    let pattern = &input.pattern;
    let path = &input.path;

    // Test prefix matching
    let _ = path.starts_with(pattern);

    // Test exact matching
    let _ = path == pattern;

    // Test regex matching (if pattern is valid regex)
    if let Ok(re) = regex::Regex::new(pattern) {
        let _ = re.is_match(path);
    }
});
