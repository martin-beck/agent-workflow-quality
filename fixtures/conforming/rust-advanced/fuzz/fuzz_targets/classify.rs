#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(first) = data.first() {
        let _ = awq_advanced_fixture::classify(i32::from(*first));
    }
});
