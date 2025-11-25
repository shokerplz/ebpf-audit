#[macro_export]
macro_rules! time_it {
    ($name:expr, $block:expr) => {{
        let start = std::time::Instant::now();
        let result = $block;
        let elapsed = start.elapsed();
        log::debug!("{} took {:?}", $name, elapsed);
        result
    }};
}
