pub fn classify(value: i32) -> i32 {
    if value > 0 { value + 1 } else { value - 1 }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn positive() { assert_eq!(classify(1), 2); }
    #[test] fn negative() { assert_eq!(classify(-1), -2); }
}
