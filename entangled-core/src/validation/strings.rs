//! String predicates used by Stage 5 validators.

/// Returns `false` if the string contains any control character in
/// U+0000..=U+001F or U+007F. When `allow_lf` is `true`, U+000A is permitted
/// (used by `code_block.content` and `canary.statement`).
pub fn no_control_chars(s: &str, allow_lf: bool) -> bool {
    for ch in s.chars() {
        let cp = ch as u32;
        let is_c0 = cp <= 0x1F;
        let is_del = cp == 0x7F;
        if is_c0 || is_del {
            if allow_lf && cp == 0x0A {
                continue;
            }
            return false;
        }
    }
    true
}

/// Returns `true` iff `s.len() <= max` (UTF-8 byte length).
pub fn check_byte_len(s: &str, max: usize) -> bool {
    s.len() <= max
}
