//! Pure string helpers for deriving key selector file names.
//!
//! Moved out of `main.rs` as part of the incremental module split (M1 step 1).

pub(crate) fn slugify_key_name(name: &str) -> String {
    let mut slug = String::new();
    let mut last_dash = false;

    for ch in name.chars().flat_map(char::to_lowercase) {
        let is_allowed = ch.is_ascii_alphanumeric() || ch == '_' || ch == '-';
        if is_allowed {
            slug.push(ch);
            last_dash = false;
        } else if !last_dash {
            slug.push('-');
            last_dash = true;
        }
    }

    let slug = slug.trim_matches('-');
    if slug.is_empty() {
        "ssh-key".to_string()
    } else {
        slug.to_string()
    }
}

pub(crate) fn vault_item_id_prefix(cipher_id: &str) -> String {
    cipher_id
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .take(8)
        .collect::<String>()
}

pub(crate) fn selector_file_name(key_name: &str, cipher_id: &str) -> String {
    let prefix = vault_item_id_prefix(cipher_id);
    if prefix.is_empty() {
        format!("{}.pub", slugify_key_name(key_name))
    } else {
        format!("{}--{}.pub", slugify_key_name(key_name), prefix)
    }
}
