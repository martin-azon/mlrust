use alloc::vec::Vec;

pub(crate) fn try_hex_field<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    for line in text.lines() {
        let line = line.trim();

        let Some((lhs, rhs)) = line.split_once('=') else {
            continue;
        };

        if lhs.trim() == name {
            return Some(
                rhs.trim()
                    .rsplit(" = ")
                    .next()
                    .expect("field has a value")
                    .trim(),
            );
        }
    }

    None
}

pub(crate) fn hex_field<'a>(text: &'a str, name: &str) -> &'a str {
    try_hex_field(text, name).unwrap_or_else(|| {
        panic!("missing CCTV field: {name}");
    })
}

pub(crate) fn hex_field_any<'a>(text: &'a str, names: &[&str]) -> &'a str {
    for name in names {
        if let Some(value) = try_hex_field(text, name) {
            return value;
        }
    }

    panic!("missing CCTV field among: {names:?}");
}

pub(crate) fn hex_array<const N: usize>(hex_str: &str) -> [u8; N] {
    let bytes = hex::decode(hex_str).expect("valid hex");

    bytes.try_into().unwrap_or_else(|bytes: Vec<u8>| {
        panic!("wrong length: expected {N} bytes, got {}", bytes.len())
    })
}

pub(crate) fn hex_field_nth<'a>(text: &'a str, name: &str, n: usize) -> &'a str {
    let mut count = 0usize;

    for line in text.lines() {
        let line = line.trim();

        let Some((lhs, rhs)) = line.split_once('=') else {
            continue;
        };

        if lhs.trim() == name {
            if count == n {
                return rhs
                    .trim()
                    .rsplit(" = ")
                    .next()
                    .expect("field has a value")
                    .trim();
            }

            count += 1;
        }
    }

    panic!("missing CCTV field occurrence {n}: {name}");
}
