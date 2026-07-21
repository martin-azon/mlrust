pub(crate) fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex digit"),
    }
}

pub(crate) fn decode_hex_32(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64);

    let mut out = [0u8; 32];

    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex_nibble(hex.as_bytes()[2 * i]);
        let lo = hex_nibble(hex.as_bytes()[2 * i + 1]);

        *byte = (hi << 4) | lo;
    }

    out
}
