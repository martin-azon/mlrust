use subtle::{ConstantTimeEq, Choice, ConditionallySelectable};

pub fn ct_eq(a: &[u8], b: &[u8]) -> Choice {
    a.ct_eq(b)
}

pub fn ct_is_zero(a: &[u8]) -> Choice {
    let mut acc = 0u8;

    for &byte in a {
        acc |= byte;
    }

    acc.ct_eq(&0u8)
}

pub fn ct_select_bytes(
    out: &mut [u8],
    a: &[u8],
    b: &[u8],
    choice: Choice
) {
    assert_eq!(a.len(), b.len());
    assert_eq!(a.len(), out.len());

    for ((out_byte, a_byte), b_byte) in out.iter_mut().zip(a.iter()).zip(b.iter()) {
        *out_byte = u8::conditional_select(a_byte, b_byte, choice);
    }
}

pub fn ct_conditional_assign_bytes(
    target: &mut [u8],
    source: &[u8],
    choice: Choice
) {
    assert_eq!(target.len(), source.len());

    for (target_byte, source_byte) in target.iter_mut().zip(source.iter()){
        target_byte.conditional_assign(source_byte, choice);
    }
}