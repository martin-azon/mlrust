mod common;

use common::hex::decode_hex_32;
use common::rbg::FixedChunksRbg;

use ml_kem::{
    MlKem512Ciphertext, MlKem768Ciphertext, MlKem1024Ciphertext, ml_kem512_decaps,
    ml_kem512_encaps_with_rbg, ml_kem512_keygen_with_rbg, ml_kem768_decaps,
    ml_kem768_encaps_with_rbg, ml_kem768_keygen_with_rbg, ml_kem1024_decaps,
    ml_kem1024_encaps_with_rbg, ml_kem1024_keygen_with_rbg,
};

use sha3::digest::{ExtendableOutput, Update, XofReader};
use shake::Shake128;

fn cctv_accumulated_mlkem512(iterations: usize) -> [u8; 32] {
    let mut rng = Shake128::default().finalize_xof();
    let mut accumulator = Shake128::default();

    for _ in 0..iterations {
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        let mut m = [0u8; 32];
        let mut invalid_ct_bytes = [0u8; 768];

        rng.read(&mut d);
        rng.read(&mut z);
        rng.read(&mut m);
        rng.read(&mut invalid_ct_bytes);

        let keygen_chunks: [&[u8]; 2] = [d.as_ref(), z.as_ref()];
        let mut keygen_rbg = FixedChunksRbg::new(&keygen_chunks);

        let keypair =
            ml_kem512_keygen_with_rbg(&mut keygen_rbg).expect("ML-KEM-512 keygen succeeds");

        let encaps_chunks: [&[u8]; 1] = [m.as_ref()];
        let mut encaps_rbg = FixedChunksRbg::new(&encaps_chunks);

        let (ss_encaps, ct) =
            ml_kem512_encaps_with_rbg(keypair.encapsulation_key(), &mut encaps_rbg)
                .expect("ML-KEM-512 encaps succeeds");

        let ss_decaps = ml_kem512_decaps(keypair.decapsulation_key(), &ct);
        assert_eq!(ss_encaps.as_bytes(), ss_decaps.as_bytes());

        let invalid_ct = MlKem512Ciphertext::from_bytes(invalid_ct_bytes);
        let ss_invalid_decaps = ml_kem512_decaps(keypair.decapsulation_key(), &invalid_ct);

        accumulator.update(keypair.encapsulation_key().as_bytes());
        accumulator.update(keypair.decapsulation_key().as_bytes());
        accumulator.update(ct.as_bytes());
        accumulator.update(ss_encaps.as_bytes());
        accumulator.update(ss_invalid_decaps.as_bytes());
    }

    let mut out = [0u8; 32];
    let mut reader = accumulator.finalize_xof();
    reader.read(&mut out);

    out
}

fn cctv_accumulated_mlkem768(iterations: usize) -> [u8; 32] {
    let mut rng = Shake128::default().finalize_xof();
    let mut accumulator = Shake128::default();

    for _ in 0..iterations {
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        let mut m = [0u8; 32];
        let mut invalid_ct_bytes = [0u8; 1088];

        rng.read(&mut d);
        rng.read(&mut z);
        rng.read(&mut m);
        rng.read(&mut invalid_ct_bytes);

        let keygen_chunks: [&[u8]; 2] = [d.as_ref(), z.as_ref()];
        let mut keygen_rbg = FixedChunksRbg::new(&keygen_chunks);

        let keypair =
            ml_kem768_keygen_with_rbg(&mut keygen_rbg).expect("ML-KEM-768 keygen succeeds");

        let encaps_chunks: [&[u8]; 1] = [m.as_ref()];
        let mut encaps_rbg = FixedChunksRbg::new(&encaps_chunks);

        let (ss_encaps, ct) =
            ml_kem768_encaps_with_rbg(keypair.encapsulation_key(), &mut encaps_rbg)
                .expect("ML-KEM-768 encaps succeeds");

        let ss_decaps = ml_kem768_decaps(keypair.decapsulation_key(), &ct);
        assert_eq!(ss_encaps.as_bytes(), ss_decaps.as_bytes());

        let invalid_ct = MlKem768Ciphertext::from_bytes(invalid_ct_bytes);
        let ss_invalid_decaps = ml_kem768_decaps(keypair.decapsulation_key(), &invalid_ct);

        accumulator.update(keypair.encapsulation_key().as_bytes());
        accumulator.update(keypair.decapsulation_key().as_bytes());
        accumulator.update(ct.as_bytes());
        accumulator.update(ss_encaps.as_bytes());
        accumulator.update(ss_invalid_decaps.as_bytes());
    }

    let mut out = [0u8; 32];
    let mut reader = accumulator.finalize_xof();
    reader.read(&mut out);

    out
}

fn cctv_accumulated_mlkem1024(iterations: usize) -> [u8; 32] {
    let mut rng = Shake128::default().finalize_xof();
    let mut accumulator = Shake128::default();

    for _ in 0..iterations {
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        let mut m = [0u8; 32];
        let mut invalid_ct_bytes = [0u8; 1568];

        rng.read(&mut d);
        rng.read(&mut z);
        rng.read(&mut m);
        rng.read(&mut invalid_ct_bytes);

        let keygen_chunks: [&[u8]; 2] = [d.as_ref(), z.as_ref()];
        let mut keygen_rbg = FixedChunksRbg::new(&keygen_chunks);

        let keypair =
            ml_kem1024_keygen_with_rbg(&mut keygen_rbg).expect("ML-KEM-1024 keygen succeeds");

        let encaps_chunks: [&[u8]; 1] = [m.as_ref()];
        let mut encaps_rbg = FixedChunksRbg::new(&encaps_chunks);

        let (ss_encaps, ct) =
            ml_kem1024_encaps_with_rbg(keypair.encapsulation_key(), &mut encaps_rbg)
                .expect("ML-KEM-1024 encaps succeeds");

        let ss_decaps = ml_kem1024_decaps(keypair.decapsulation_key(), &ct);
        assert_eq!(ss_encaps.as_bytes(), ss_decaps.as_bytes());

        let invalid_ct = MlKem1024Ciphertext::from_bytes(invalid_ct_bytes);
        let ss_invalid_decaps = ml_kem1024_decaps(keypair.decapsulation_key(), &invalid_ct);

        accumulator.update(keypair.encapsulation_key().as_bytes());
        accumulator.update(keypair.decapsulation_key().as_bytes());
        accumulator.update(ct.as_bytes());
        accumulator.update(ss_encaps.as_bytes());
        accumulator.update(ss_invalid_decaps.as_bytes());
    }

    let mut out = [0u8; 32];
    let mut reader = accumulator.finalize_xof();
    reader.read(&mut out);

    out
}

#[test]
#[ignore = "long CCTV accumulated ML-KEM vector test"]
fn cctv_accumulated_mlkem512_10_000_iterations() {
    let expected =
        decode_hex_32("845913ea5a308b803c764a9ed8e9d814ca1fd9c82ba43c7b1e64b79c7a6ec8e4");

    let actual = cctv_accumulated_mlkem512(10_000);

    assert_eq!(actual, expected);
}

#[test]
#[ignore = "long CCTV accumulated ML-KEM vector test"]
fn cctv_accumulated_mlkem768_10_000_iterations() {
    let expected =
        decode_hex_32("f7db260e1137a742e05fe0db9525012812b004d29040a5b606aad3d134b548d3");

    let actual = cctv_accumulated_mlkem768(10_000);

    assert_eq!(actual, expected);
}

#[test]
#[ignore = "long CCTV accumulated ML-KEM vector test"]
fn cctv_accumulated_mlkem1024_10_000_iterations() {
    let expected =
        decode_hex_32("47ac888fe61544efc0518f46094b4f8a600965fc89822acb06dc7169d24f3543");

    let actual = cctv_accumulated_mlkem1024(10_000);

    assert_eq!(actual, expected);
}
