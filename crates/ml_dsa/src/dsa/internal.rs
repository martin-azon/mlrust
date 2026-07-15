



use crate::encoding::{pk_decode, pk_encode, sig_decode, sig_encode, sk_decode, sk_encode, w1_encode, DecodedPublicKey, DecodedSecretKey, DecodedSignature};
use crate::error::MlDsaError;
use crate::keys::{MlDsaKeypair, PublicKey, SecretKey, Signature};
use crate::primitives::challenge::sample_in_ball;
use crate::primitives::norm::norm_polyvec_zq;
use crate::primitives::rounding::{high_bits_vec, low_bits_vec, make_hint_vec, mod_pm_q_polyvec, power2round_vec, use_hint_vec};
use crate::primitives::sampling::{expand_a, expand_mask, expand_s};

use mlrust_core::encode::bits::{bitlen_u32, int_to_bytes};
use mlrust_core::params::{Q8380417, RingParams};
use mlrust_core::poly::PolyVec;
use mlrust_core::symmetric::ml_dsa::{h, h_init, h_absorb, h_finalize, h_squeeze};
use mlrust_core::error::PqcCoreError;


pub(crate) fn ml_dsa_keygen_internal<
    const K: usize,
    const L: usize,
    const D: usize,
    const ETA: usize,
    const BITLEN_2ETA: usize,
    const SK_BYTES: usize,
    const PK_BYTES: usize,
> (randomness_xi: &[u8; 32]) -> MlDsaKeypair<SK_BYTES, PK_BYTES> {
    assert_eq!(BITLEN_2ETA, bitlen_u32(2 * ETA as u32));
    assert_eq!(PK_BYTES, 32 + 32 * K * (bitlen_u32(Q8380417::Q as u32 - 1) - D));
    assert_eq!(SK_BYTES, 128 + 32 * ((L + K) * BITLEN_2ETA + D * K));


    let mut input_hash = [0u8; 34];

    input_hash[0..32].copy_from_slice(randomness_xi);
    int_to_bytes(K as u32, 1, &mut input_hash[32..33]);
    int_to_bytes(L as u32, 1, &mut input_hash[33..34]);

    let mut buffer = [0u8; 128];

    h(&input_hash, &mut buffer);

    let mut rho = [0u8; 32];
    let mut rho_prime = [0u8; 64];
    let mut seed_k = [0u8; 32];

    rho.copy_from_slice(&buffer[0..32]);
    rho_prime.copy_from_slice(&buffer[32..96]);
    seed_k.copy_from_slice(&buffer[96..]);

    let a_hat = expand_a::<K, L>(&rho);
    let (s1, s2) = expand_s::<K, L, ETA>(&rho_prime);

    let mut s1_hat = s1;
    s1_hat.ntt();

    let mut t = a_hat.mul_vec_ntt(&s1_hat);
    t.inv_ntt();
    t.add_assign(&s2);

    let (t1, t0) = power2round_vec::<K, D>(&t);

    let pk = pk_encode::<K, D, PK_BYTES>(
        &DecodedPublicKey{rho, t1}
    );

    let mut tr = [0u8; 64];
    h(pk.as_bytes(), &mut tr);

    let sk = sk_encode::<K, L, D, ETA, BITLEN_2ETA, SK_BYTES>(
        &DecodedSecretKey{rho, seed_k, tr, s1, s2, t0}
    );

    MlDsaKeypair::from_parts(sk, pk)
}



pub(crate) fn ml_dsa_sign_internal<
    const K: usize,
    const L: usize,
    const D: usize,
    const TAU: usize,
    const LAMBDA_OVER_4: usize,
    const GAMMA1: usize,
    const BITLEN_2GAMMA1_MINUS_ONE: usize,
    const BITLEN_2GAMMA1_MINUS_ONE_TIMES_32: usize,
    const GAMMA2: usize,
    const BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE: usize,
    const K_TIMES_32_TIMES_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE: usize,
    const ETA: usize,
    const BITLEN_2ETA: usize,
    const BETA: usize,
    const OMEGA: usize,
    const SK_BYTES: usize,
    const SIG_BYTES: usize
> (
    sk: &SecretKey<SK_BYTES>,
    formatted_message: &[u8],
    randomness: &[u8; 32]
) -> Result<Signature<SIG_BYTES>, MlDsaError> {
    assert_eq!(BITLEN_2ETA, bitlen_u32(2 * ETA as u32));
    assert_eq!(BITLEN_2GAMMA1_MINUS_ONE, bitlen_u32(2 * GAMMA1 as u32 - 1));
    assert_eq!(BITLEN_2GAMMA1_MINUS_ONE_TIMES_32, BITLEN_2GAMMA1_MINUS_ONE * 32);
    assert_eq!(
        BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE,
        bitlen_u32(((Q8380417::Q - 1)/(2 * GAMMA2 as i32)) as u32 - 1)
    );
    assert_eq!(
        K_TIMES_32_TIMES_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE,
        K * 32 * (bitlen_u32(((Q8380417::Q - 1)/(2 * GAMMA2 as i32)) as u32 - 1))
    );
    assert_eq!(
        SK_BYTES,
        128 + 32 * ((L + K) * BITLEN_2ETA + D * K)
    );
    assert_eq!(
        SIG_BYTES,
        LAMBDA_OVER_4 + L * 32 * (1 + bitlen_u32(GAMMA1 as u32 - 1)) + OMEGA + K
    );

    assert!(D > 0);
    assert!(D < 31);
    assert!(GAMMA1 > BETA);
    assert!(GAMMA2 > BETA);
    assert_eq!((Q8380417::Q - 1) % (2 * GAMMA2 as i32), 0);

    let dec_sk = sk_decode::<K, L, D, ETA, BITLEN_2ETA, SK_BYTES>(sk)?;

    let mut s1_hat = dec_sk.s1;
    let mut s2_hat = dec_sk.s2;
    let mut t0_hat = dec_sk.t0;

    s1_hat.ntt();
    s2_hat.ntt();
    t0_hat.ntt();

    let a_hat = expand_a::<K, L>(&dec_sk.rho);

    let mut state1 = h_init();
    h_absorb(&mut state1, &dec_sk.tr);
    h_absorb(&mut state1, formatted_message);
    let mut reader1 = h_finalize(state1);

    let mut mu= [0u8; 64];
    h_squeeze(&mut reader1, &mut mu);

    let mut state2 = h_init();
    h_absorb(&mut state2, &dec_sk.seed_k);
    h_absorb(&mut state2, randomness);
    h_absorb(&mut state2, &mu);
    let mut reader2 = h_finalize(state2);

    let mut rho_double_prime = [0u8; 64];
    h_squeeze(&mut reader2, &mut rho_double_prime);

    let mut kappa = 0usize;

    loop {
        let last_nonce = kappa
            .checked_add(L.saturating_sub(1))
            .ok_or(MlDsaError::Core(PqcCoreError::RejectionSamplingFailed))?;

        if last_nonce > u16::MAX as usize {
            return Err(MlDsaError::Core(PqcCoreError::RejectionSamplingFailed));
        }

        let y = expand_mask::<
            L, GAMMA1, BITLEN_2GAMMA1_MINUS_ONE, BITLEN_2GAMMA1_MINUS_ONE_TIMES_32
        >(&rho_double_prime, kappa);

        let mut y_hat = y;
        y_hat.ntt();

        let mut w = a_hat.mul_vec_ntt(&y_hat);
        w.inv_ntt();

        let w1 = high_bits_vec::<K, GAMMA2>(&w);

        let mut w1_encoded = [0u8; K_TIMES_32_TIMES_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE];

        w1_encode::<
            K, GAMMA2, BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE
        >(&w1, &mut w1_encoded);

        let mut c_tilde = [0u8; LAMBDA_OVER_4];

        let mut state3 = h_init();
        h_absorb(&mut state3, &mu);
        h_absorb(&mut state3, &w1_encoded);

        let mut reader3 = h_finalize(state3);
        h_squeeze(&mut reader3, &mut c_tilde);

        let mut c_hat = sample_in_ball::<LAMBDA_OVER_4, TAU>(&c_tilde);
        c_hat.ntt();

        let mut cs1 = s1_hat.mul_by_poly_ntt(&c_hat);
        cs1.inv_ntt();

        let mut cs2 = s2_hat.mul_by_poly_ntt(&c_hat);
        cs2.inv_ntt();

        let z = y.add(&cs1);
        let w_minus_cs2 = w.sub(&cs2);
        let r0 = low_bits_vec::<K, GAMMA2>(&w_minus_cs2);

        let z_small = norm_polyvec_zq(z) < (GAMMA1 - BETA) as u32;
        let r0_small = norm_polyvec_zq(r0) < (GAMMA2 - BETA) as u32;

        if z_small && r0_small {
            let mut ct0 = t0_hat.mul_by_poly_ntt(&c_hat);
            ct0.inv_ntt();

            let minus_ct0 = PolyVec::<Q8380417, K>::zero().sub(&ct0);
            let w_minus_cs2 = w.sub(&cs2);
            let rhs_make_hint = w_minus_cs2.add(&ct0);

            let (hint, h_weight) = make_hint_vec::<K, GAMMA2>(&minus_ct0, &rhs_make_hint);

            let ct0_small = norm_polyvec_zq(ct0) < GAMMA2 as u32;
            if ct0_small && h_weight <= OMEGA {
                let dec_sig = DecodedSignature::<K, L, LAMBDA_OVER_4>{
                    c_tilde,
                    z: mod_pm_q_polyvec(z),
                    hint
                };

                return Ok(sig_encode::<
                    K, L, LAMBDA_OVER_4, GAMMA1, BITLEN_2GAMMA1_MINUS_ONE, OMEGA, SIG_BYTES
                >(&dec_sig));

            }
        }

        kappa = kappa
            .checked_add(L)
            .ok_or(MlDsaError::Core(PqcCoreError::RejectionSamplingFailed))?;

    }
}


pub(crate) fn ml_dsa_verify_internal<
    const K: usize,
    const L: usize,
    const D: usize,
    const TAU: usize,
    const LAMBDA_OVER_4: usize,
    const GAMMA1: usize,
    const BITLEN_2GAMMA1_MINUS_ONE: usize,
    const BITLEN_2GAMMA1_MINUS_ONE_TIMES_32: usize,
    const GAMMA2: usize,
    const BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE: usize,
    const K_TIMES_32_TIMES_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE: usize,
    const ETA: usize,
    const BITLEN_2ETA: usize,
    const BETA: usize,
    const OMEGA: usize,
    const PK_BYTES: usize,
    const SIG_BYTES: usize
> (
    pk: &PublicKey<PK_BYTES>,
    formatted_message: &[u8],
    signature: &Signature<SIG_BYTES>
) -> Result<bool, MlDsaError> {
    assert_eq!(BITLEN_2ETA, bitlen_u32(2 * ETA as u32));
    assert_eq!(BITLEN_2GAMMA1_MINUS_ONE, bitlen_u32(2 * GAMMA1 as u32 - 1));
    assert_eq!(BITLEN_2GAMMA1_MINUS_ONE_TIMES_32, BITLEN_2GAMMA1_MINUS_ONE * 32);
    assert_eq!(
        BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE,
        bitlen_u32(((Q8380417::Q - 1) / (2 * GAMMA2 as i32)) as u32 - 1)
    );
    assert_eq!(
        K_TIMES_32_TIMES_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE,
        K * 32 * (bitlen_u32(((Q8380417::Q - 1)/(2 * GAMMA2 as i32)) as u32 - 1))
    );
    assert_eq!(
        PK_BYTES,
        32 + 32 * K * (bitlen_u32(Q8380417::Q as u32 - 1) - D)
    );
    assert_eq!(
        SIG_BYTES,
        LAMBDA_OVER_4 + L * BITLEN_2GAMMA1_MINUS_ONE_TIMES_32 + OMEGA + K
    );

    assert!(D > 0);
    assert!(D < 31);
    assert!(GAMMA1 > BETA);
    assert!(GAMMA2 > BETA);
    assert_eq!((Q8380417::Q - 1) % (2 * GAMMA2 as i32), 0);

    let dec_pk= pk_decode::<K, PK_BYTES>(pk)?;
    let dec_sig = sig_decode::<
        K, L, LAMBDA_OVER_4, GAMMA1, BITLEN_2GAMMA1_MINUS_ONE, OMEGA, SIG_BYTES
    >(signature)?;

    let t1 = dec_pk.t1;
    let z = dec_sig.z;

    let norm_z_small = norm_polyvec_zq(z) < (GAMMA1 - BETA) as u32;

    let a_hat = expand_a::<K, L>(&dec_pk.rho);


    let mut tr = [0u8; 64];
    h(pk.as_bytes(), &mut tr);

    let mut state1 = h_init();
    h_absorb(&mut state1, &tr);
    h_absorb(&mut state1, formatted_message);
    let mut reader1 = h_finalize(state1);

    let mut mu= [0u8; 64];
    h_squeeze(&mut reader1, &mut mu);


    let mut c = sample_in_ball::<LAMBDA_OVER_4, TAU>(&dec_sig.c_tilde);

    let two_d = 1 << D;
    let mut t1_times_2d = t1.mul_by_constant(&two_d);
    t1_times_2d.ntt();

    c.ntt();
    let c_times_t1_times_2d = t1_times_2d.mul_by_poly_ntt(&c);

    let mut z_hat = z;
    z_hat.ntt();
    let a_hat_times_z_hat = a_hat.mul_vec_ntt(&z_hat);

    let mut w_bis_approx = a_hat_times_z_hat.sub(&c_times_t1_times_2d);
    w_bis_approx.inv_ntt();

    let w1_bis = use_hint_vec::<K, GAMMA2>(&dec_sig.hint, &w_bis_approx);

    let mut w1_encoded = [0u8; K_TIMES_32_TIMES_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE];
    w1_encode::<
        K, GAMMA2, BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE
    >(&w1_bis, &mut w1_encoded);

    let mut state2 = h_init();
    h_absorb(&mut state2, &mu);
    h_absorb(&mut state2, &w1_encoded);
    let mut reader2 = h_finalize(state2);

    let mut c_tilde_bis= [0u8; LAMBDA_OVER_4];
    h_squeeze(&mut reader2, &mut c_tilde_bis);


    let commitments_match = dec_sig.c_tilde == c_tilde_bis;
    Ok(norm_z_small && commitments_match)
}