



//use crate::dsa::params::MlDsaParams;

use mlrust_core::encode::bits::{bitlen_u32, bytes_to_bits, int_to_bytes};
use mlrust_core::encode::ml_dsa::hint::HintVec;
use mlrust_core::params::{Q8380417, RingParams};
use mlrust_core::poly::PolyVec;
use mlrust_core::symmetric::ml_dsa::{h, h_init, h_absorb, h_finalize, h_squeeze};
use crate::encoding::{pk_encode, sig_encode, sk_decode, sk_encode, w1_encode, DecodedPublicKey, DecodedSecretKey, DecodedSignature};
use crate::error::MlDsaError;
use crate::keys::{MlDsaKeypair, PublicKey, SecretKey, Signature};
use crate::primitives::challenge::sample_in_ball;
use crate::primitives::norm::norm_polyvec_zq;
use crate::primitives::rounding::{high_bits_vec, low_bits_vec, make_hint_vec, mod_pm_q_polyvec, power2round_vec};
use crate::primitives::sampling::{expand_a, expand_mask, expand_s};

pub(crate) fn ml_dsa_keygen_internal<
    const K: usize,
    const L: usize,
    const D: usize,
    const ETA: usize,
    const BITLEN_2ETA: usize,
    const SK_BYTES: usize,
    const PK_BYTES: usize,
> (randomness_xi: &[u8; 32]) -> MlDsaKeypair<SK_BYTES, PK_BYTES> {
    assert_eq!(BITLEN_2ETA, bitlen_u32((2 * ETA) as u32));
    assert_eq!(PK_BYTES, 32 + 32 * K * (bitlen_u32((Q8380417::Q - 1) as u32) - D));
    assert_eq!(SK_BYTES, 128 + 32 * ((L + K) * BITLEN_2ETA) + D * K);


    let mut input_hash = [0u8; 34];

    input_hash[0..32].copy_from_slice(randomness_xi);
    int_to_bytes(K as u32, 1, &mut input_hash[32..33]);
    int_to_bytes(L as u32, 1, &mut input_hash[33..34]);

    let mut buffer = [0u8; 128];

    h(&input_hash, &mut buffer);

    let mut rho = [0u8; 32];
    let mut rho_bis = [0u8; 64];
    let mut seed_k = [0u8; 32];

    rho.copy_from_slice(&buffer[0..32]);
    rho_bis.copy_from_slice(&buffer[32..96]);
    seed_k.copy_from_slice(&buffer[96..]);

    let a_hat = expand_a::<K, L>(&rho);
    let (mut s1, mut s2) = expand_s::<K, L, ETA>(&rho_bis);

    s1.ntt();
    let mut t = a_hat.mul_vec_ntt(&s1);
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
    const BETA: usize,
    const ETA: usize,
    const BITLEN_2ETA: usize,
    const OMEGA: usize,
    const GAMMA1: usize,
    const BITLEN_2GAMMA1_MINUS_ONE: usize,
    const BITLEN_2GAMMA1_MINUS_ONE_TIMES_32: usize,
    const GAMMA2: usize,
    const BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE: usize,
    const K_TIMES_32_TIMES_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE: usize,
    const LAMBDA_OVER_4: usize,
    const TAU: usize,
    const SK_BYTES: usize,
    const SIG_BYTES: usize
> (
    sk: &SecretKey<SK_BYTES>,
    message: &[u8],
    randomness: &[u8; 32]
) -> Result<Signature<SIG_BYTES>, MlDsaError> {



    let dec_sk = sk_decode::<K, L, D, ETA, BITLEN_2ETA, SK_BYTES>(&sk)?;

    //let seed_k = dec_sk.seed_k;

    let mut s1 = dec_sk.s1;
    let mut s2 = dec_sk.s2;
    let mut t0 = dec_sk.t0;

    s1.ntt();
    s2.ntt();
    t0.ntt();

    let a_hat = expand_a::<K, L>(&dec_sk.rho);

    let mut tr_as_bits = [0u8; 512];
    bytes_to_bits(&dec_sk.tr, &mut tr_as_bits);

    let mut state1 = h_init();
    h_absorb(&mut state1, &tr_as_bits);
    h_absorb(&mut state1, message);
    let mut reader1 = h_finalize(state1);

    let mut mu= [0u8; 64];
    h_squeeze(&mut reader1, &mut mu);

    let mut state2 = h_init();
    h_absorb(&mut state2, &dec_sk.seed_k);
    h_absorb(&mut state2, randomness);
    h_absorb(&mut state2, &mu);
    let mut reader2 = h_finalize(state2);

    let mut rho_second = [0u8; 64];
    h_squeeze(&mut reader2, &mut rho_second);


    let mut kappa = 0usize;
    let mut sampling_failed = true;

    let mut c_tilde = [0u8; LAMBDA_OVER_4];
    let mut hint = HintVec::<K>::zero();
    let mut z = PolyVec::<Q8380417, L>::zero();

    while sampling_failed {
        let mut y = expand_mask::<
            L, GAMMA1, BITLEN_2GAMMA1_MINUS_ONE, BITLEN_2GAMMA1_MINUS_ONE_TIMES_32
        >(&rho_second, kappa);

        y.ntt();
        let mut w = a_hat.mul_vec_ntt(&y);
        w.inv_ntt();

        let w1 = high_bits_vec::<K, GAMMA2>(&w);

        let mut w1_encoded = [0u8; K_TIMES_32_TIMES_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE];
        w1_encode::<
            K, GAMMA2, BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE
        >(&w1, &mut w1_encoded);

        let mut state3 = h_init();
        h_absorb(&mut state3, &mu);
        h_absorb(&mut state3, &w1_encoded);
        let mut reader3 = h_finalize(state3);


        h_squeeze(&mut reader3, &mut c_tilde);

        let mut c = sample_in_ball::<LAMBDA_OVER_4, TAU>(&c_tilde);
        c.ntt();

        let mut cs1 = s1.dilatation_ntt(&c);
        cs1.inv_ntt();

        let mut cs2 = s2.dilatation_ntt(&c);
        cs2.inv_ntt();

        z = y.add(&cs1);

        let r0 = low_bits_vec::<K, GAMMA2>(&w.sub(&cs2));

        if norm_polyvec_zq(&z) < (GAMMA1 - BETA) as u32 && norm_polyvec_zq(&r0) < (GAMMA2 - BETA) as u32 {
            let mut ct0 = t0.dilatation_ntt(&c);
            ct0.inv_ntt();

            let minus_ct0 = PolyVec::<Q8380417, K>::zero().sub(&ct0);
            let w_minus_cs2 = w.sub(&cs2);
            let rhs_make_hint = w_minus_cs2.add(&ct0);

            let (h, h_weight) = make_hint_vec::<K, GAMMA2>(&minus_ct0, &rhs_make_hint);

            if norm_polyvec_zq(&ct0) < GAMMA2 as u32 && h_weight <= OMEGA {
                sampling_failed = false;
            }

            hint = h;
        }

        kappa += L;
    }


    let dec_sig = DecodedSignature::<K, L, LAMBDA_OVER_4>{
        c_tilde,
        z: mod_pm_q_polyvec(z),
        hint
    };
    Ok(sig_encode::<K, L, LAMBDA_OVER_4, GAMMA1, BITLEN_2GAMMA1_MINUS_ONE, OMEGA, SIG_BYTES>(&dec_sig))
}



pub(crate) fn ml_dsa_verify_internal<
    const K: usize,
    const L: usize,
    const D: usize,
    const ETA: usize,
    const BITLEN_2ETA: usize,
    const BITLEN_Q_MINUS_ONE: usize,
    const OMEGA: usize,
    const GAMMA1: usize,
    const BITLEN_2GAMMA1_MINUS_ONE: usize,
    const BITLEN_2GAMMA1_MINUS_ONE_TIMES_32: usize,
    const LAMBDA_OVER_4: usize,
    const TAU: usize,
    const PK_BYTES: usize,
    const SK_BYTES: usize,
    const SIG_BYTES: usize
> (
    pk: PublicKey<PK_BYTES>,
    message: &[u8],
    signature: Signature<SIG_BYTES>
) -> bool {
    todo!()
}