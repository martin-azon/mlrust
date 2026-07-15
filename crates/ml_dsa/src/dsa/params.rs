use crate::constants::{
    MlDsa44,
    ML_DSA_44_K,
    ML_DSA_44_L,
    ML_DSA_44_ETA,
    ML_DSA_44_BITLEN_2ETA,
    ML_DSA_44_GAMMA1,
    ML_DSA_44_BITLEN_2GAMMA1_MINUS_ONE,
    ML_DSA_44_BITLEN_2GAMMA1_MINUS_ONE_TIMES_32,
    ML_DSA_44_TAU,
    ML_DSA_44_BETA,
    ML_DSA_44_GAMMA2,
    ML_DSA_44_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE,
    ML_DSA_44_K_TIMES_32_TIMES_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE,
    ML_DSA_44_LAMBDA_OVER_4,
    ML_DSA_44_D,
    ML_DSA_44_OMEGA,
    ML_DSA_44_PUBLIC_KEY_BYTES,
    ML_DSA_44_SECRET_KEY_BYTES,
    ML_DSA_44_SIGNATURE_BYTES,
    MlDsa65,
    ML_DSA_65_K,
    ML_DSA_65_L,
    ML_DSA_65_ETA,
    ML_DSA_65_BITLEN_2ETA,
    ML_DSA_65_GAMMA1,
    ML_DSA_65_BITLEN_2GAMMA1_MINUS_ONE,
    ML_DSA_65_BITLEN_2GAMMA1_MINUS_ONE_TIMES_32,
    ML_DSA_65_TAU,
    ML_DSA_65_BETA,
    ML_DSA_65_GAMMA2,
    ML_DSA_65_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE,
    ML_DSA_65_K_TIMES_32_TIMES_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE,
    ML_DSA_65_LAMBDA_OVER_4,
    ML_DSA_65_D,
    ML_DSA_65_OMEGA,
    ML_DSA_65_PUBLIC_KEY_BYTES,
    ML_DSA_65_SECRET_KEY_BYTES,
    ML_DSA_65_SIGNATURE_BYTES,
    MlDsa87,
    ML_DSA_87_K,
    ML_DSA_87_L,
    ML_DSA_87_ETA,
    ML_DSA_87_BITLEN_2ETA,
    ML_DSA_87_GAMMA1,
    ML_DSA_87_BITLEN_2GAMMA1_MINUS_ONE,
    ML_DSA_87_BITLEN_2GAMMA1_MINUS_ONE_TIMES_32,
    ML_DSA_87_TAU,
    ML_DSA_87_BETA,
    ML_DSA_87_GAMMA2,
    ML_DSA_87_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE,
    ML_DSA_87_K_TIMES_32_TIMES_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE,
    ML_DSA_87_LAMBDA_OVER_4,
    ML_DSA_87_D,
    ML_DSA_87_OMEGA,
    ML_DSA_87_PUBLIC_KEY_BYTES,
    ML_DSA_87_SECRET_KEY_BYTES,
    ML_DSA_87_SIGNATURE_BYTES,
};

use crate::keys::{
    MlDsa44Keypair,
    MlDsa44PublicKey,
    MlDsa44SecretKey,
    MlDsa44Signature,
    MlDsa65Keypair,
    MlDsa65PublicKey,
    MlDsa65SecretKey,
    MlDsa65Signature,
    MlDsa87Keypair,
    MlDsa87PublicKey,
    MlDsa87SecretKey,
    MlDsa87Signature,
};

use crate::dsa::internal::{ml_dsa_keygen_internal, ml_dsa_sign_internal, ml_dsa_verify_internal};
use crate::error::MlDsaError;



pub trait MlDsaParams: Sized {
    /// Dimension `k`.
    const K: usize;

    /// Dimension `l`.
    const L: usize;
    
    /// Number of dropped bits from t.
    const D: usize;

    /// Number of 1's in the polynomial c.
    const TAU: usize;

    /// Collision strength of c_tilde.
    const LAMBDA_OVER_4: usize;

    /// Noise parameter used for secret-vector sampling.
    const GAMMA1: usize;

    /// Numerical value bit_length(2 * GAMMA1 - 1).
    const BITLEN_2GAMMA1_MINUS_ONE: usize;

    /// Numerical value 32 * (bit_length(2 * GAMMA1 - 1)).
    const BITLEN_2GAMMA1_MINUS_ONE_TIMES_32: usize;

    /// HighBits / LowBits parameter.
    const GAMMA2: usize;
    
    /// Numerical value bit_length(2 * GAMMA1) - 1.
    const BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE: usize;

    /// Numerical value 32 * K * bit_length((Q - 1) / (2 * GAMMA2) - 1).
    const K_TIMES_32_TIMES_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE: usize;
    
    /// Noise parameter used for secret-vector sampling.
    const ETA: usize;

    /// Bit length of the noise parameter ETA.
    const BITLEN_2ETA: usize;

    /// Beta = tau * eta.
    const BETA: usize;
    
    /// Max of 1's in hint vector.
    const OMEGA: usize;



    /// Serialized secret key length in bytes.
    const SK_BYTES: usize;

    /// Serialized public key length in bytes.
    const PK_BYTES: usize;

    /// Serialized signature length in bytes.
    const SIG_BYTES: usize;



    /// Secret key type for this parameter set.
    type SecretKey;

    /// Public key type for this parameter set.
    type PublicKey;

    /// Signature type for this parameter set.
    type Signature;

    /// Keypair type for this parameter set.
    type KeyPair;



    /// Deterministically generates a keypair from the 32-byte ML-DSA
    /// key-generation seed.
    fn keygen_from_seed(xi: &[u8; 32]) -> Self::KeyPair;

    /// Deterministically signs a formatted message using a
    /// 32-byte randomness seed.
    fn sign_from_seed(
        sk: &Self::SecretKey,
        formatted_message: &[u8],
        randomness: &[u8; 32]
    ) -> Result<Self::Signature, MlDsaError>;

    /// Verifies that the signature is correct.
    fn verify(
        pk: &Self::PublicKey,
        formatted_message: &[u8],
        signature: &Self::Signature
    ) -> Result<bool, MlDsaError>;
}



impl MlDsaParams for MlDsa44 {
    const K: usize = ML_DSA_44_K;
    const L: usize = ML_DSA_44_L;
    const D: usize = ML_DSA_44_D;
    const TAU: usize = ML_DSA_44_TAU;
    const LAMBDA_OVER_4: usize = ML_DSA_44_LAMBDA_OVER_4;
    const GAMMA1: usize = ML_DSA_44_GAMMA1;
    const BITLEN_2GAMMA1_MINUS_ONE: usize = ML_DSA_44_BITLEN_2GAMMA1_MINUS_ONE;
    const BITLEN_2GAMMA1_MINUS_ONE_TIMES_32: usize = ML_DSA_44_BITLEN_2GAMMA1_MINUS_ONE_TIMES_32;
    const GAMMA2: usize = ML_DSA_44_GAMMA2;
    const BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE: usize = ML_DSA_44_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE;
    const K_TIMES_32_TIMES_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE: usize = ML_DSA_44_K_TIMES_32_TIMES_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE;
    const ETA: usize = ML_DSA_44_ETA;
    const BITLEN_2ETA: usize = ML_DSA_44_BITLEN_2ETA;
    const BETA: usize = ML_DSA_44_BETA;
    const OMEGA: usize = ML_DSA_44_OMEGA;


    const SK_BYTES: usize = ML_DSA_44_SECRET_KEY_BYTES;
    const PK_BYTES: usize = ML_DSA_44_PUBLIC_KEY_BYTES;
    const SIG_BYTES: usize = ML_DSA_44_SIGNATURE_BYTES;

    type SecretKey = MlDsa44SecretKey;
    type PublicKey = MlDsa44PublicKey;
    type Signature = MlDsa44Signature;
    type KeyPair = MlDsa44Keypair;

    fn keygen_from_seed(xi: &[u8; 32]) -> Self::KeyPair {
        ml_dsa_keygen_internal::<
            ML_DSA_44_K,
            ML_DSA_44_L,
            ML_DSA_44_D,
            ML_DSA_44_ETA,
            ML_DSA_44_BITLEN_2ETA,
            ML_DSA_44_SECRET_KEY_BYTES,
            ML_DSA_44_PUBLIC_KEY_BYTES,
        >(xi)
    }

    fn sign_from_seed(
        sk: &Self::SecretKey, formatted_message: &[u8], randomness: &[u8; 32]
    ) -> Result<Self::Signature, MlDsaError> {
        ml_dsa_sign_internal::<
            ML_DSA_44_K,
            ML_DSA_44_L,
            ML_DSA_44_D,
            ML_DSA_44_TAU,
            ML_DSA_44_LAMBDA_OVER_4,
            ML_DSA_44_GAMMA1,
            ML_DSA_44_BITLEN_2GAMMA1_MINUS_ONE,
            ML_DSA_44_BITLEN_2GAMMA1_MINUS_ONE_TIMES_32,
            ML_DSA_44_GAMMA2,
            ML_DSA_44_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE,
            ML_DSA_44_K_TIMES_32_TIMES_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE,
            ML_DSA_44_ETA,
            ML_DSA_44_BITLEN_2ETA,
            ML_DSA_44_BETA,
            ML_DSA_44_OMEGA,
            ML_DSA_44_SECRET_KEY_BYTES,
            ML_DSA_44_SIGNATURE_BYTES,
        >(sk, formatted_message, randomness)
    }

    fn verify(
        pk: &Self::PublicKey, formatted_message: &[u8], signature: &Self::Signature
    ) -> Result<bool, MlDsaError> {
        ml_dsa_verify_internal::<
            ML_DSA_44_K,
            ML_DSA_44_L,
            ML_DSA_44_D,
            ML_DSA_44_TAU,
            ML_DSA_44_LAMBDA_OVER_4,
            ML_DSA_44_GAMMA1,
            ML_DSA_44_BITLEN_2GAMMA1_MINUS_ONE,
            ML_DSA_44_BITLEN_2GAMMA1_MINUS_ONE_TIMES_32,
            ML_DSA_44_GAMMA2,
            ML_DSA_44_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE,
            ML_DSA_44_K_TIMES_32_TIMES_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE,
            ML_DSA_44_ETA,
            ML_DSA_44_BITLEN_2ETA,
            ML_DSA_44_BETA,
            ML_DSA_44_OMEGA,
            ML_DSA_44_PUBLIC_KEY_BYTES,
            ML_DSA_44_SIGNATURE_BYTES,
        >(pk, formatted_message, signature)
    }
}




impl MlDsaParams for MlDsa65 {
    const K: usize = ML_DSA_65_K;
    const L: usize = ML_DSA_65_L;
    const D: usize = ML_DSA_65_D;
    const TAU: usize = ML_DSA_65_TAU;
    const LAMBDA_OVER_4: usize = ML_DSA_65_LAMBDA_OVER_4;
    const GAMMA1: usize = ML_DSA_65_GAMMA1;
    const BITLEN_2GAMMA1_MINUS_ONE: usize = ML_DSA_65_BITLEN_2GAMMA1_MINUS_ONE;
    const BITLEN_2GAMMA1_MINUS_ONE_TIMES_32: usize = ML_DSA_65_BITLEN_2GAMMA1_MINUS_ONE_TIMES_32;
    const GAMMA2: usize = ML_DSA_65_GAMMA2;
    const BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE: usize = ML_DSA_65_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE;
    const K_TIMES_32_TIMES_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE: usize = ML_DSA_65_K_TIMES_32_TIMES_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE;
    const ETA: usize = ML_DSA_65_ETA;
    const BITLEN_2ETA: usize = ML_DSA_65_BITLEN_2ETA;
    const BETA: usize = ML_DSA_65_BETA;
    const OMEGA: usize = ML_DSA_65_OMEGA;


    const SK_BYTES: usize = ML_DSA_65_SECRET_KEY_BYTES;
    const PK_BYTES: usize = ML_DSA_65_PUBLIC_KEY_BYTES;
    const SIG_BYTES: usize = ML_DSA_65_SIGNATURE_BYTES;

    type SecretKey = MlDsa65SecretKey;
    type PublicKey = MlDsa65PublicKey;
    type Signature = MlDsa65Signature;
    type KeyPair = MlDsa65Keypair;

    fn keygen_from_seed(xi: &[u8; 32]) -> Self::KeyPair {
        ml_dsa_keygen_internal::<
            ML_DSA_65_K,
            ML_DSA_65_L,
            ML_DSA_65_D,
            ML_DSA_65_ETA,
            ML_DSA_65_BITLEN_2ETA,
            ML_DSA_65_SECRET_KEY_BYTES,
            ML_DSA_65_PUBLIC_KEY_BYTES,
        >(xi)
    }

    fn sign_from_seed(
        sk: &Self::SecretKey, formatted_message: &[u8], randomness: &[u8; 32]
    ) -> Result<Self::Signature, MlDsaError> {
        ml_dsa_sign_internal::<
            ML_DSA_65_K,
            ML_DSA_65_L,
            ML_DSA_65_D,
            ML_DSA_65_TAU,
            ML_DSA_65_LAMBDA_OVER_4,
            ML_DSA_65_GAMMA1,
            ML_DSA_65_BITLEN_2GAMMA1_MINUS_ONE,
            ML_DSA_65_BITLEN_2GAMMA1_MINUS_ONE_TIMES_32,
            ML_DSA_65_GAMMA2,
            ML_DSA_65_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE,
            ML_DSA_65_K_TIMES_32_TIMES_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE,
            ML_DSA_65_ETA,
            ML_DSA_65_BITLEN_2ETA,
            ML_DSA_65_BETA,
            ML_DSA_65_OMEGA,
            ML_DSA_65_SECRET_KEY_BYTES,
            ML_DSA_65_SIGNATURE_BYTES,
        >(sk, formatted_message, randomness)
    }

    fn verify(
        pk: &Self::PublicKey, formatted_message: &[u8], signature: &Self::Signature
    ) -> Result<bool, MlDsaError> {
        ml_dsa_verify_internal::<
            ML_DSA_65_K,
            ML_DSA_65_L,
            ML_DSA_65_D,
            ML_DSA_65_TAU,
            ML_DSA_65_LAMBDA_OVER_4,
            ML_DSA_65_GAMMA1,
            ML_DSA_65_BITLEN_2GAMMA1_MINUS_ONE,
            ML_DSA_65_BITLEN_2GAMMA1_MINUS_ONE_TIMES_32,
            ML_DSA_65_GAMMA2,
            ML_DSA_65_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE,
            ML_DSA_65_K_TIMES_32_TIMES_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE,
            ML_DSA_65_ETA,
            ML_DSA_65_BITLEN_2ETA,
            ML_DSA_65_BETA,
            ML_DSA_65_OMEGA,
            ML_DSA_65_PUBLIC_KEY_BYTES,
            ML_DSA_65_SIGNATURE_BYTES,
        >(pk, formatted_message, signature)
    }
}




impl MlDsaParams for MlDsa87 {
    const K: usize = ML_DSA_87_K;
    const L: usize = ML_DSA_87_L;
    const D: usize = ML_DSA_87_D;
    const TAU: usize = ML_DSA_87_TAU;
    const LAMBDA_OVER_4: usize = ML_DSA_87_LAMBDA_OVER_4;
    const GAMMA1: usize = ML_DSA_87_GAMMA1;
    const BITLEN_2GAMMA1_MINUS_ONE: usize = ML_DSA_87_BITLEN_2GAMMA1_MINUS_ONE;
    const BITLEN_2GAMMA1_MINUS_ONE_TIMES_32: usize = ML_DSA_87_BITLEN_2GAMMA1_MINUS_ONE_TIMES_32;
    const GAMMA2: usize = ML_DSA_87_GAMMA2;
    const BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE: usize = ML_DSA_87_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE;
    const K_TIMES_32_TIMES_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE: usize = ML_DSA_87_K_TIMES_32_TIMES_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE;
    const ETA: usize = ML_DSA_87_ETA;
    const BITLEN_2ETA: usize = ML_DSA_87_BITLEN_2ETA;
    const BETA: usize = ML_DSA_87_BETA;
    const OMEGA: usize = ML_DSA_87_OMEGA;


    const SK_BYTES: usize = ML_DSA_87_SECRET_KEY_BYTES;
    const PK_BYTES: usize = ML_DSA_87_PUBLIC_KEY_BYTES;
    const SIG_BYTES: usize = ML_DSA_87_SIGNATURE_BYTES;

    type SecretKey = MlDsa87SecretKey;
    type PublicKey = MlDsa87PublicKey;
    type Signature = MlDsa87Signature;
    type KeyPair = MlDsa87Keypair;

    fn keygen_from_seed(xi: &[u8; 32]) -> Self::KeyPair {
        ml_dsa_keygen_internal::<
            ML_DSA_87_K,
            ML_DSA_87_L,
            ML_DSA_87_D,
            ML_DSA_87_ETA,
            ML_DSA_87_BITLEN_2ETA,
            ML_DSA_87_SECRET_KEY_BYTES,
            ML_DSA_87_PUBLIC_KEY_BYTES,
        >(xi)
    }

    fn sign_from_seed(
        sk: &Self::SecretKey, formatted_message: &[u8], randomness: &[u8; 32]
    ) -> Result<Self::Signature, MlDsaError> {
        ml_dsa_sign_internal::<
            ML_DSA_87_K,
            ML_DSA_87_L,
            ML_DSA_87_D,
            ML_DSA_87_TAU,
            ML_DSA_87_LAMBDA_OVER_4,
            ML_DSA_87_GAMMA1,
            ML_DSA_87_BITLEN_2GAMMA1_MINUS_ONE,
            ML_DSA_87_BITLEN_2GAMMA1_MINUS_ONE_TIMES_32,
            ML_DSA_87_GAMMA2,
            ML_DSA_87_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE,
            ML_DSA_87_K_TIMES_32_TIMES_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE,
            ML_DSA_87_ETA,
            ML_DSA_87_BITLEN_2ETA,
            ML_DSA_87_BETA,
            ML_DSA_87_OMEGA,
            ML_DSA_87_SECRET_KEY_BYTES,
            ML_DSA_87_SIGNATURE_BYTES,
        >(sk, formatted_message, randomness)
    }

    fn verify(
        pk: &Self::PublicKey, formatted_message: &[u8], signature: &Self::Signature
    ) -> Result<bool, MlDsaError> {
        ml_dsa_verify_internal::<
            ML_DSA_87_K,
            ML_DSA_87_L,
            ML_DSA_87_D,
            ML_DSA_87_TAU,
            ML_DSA_87_LAMBDA_OVER_4,
            ML_DSA_87_GAMMA1,
            ML_DSA_87_BITLEN_2GAMMA1_MINUS_ONE,
            ML_DSA_87_BITLEN_2GAMMA1_MINUS_ONE_TIMES_32,
            ML_DSA_87_GAMMA2,
            ML_DSA_87_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE,
            ML_DSA_87_K_TIMES_32_TIMES_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE,
            ML_DSA_87_ETA,
            ML_DSA_87_BITLEN_2ETA,
            ML_DSA_87_BETA,
            ML_DSA_87_OMEGA,
            ML_DSA_87_PUBLIC_KEY_BYTES,
            ML_DSA_87_SIGNATURE_BYTES,
        >(pk, formatted_message, signature)
    }
}