use crate::constants::{
    MlDsa44,
    MlDsa65,
    MlDsa87,
    ML_DSA_44_K,
    ML_DSA_44_L,
    ML_DSA_44_ETA,
    ML_DSA_44_GAMMA1,
    ML_DSA_44_TAU,
    ML_DSA_44_BETA,
    ML_DSA_44_GAMMA2,
    ML_DSA_44_LAMBDA_OVER_4,
    ML_DSA_44_D,
    ML_DSA_44_OMEGA,
    ML_DSA_44_PUBLIC_KEY_BYTES,
    ML_DSA_44_SECRET_KEY_BYTES,
    ML_DSA_44_SIGNATURE_BYTES,
    ML_DSA_65_K,
    ML_DSA_65_L,
    ML_DSA_65_ETA,
    ML_DSA_65_GAMMA1,
    ML_DSA_65_TAU,
    ML_DSA_65_BETA,
    ML_DSA_65_GAMMA2,
    ML_DSA_65_LAMBDA_OVER_4,
    ML_DSA_65_D,
    ML_DSA_65_OMEGA,
    ML_DSA_65_PUBLIC_KEY_BYTES,
    ML_DSA_65_SECRET_KEY_BYTES,
    ML_DSA_65_SIGNATURE_BYTES,
    ML_DSA_87_K,
    ML_DSA_87_L,
    ML_DSA_87_ETA,
    ML_DSA_87_GAMMA1,
    ML_DSA_87_TAU,
    ML_DSA_87_BETA,
    ML_DSA_87_GAMMA2,
    ML_DSA_87_LAMBDA_OVER_4,
    ML_DSA_87_D,
    ML_DSA_87_OMEGA,
    ML_DSA_87_PUBLIC_KEY_BYTES,
    ML_DSA_87_SECRET_KEY_BYTES,
    ML_DSA_87_SIGNATURE_BYTES,
};
use crate::dsa::internal::ml_dsa_keygen_internal;
use crate::error::MlDsaError;
use crate::keys::{MlDsa44Keypair, MlDsa44PublicKey, MlDsa44SecretKey, MlDsa44Signature, SecretKey, Signature};

pub trait MlDsaParams: Sized {
    /// Dimension `k`.
    const K: usize;

    /// Dimension `l`.
    const L: usize;

    /// Noise parameter used for secret-vector sampling.
    const ETA: usize;

    /// Noise parameter used for secret-vector sampling.
    const GAMMA1: i32;

    /// Number of 1's in the polynomial c.
    const TAU: usize;

    /// Beta = tau * eta.
    const BETA: usize;

    /// HighBits / LowBits parameter.
    const GAMMA2: i32;

    /// Collision strength of c_tilde.
    const LAMBDA_OVER_4: usize;

    /// Number of dropped bits from t.
    const D: usize;

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
    const ETA: usize = ML_DSA_44_ETA;
    const GAMMA1: i32 = ML_DSA_44_GAMMA1;
    const TAU: usize = ML_DSA_44_TAU;
    const BETA: usize = ML_DSA_44_BETA;
    const GAMMA2: i32 = ML_DSA_44_GAMMA2;
    const LAMBDA_OVER_4: usize = ML_DSA_44_LAMBDA_OVER_4;
    const D: usize = ML_DSA_44_D;
    const OMEGA: usize = ML_DSA_44_OMEGA;


    const SK_BYTES: usize = ML_DSA_44_SECRET_KEY_BYTES;
    const PK_BYTES: usize = ML_DSA_44_PUBLIC_KEY_BYTES;
    const SIG_BYTES: usize = ML_DSA_44_SIGNATURE_BYTES;

    type SecretKey = MlDsa44SecretKey;
    type PublicKey = MlDsa44PublicKey;
    type Signature = MlDsa44Signature;
    type KeyPair = MlDsa44Keypair;

    fn keygen_from_seed(xi: &[u8; 32]) -> Self::KeyPair {
        todo!()
    }

}