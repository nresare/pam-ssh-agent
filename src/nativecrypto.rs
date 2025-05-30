use anyhow::anyhow;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Public};
use openssl::rsa::Rsa;
use openssl::sign::Verifier;
use ssh_key::public::{EcdsaPublicKey, KeyData};
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, Signature};
use EcdsaPublicKey::{NistP256, NistP384, NistP521};

pub trait PublicKeyVerifier {
    fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), signature::Error>;
}

impl PublicKeyVerifier for KeyData {
    fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), signature::Error> {
        let (key, digest) =
            get_key_and_digest(self, signature).map_err(signature::Error::from_source)?;
        let mut verifier = digest
            .map_or_else(
                || Verifier::new_without_digest(&key),
                |digest| Verifier::new(digest, &key),
            )
            .map_err(signature::Error::from_source)?;
        match verifier
            .verify_oneshot(&convert_signature(signature)?, message)
            .map_err(signature::Error::from_source)?
        {
            true => Ok(()),
            false => Err(signature::Error::new()),
        }
    }
}

/// Create an OpenSSL PKey from &KeyData, in the case of RSA, use the hash algorithm information
/// in the RSA signature
fn get_key_and_digest(
    key_data: &KeyData,
    signature: &Signature,
) -> anyhow::Result<(PKey<Public>, Option<MessageDigest>)> {
    match key_data {
        KeyData::Ecdsa(public_key) => {
            let (group, digest) = match public_key {
                NistP256(_) => (Nid::X9_62_PRIME256V1, Some(MessageDigest::sha256())),
                NistP384(_) => (Nid::SECP384R1, Some(MessageDigest::sha384())),
                NistP521(_) => (Nid::SECP521R1, Some(MessageDigest::sha512())),
            };
            let group = EcGroup::from_curve_name(group)?;
            let bytes = public_key.as_sec1_bytes();

            let mut ctx = openssl::bn::BigNumContext::new()?;
            let point = EcPoint::from_bytes(&group, bytes, &mut ctx)?;
            let ec_key = EcKey::from_public_key(&group, &point)?;
            ec_key.check_key()?;
            Ok((PKey::from_ec_key(ec_key)?, digest))
        }
        KeyData::Ed25519(public_key) => {
            let key = PKey::public_key_from_raw_bytes(&public_key.0, openssl::pkey::Id::ED25519)?;
            Ok((key, None))
        }
        KeyData::Rsa(public_key) => {
            let e = BigNum::from_slice(public_key.e.as_bytes())?;
            let n = BigNum::from_slice(public_key.n.as_bytes())?;
            let rsa = Rsa::from_public_components(n, e)?;
            let digest = match signature.algorithm() {
                Algorithm::Rsa { hash } => match hash {
                    None => return Err(anyhow::anyhow!("No RSA hash algorithm specified")),
                    Some(HashAlg::Sha256) => MessageDigest::sha256(),
                    Some(HashAlg::Sha512) => MessageDigest::sha512(),
                    _ => return Err(anyhow::anyhow!("Unsupported RSA hash algorithm")),
                },
                _ => {
                    return Err(anyhow::anyhow!(
                        "Trying to read a non-RSA signature with an RSA key: {:?}",
                        signature.algorithm()
                    ))
                }
            };
            Ok((PKey::from_rsa(rsa)?, Some(digest)))
        }
        _ => Err(anyhow!(
            "Key type is not supported: {:?}",
            key_data.algorithm()
        )),
    }
}

macro_rules! to_der {
    ($ssh_signature:expr, $sig_type:ty) => {{
        let sig = <$sig_type>::try_from($ssh_signature)?;
        sig.to_der().to_bytes()
    }};
}

fn convert_signature(signature: &Signature) -> Result<Vec<u8>, signature::Error> {
    match signature.algorithm() {
        Algorithm::Ecdsa { curve } => {
            let bytes = match curve {
                EcdsaCurve::NistP256 => to_der!(signature, p256::ecdsa::Signature),
                EcdsaCurve::NistP384 => to_der!(signature, p384::ecdsa::Signature),
                EcdsaCurve::NistP521 => to_der!(signature, p521::ecdsa::Signature),
            };
            Ok(bytes.to_vec())
        }
        Algorithm::Ed25519 => Ok(signature.as_bytes().to_vec()),
        Algorithm::Rsa { .. } => Ok(signature.as_bytes().to_vec()),
        _ => Err(signature::Error::from_source(anyhow::anyhow!(
            "unsupported signature type"
        ))),
    }
}
