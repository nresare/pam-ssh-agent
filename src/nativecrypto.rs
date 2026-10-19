use EcdsaPublicKey::{NistP256, NistP384, NistP521};
use anyhow::{Result, anyhow};
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Public};
use openssl::rsa::Rsa;
use openssl::sha::sha256;
use openssl::sign::Verifier;
use ssh_key::public::{EcdsaPublicKey, KeyData};
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, Signature};

/// This trait mirrors signature::Verifier, but is separate and as such can be used
/// to direct the signature verification cryptographic to the openssl version by simply
/// conditionally import this trait instead of signature::Verifier
pub trait PublicKeyVerifier {
    fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), signature::Error>;
}

impl PublicKeyVerifier for KeyData {
    fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), signature::Error> {
        let validator = Validator::new(self, signature).map_err(signature::Error::from_source)?;
        validator
            .verify(message, signature)
            .map_err(signature::Error::from_source)
    }
}

struct Validator {
    key: PKey<Public>,
    scheme: Scheme,
}

enum Scheme {
    Ecdsa(MessageDigest),
    Ed25519,
    Rsa(MessageDigest),
    SkEcdsa { application: String },
    SkEd25519 { application: String },
}
impl Validator {
    pub fn new(key_data: &KeyData, signature: &Signature) -> Result<Validator> {
        match key_data {
            KeyData::Ecdsa(key) => {
                let (scheme, curve) = match key {
                    NistP256(_) => (
                        Scheme::Ecdsa(MessageDigest::sha256()),
                        Nid::X9_62_PRIME256V1,
                    ),
                    NistP384(_) => (Scheme::Ecdsa(MessageDigest::sha384()), Nid::SECP384R1),
                    NistP521(_) => (Scheme::Ecdsa(MessageDigest::sha512()), Nid::SECP521R1),
                };
                Ok(Validator {
                    key: ec_pkey_from_key_data(curve, key.as_sec1_bytes())?,
                    scheme,
                })
            }
            KeyData::Ed25519(public_key) => Ok(Validator {
                key: PKey::public_key_from_raw_bytes(&public_key.0, openssl::pkey::Id::ED25519)?,
                scheme: Scheme::Ed25519,
            }),
            KeyData::SkEcdsaSha2NistP256(pk) => Ok(Validator {
                key: ec_pkey_from_key_data(Nid::X9_62_PRIME256V1, pk.ec_point().as_bytes())?,
                scheme: Scheme::SkEcdsa {
                    application: pk.application().to_owned(),
                },
            }),
            KeyData::SkEd25519(public_key) => {
                let key = PKey::public_key_from_raw_bytes(
                    &public_key.public_key().0,
                    openssl::pkey::Id::ED25519,
                )?;
                let scheme = Scheme::SkEd25519 {
                    application: public_key.application().to_owned(),
                };
                Ok(Validator { key, scheme })
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
                        ));
                    }
                };
                let key = PKey::from_rsa(rsa)?;
                Ok(Validator {
                    key,
                    scheme: Scheme::Rsa(digest),
                })
            }
            _ => Err(anyhow!(
                "Key type is not supported: {:?}",
                key_data.algorithm()
            )),
        }
    }

    fn into_verifier(&self) -> Result<Verifier<'_>, signature::Error> {
        match &self.scheme {
            Scheme::Ecdsa(digest) | Scheme::Rsa(digest) => Verifier::new(*digest, &self.key),
            Scheme::SkEcdsa { .. } => Verifier::new(MessageDigest::sha256(), &self.key),
            Scheme::Ed25519 | Scheme::SkEd25519 { .. } => Verifier::new_without_digest(&self.key),
        }
        .map_err(signature::Error::from_source)
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), signature::Error> {
        match &self.scheme {
            Scheme::SkEcdsa { application } => self.handle_sk_signature(
                signature,
                message,
                Algorithm::Ecdsa {
                    curve: EcdsaCurve::NistP256,
                },
                application,
            ),
            Scheme::SkEd25519 { application } => {
                self.handle_sk_signature(signature, message, Algorithm::Ed25519, application)
            }
            _ => inner_verify(message, signature, self.into_verifier()?),
        }
    }
    fn handle_sk_signature(
        &self,
        signature: &Signature,
        message: &[u8],
        algorithm: Algorithm,
        application: &str,
    ) -> Result<(), signature::Error> {
        let bytes = signature.as_bytes();
        let split = bytes
            .len()
            .checked_sub(5)
            .ok_or_else(signature::Error::new)?;
        let (inner, flags_and_counter) = bytes.split_at(split);

        // ssh-key appends the flags and big-endian counter to as_bytes().
        // They belong in the signed message, not the underlying signature.
        let mut signed_data = Vec::with_capacity(69);
        signed_data.extend_from_slice(&sha256(application.as_bytes()));
        signed_data.extend_from_slice(flags_and_counter);
        signed_data.extend_from_slice(&sha256(message));
        let signature = Signature::new(algorithm, inner).map_err(signature::Error::from_source)?;
        inner_verify(&signed_data, &signature, self.into_verifier()?)
    }
}

fn ec_pkey_from_key_data(curve: Nid, bytes: &[u8]) -> Result<PKey<Public>> {
    let group = EcGroup::from_curve_name(curve)?;

    let mut ctx = openssl::bn::BigNumContext::new()?;
    let point = EcPoint::from_bytes(&group, bytes, &mut ctx)?;
    let ec_key = EcKey::from_public_key(&group, &point)?;
    ec_key.check_key()?;
    Ok(PKey::from_ec_key(ec_key)?)
}
macro_rules! to_der {
    ($ssh_signature:expr, $sig_type:ty) => {{
        let sig = <$sig_type>::try_from($ssh_signature)?;
        sig.to_der().to_bytes()
    }};
}

fn inner_verify(
    message: &[u8],
    signature: &Signature,
    mut verifier: Verifier,
) -> Result<(), signature::Error> {
    // OpenSSL performs the final hash for ECDSA/RSA. Ed25519 verifies the
    // prepared message directly, without an external digest.
    let signature = (match signature.algorithm() {
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
    })?;
    if verifier
        .verify_oneshot(&signature, message)
        .map_err(signature::Error::from_source)?
    {
        Ok(())
    } else {
        Err(signature::Error::new())
    }
}
