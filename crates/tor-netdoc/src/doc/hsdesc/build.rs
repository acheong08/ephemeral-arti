//! Hidden service descriptor encoding.

mod inner;
mod middle;
mod outer;

use crate::doc::hsdesc::{IntroAuthType, IntroPointDesc};
use crate::NetdocBuilder;
use rand::{CryptoRng, RngCore};
use tor_bytes::EncodeError;
use tor_cell::chancell::msg::HandshakeType;
use tor_cert::{CertEncodeError, CertType, CertifiedKey, Ed25519Cert, EncodedEd25519Cert};
use tor_error::into_bad_api_usage;
use tor_hscrypto::pk::{HsBlindIdKey, HsBlindIdKeypair, HsSvcDescEncKeypair};
use tor_hscrypto::{RevisionCounter, Subcredential};
use tor_llcrypto::pk::curve25519;
use tor_llcrypto::pk::ed25519;
use tor_units::IntegerMinutes;

use derive_builder::Builder;
use smallvec::SmallVec;

use std::borrow::{Borrow, Cow};
use std::time::SystemTime;

use self::inner::HsDescInner;
use self::middle::HsDescMiddle;
use self::outer::HsDescOuter;

use super::desc_enc::{HsDescEncNonce, HsDescEncryption, HS_DESC_ENC_NONCE_LEN};

/// An intermediary type for encoding hidden service descriptors.
///
/// This object is constructed via [`HsDescBuilder`], and then turned into a
/// signed document using [`HsDescBuilder::build_sign()`].
///
/// TODO: Add an example for using this API.
#[derive(Builder)]
#[builder(public, derive(Debug, Clone), pattern = "owned", build_fn(vis = ""))]
struct HsDesc<'a> {
    /// The blinded hidden service public key used for the first half of the "SECRET_DATA" field.
    ///
    /// (See rend-spec v3 2.5.1.1 and 2.5.2.1.)
    blinded_id: &'a HsBlindIdKey,
    /// The short-term descriptor signing key (KP_hs_desc_sign, KS_hs_desc_sign).
    hs_desc_sign: &'a ed25519::Keypair,
    /// The descriptor signing key certificate.
    ///
    /// This certificate can be created using [`create_desc_sign_key_cert`].
    hs_desc_sign_cert: EncodedEd25519Cert,
    /// A list of recognized CREATE handshakes that this onion service supports.
    create2_formats: &'a [HandshakeType],
    /// A list of authentication types that this onion service supports.
    auth_required: Option<SmallVec<[IntroAuthType; 2]>>,
    /// If true, this a "single onion service" and is not trying to keep its own location private.
    is_single_onion_service: bool,
    /// One or more introduction points used to contact the onion service.
    intro_points: &'a [IntroPointDesc],
    /// The expiration time of an introduction point authentication key certificate.
    intro_auth_key_cert_expiry: SystemTime,
    /// The expiration time of an introduction point encryption key certificate.
    intro_enc_key_cert_expiry: SystemTime,
    /// The list of clients authorized to access the hidden service.
    ///
    /// If `None`, client authentication is disabled.
    /// If `Some(&[])`, client authorization is enabled,
    /// but there will be no authorized clients.
    ///
    /// If client authorization is disabled, the resulting middle document will contain a single
    /// `auth-client` line populated with random values.
    ///
    /// Client authorization is disabled by default.
    #[builder(default)]
    auth_clients: Option<&'a [curve25519::PublicKey]>,
    /// The lifetime of this descriptor, in minutes.
    ///
    /// This doesn't actually list the starting time or the end time for the
    /// descriptor: presumably, because we didn't want to leak the onion
    /// service's view of the wallclock.
    lifetime: IntegerMinutes<u16>,
    /// A revision counter to tell whether this descriptor is more or less recent
    /// than another one for the same blinded ID.
    revision_counter: RevisionCounter,
    /// The "subcredential" of the onion service.
    subcredential: Subcredential,
}

/// Client authorization parameters.
#[derive(Debug)]
pub(super) struct ClientAuth<'a> {
    /// An ephemeral x25519 keypair generated by the hidden service (`KP_hss_desc_enc`).
    ///
    /// A new keypair MUST be generated every time a descriptor is encoded, or the descriptor
    /// encryption will not be secure.
    ephemeral_key: HsSvcDescEncKeypair,
    /// The list of authorized clients.
    auth_clients: &'a [curve25519::PublicKey],
    /// The `N_hs_desc_enc` descriptor_cookie key generated by the hidden service.
    ///
    /// A new descriptor cookie is randomly generated for each descriptor.
    descriptor_cookie: [u8; HS_DESC_ENC_NONCE_LEN],
}

impl<'a> ClientAuth<'a> {
    /// Create a new `ClientAuth` using the specified authorized clients.
    ///
    /// If `auth_clients` is empty list, there will be no authorized clients.
    ///
    /// This returns `None` if the list of `auth_clients` is `None`.
    fn new<R: RngCore + CryptoRng>(
        auth_clients: Option<&'a [curve25519::PublicKey]>,
        rng: &mut R,
    ) -> Option<ClientAuth<'a>> {
        let Some(auth_clients) = auth_clients else {
            // Client auth is disabled
            return None;
        };

        // Generate a new `N_hs_desc_enc` descriptor_cookie key for this descriptor.
        let descriptor_cookie = rand::Rng::gen::<[u8; HS_DESC_ENC_NONCE_LEN]>(rng);

        let secret = curve25519::StaticSecret::random_from_rng(rng);
        let ephemeral_key = HsSvcDescEncKeypair {
            public: curve25519::PublicKey::from(&secret).into(),
            secret: secret.into(),
        };

        Some(ClientAuth {
            ephemeral_key,
            auth_clients,
            descriptor_cookie,
        })
    }
}

impl<'a> NetdocBuilder for HsDescBuilder<'a> {
    fn build_sign<R: RngCore + CryptoRng>(self, rng: &mut R) -> Result<String, EncodeError> {
        /// The superencrypted field must be padded to the nearest multiple of 10k bytes
        ///
        /// rend-spec-v3 2.5.1.1
        const SUPERENCRYPTED_ALIGN: usize = 10 * (1 << 10);

        let hs_desc = self
            .build()
            .map_err(into_bad_api_usage!("the HsDesc could not be built"))?;

        let client_auth = ClientAuth::new(hs_desc.auth_clients, rng);

        // Construct the inner (second layer) plaintext. This is the unencrypted value of the
        // "encrypted" field.
        let inner_plaintext = HsDescInner {
            hs_desc_sign: hs_desc.hs_desc_sign,
            create2_formats: hs_desc.create2_formats,
            auth_required: hs_desc.auth_required.as_ref(),
            is_single_onion_service: hs_desc.is_single_onion_service,
            intro_points: hs_desc.intro_points,
            intro_auth_key_cert_expiry: hs_desc.intro_auth_key_cert_expiry,
            intro_enc_key_cert_expiry: hs_desc.intro_enc_key_cert_expiry,
        }
        .build_sign(rng)?;

        let desc_enc_nonce = client_auth
            .as_ref()
            .map(|client_auth| client_auth.descriptor_cookie.into());

        // Encrypt the inner document. The encrypted blob is the ciphertext contained in the
        // "encrypted" field described in section 2.5.1.2. of rend-spec-v3.
        let inner_encrypted = hs_desc.encrypt_field(
            rng,
            inner_plaintext.as_bytes(),
            desc_enc_nonce.as_ref(),
            b"hsdir-encrypted-data",
        );

        // Construct the middle (first player) plaintext. This is the unencrypted value of the
        // "superencrypted" field.
        let middle_plaintext = HsDescMiddle {
            client_auth: client_auth.as_ref(),
            subcredential: hs_desc.subcredential,
            encrypted: inner_encrypted,
        }
        .build_sign(rng)?;

        // Section 2.5.1.1. of rend-spec-v3: before encryption, pad the plaintext to the nearest
        // multiple of 10k bytes
        let middle_plaintext =
            pad_with_zero_to_align(middle_plaintext.as_bytes(), SUPERENCRYPTED_ALIGN);

        // Encrypt the middle document. The encrypted blob is the ciphertext contained in the
        // "superencrypted" field described in section 2.5.1.1. of rend-spec-v3.
        let middle_encrypted = hs_desc.encrypt_field(
            rng,
            middle_plaintext.borrow(),
            // desc_enc_nonce is absent when handling the superencryption layer (2.5.1.1).
            None,
            b"hsdir-superencrypted-data",
        );

        // Finally, build the hidden service descriptor.
        HsDescOuter {
            hs_desc_sign: hs_desc.hs_desc_sign,
            hs_desc_sign_cert: hs_desc.hs_desc_sign_cert,
            lifetime: hs_desc.lifetime,
            revision_counter: hs_desc.revision_counter,
            superencrypted: middle_encrypted,
        }
        .build_sign(rng)
    }
}

/// Create the descriptor signing key certificate.
///
/// Returns the encoded representation of the certificate
/// obtained by signing the descriptor signing key `hs_desc_sign`
/// with the blinded id key `blind_id`.
///
/// This certificate is meant to be passed to [`HsDescBuilder::hs_desc_sign_cert`].
pub fn create_desc_sign_key_cert(
    hs_desc_sign: &ed25519::PublicKey,
    blind_id: &HsBlindIdKeypair,
    expiry: SystemTime,
) -> Result<EncodedEd25519Cert, CertEncodeError> {
    // "The certificate cross-certifies the short-term descriptor signing key with the blinded
    // public key.  The certificate type must be [08], and the blinded public key must be
    // present as the signing-key extension."
    Ed25519Cert::constructor()
        .cert_type(CertType::HS_BLINDED_ID_V_SIGNING)
        .expiration(expiry)
        .signing_key(ed25519::Ed25519Identity::from(blind_id.as_ref().public()))
        .cert_key(CertifiedKey::Ed25519(hs_desc_sign.into()))
        .encode_and_sign(blind_id)
}

impl<'a> HsDesc<'a> {
    /// Encrypt the specified plaintext using the algorithm described in section
    /// `[HS-DESC-ENCRYPTION-KEYS]` of rend-spec-v3.txt.
    fn encrypt_field<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        plaintext: &[u8],
        desc_enc_nonce: Option<&HsDescEncNonce>,
        string_const: &[u8],
    ) -> Vec<u8> {
        let encrypt = HsDescEncryption {
            blinded_id: &ed25519::Ed25519Identity::from(self.blinded_id.as_ref()).into(),
            desc_enc_nonce,
            subcredential: &self.subcredential,
            revision: self.revision_counter,
            string_const,
        };

        encrypt.encrypt(rng, plaintext)
    }
}

/// Pad `v` with zeroes to the next multiple of `alignment`.
fn pad_with_zero_to_align(v: &[u8], alignment: usize) -> Cow<[u8]> {
    let padding = (alignment - (v.len() % alignment)) % alignment;

    if padding > 0 {
        let padded = v
            .iter()
            .copied()
            .chain(std::iter::repeat(0).take(padding))
            .collect::<Vec<_>>();

        Cow::Owned(padded)
    } else {
        // No need to pad.
        Cow::Borrowed(v)
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use std::net::Ipv4Addr;
    use std::time::Duration;

    use super::*;
    use crate::doc::hsdesc::{EncryptedHsDesc, HsDesc as ParsedHsDesc};
    use tor_basic_utils::test_rng::Config;
    use tor_checkable::{SelfSigned, Timebound};
    use tor_hscrypto::pk::{HsClientDescEncKeypair, HsIdKeypair};
    use tor_hscrypto::time::TimePeriod;
    use tor_linkspec::LinkSpec;
    use tor_llcrypto::pk::{curve25519, ed25519::ExpandedKeypair};

    // TODO: move the test helpers to a separate module and make them more broadly available if
    // necessary.

    /// Expect `err` to be a `Bug`, and return its string representation.
    ///
    /// # Panics
    ///
    /// Panics if `err` is not a `Bug`.
    pub(super) fn expect_bug(err: EncodeError) -> String {
        match err {
            EncodeError::Bug(b) => b.to_string(),
            EncodeError::BadLengthValue => panic!("expected Bug, got BadLengthValue"),
            _ => panic!("expected Bug, got unknown error"),
        }
    }

    pub(super) fn create_intro_point_descriptor<R: RngCore + CryptoRng>(
        rng: &mut R,
        link_specifiers: &[LinkSpec],
    ) -> IntroPointDesc {
        let link_specifiers = link_specifiers
            .iter()
            .map(|link_spec| link_spec.encode())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        IntroPointDesc {
            link_specifiers,
            ipt_ntor_key: create_curve25519_pk(rng),
            ipt_sid_key: ed25519::Keypair::generate(rng).verifying_key().into(),
            svc_ntor_key: create_curve25519_pk(rng).into(),
        }
    }

    /// Create a new curve25519 public key.
    pub(super) fn create_curve25519_pk<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> curve25519::PublicKey {
        let ephemeral_key = curve25519::EphemeralSecret::random_from_rng(rng);
        (&ephemeral_key).into()
    }

    /// Parse the specified hidden service descriptor.
    fn parse_hsdesc(
        unparsed_desc: &str,
        blinded_pk: ed25519::PublicKey,
        subcredential: &Subcredential,
        hsc_desc_enc: Option<&HsClientDescEncKeypair>,
    ) -> ParsedHsDesc {
        const TIMESTAMP: &str = "2023-01-23T15:00:00Z";

        let id = ed25519::Ed25519Identity::from(blinded_pk);
        let enc_desc: EncryptedHsDesc = ParsedHsDesc::parse(unparsed_desc, &id.into())
            .unwrap()
            .check_signature()
            .unwrap()
            .check_valid_at(&humantime::parse_rfc3339(TIMESTAMP).unwrap())
            .unwrap();

        enc_desc
            .decrypt(subcredential, hsc_desc_enc)
            .unwrap()
            .check_valid_at(&humantime::parse_rfc3339(TIMESTAMP).unwrap())
            .unwrap()
            .check_signature()
            .unwrap()
    }

    #[test]
    fn encode_decode() {
        const CREATE2_FORMATS: &[HandshakeType] = &[HandshakeType::TAP, HandshakeType::NTOR];
        const LIFETIME_MINS: u16 = 100;
        const REVISION_COUNT: u64 = 2;
        const CERT_EXPIRY_SECS: u64 = 60 * 60;

        let mut rng = Config::Deterministic.into_rng();
        // The identity keypair of the hidden service.
        let hs_id = ed25519::Keypair::generate(&mut rng);
        let hs_desc_sign = ed25519::Keypair::generate(&mut rng);
        let period = TimePeriod::new(
            humantime::parse_duration("24 hours").unwrap(),
            humantime::parse_rfc3339("2023-02-09T12:00:00Z").unwrap(),
            humantime::parse_duration("12 hours").unwrap(),
        )
        .unwrap();
        let (_, blinded_id, subcredential) = HsIdKeypair::from(ExpandedKeypair::from(&hs_id))
            .compute_blinded_key(period)
            .unwrap();

        let expiry = SystemTime::now() + Duration::from_secs(CERT_EXPIRY_SECS);
        let mut rng = Config::Deterministic.into_rng();
        let intro_points = vec![IntroPointDesc {
            link_specifiers: vec![LinkSpec::OrPort(Ipv4Addr::LOCALHOST.into(), 9999)
                .encode()
                .unwrap()],
            ipt_ntor_key: create_curve25519_pk(&mut rng),
            ipt_sid_key: ed25519::Keypair::generate(&mut rng).verifying_key().into(),
            svc_ntor_key: create_curve25519_pk(&mut rng).into(),
        }];

        let hs_desc_sign_cert =
            create_desc_sign_key_cert(&hs_desc_sign.verifying_key(), &blinded_id, expiry).unwrap();
        let blinded_pk = (&blinded_id).into();
        let builder = HsDescBuilder::default()
            .blinded_id(&blinded_pk)
            .hs_desc_sign(&hs_desc_sign)
            .hs_desc_sign_cert(hs_desc_sign_cert)
            .create2_formats(CREATE2_FORMATS)
            .auth_required(None)
            .is_single_onion_service(true)
            .intro_points(&intro_points)
            .intro_auth_key_cert_expiry(expiry)
            .intro_enc_key_cert_expiry(expiry)
            .lifetime(LIFETIME_MINS.into())
            .revision_counter(REVISION_COUNT.into())
            .subcredential(subcredential);

        // Build and encode a new descriptor (cloning `builder` because it's needed later, when we
        // test if client auth works):
        let encoded_desc = builder
            .clone()
            .build_sign(&mut Config::Deterministic.into_rng())
            .unwrap();

        // Now decode it...
        let desc = parse_hsdesc(
            encoded_desc.as_str(),
            *blinded_id.as_ref().public(),
            &subcredential,
            None, /* No client auth */
        );

        let hs_desc_sign_cert =
            create_desc_sign_key_cert(&hs_desc_sign.verifying_key(), &blinded_id, expiry).unwrap();
        // ...and build a new descriptor using the information from the parsed descriptor,
        // asserting that the resulting descriptor is identical to the original.
        let reencoded_desc = HsDescBuilder::default()
            .blinded_id(&(&blinded_id).into())
            .hs_desc_sign(&hs_desc_sign)
            .hs_desc_sign_cert(hs_desc_sign_cert)
            // create2_formats is hard-coded rather than extracted from desc, because
            // create2_formats is ignored while parsing
            .create2_formats(CREATE2_FORMATS)
            .auth_required(None)
            .is_single_onion_service(desc.is_single_onion_service)
            .intro_points(&intro_points)
            .intro_auth_key_cert_expiry(expiry)
            .intro_enc_key_cert_expiry(expiry)
            .lifetime(desc.idx_info.lifetime)
            .revision_counter(desc.idx_info.revision)
            .subcredential(subcredential)
            .build_sign(&mut Config::Deterministic.into_rng())
            .unwrap();

        assert_eq!(&*encoded_desc, &*reencoded_desc);

        // The same test, this time with client auth enabled (with a single authorized client):
        let client_kp: HsClientDescEncKeypair = HsClientDescEncKeypair::generate(&mut rng);
        let client_pkey = client_kp.public().as_ref();
        let auth_clients = vec![*client_pkey];

        let encoded_desc = builder
            .auth_clients(Some(&auth_clients[..]))
            .build_sign(&mut Config::Deterministic.into_rng())
            .unwrap();

        // Now decode it...
        let desc = parse_hsdesc(
            encoded_desc.as_str(),
            *blinded_id.as_ref().public(),
            &subcredential,
            Some(&client_kp), /* With client auth */
        );

        let hs_desc_sign_cert =
            create_desc_sign_key_cert(&hs_desc_sign.verifying_key(), &blinded_id, expiry).unwrap();
        // ...and build a new descriptor using the information from the parsed descriptor,
        // asserting that the resulting descriptor is identical to the original.
        let reencoded_desc = HsDescBuilder::default()
            .blinded_id(&(&blinded_id).into())
            .hs_desc_sign(&hs_desc_sign)
            .hs_desc_sign_cert(hs_desc_sign_cert)
            // create2_formats is hard-coded rather than extracted from desc, because
            // create2_formats is ignored while parsing
            .create2_formats(CREATE2_FORMATS)
            .auth_required(None)
            .is_single_onion_service(desc.is_single_onion_service)
            .intro_points(&intro_points)
            .intro_auth_key_cert_expiry(expiry)
            .intro_enc_key_cert_expiry(expiry)
            .auth_clients(Some(&auth_clients))
            .lifetime(desc.idx_info.lifetime)
            .revision_counter(desc.idx_info.revision)
            .subcredential(subcredential)
            .build_sign(&mut Config::Deterministic.into_rng())
            .unwrap();

        assert_eq!(&*encoded_desc, &*reencoded_desc);
    }
}
