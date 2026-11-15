//! Mutual TLS between devices of one account.
//!
//! Certificates are self-signed; a peer is accepted only if its certificate's
//! Ed25519 key belongs to an active device in the trust store, and the TLS 1.3
//! handshake signature verifies under that same key.

use anyhow::Result;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{CertificateError, DigitallySignedStruct, DistinguishedName, Error, SignatureScheme};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use conduit_core::DeviceIdentity;

/// Active peer device keys mapped to their device ids.
pub type TrustStore = Arc<RwLock<HashMap<[u8; 32], String>>>;

pub fn new_trust_store() -> TrustStore {
    Arc::new(RwLock::new(HashMap::new()))
}

#[derive(Debug)]
struct PeerVerifier {
    trust: TrustStore,
}

impl PeerVerifier {
    fn check(&self, cert: &CertificateDer<'_>) -> Result<(), Error> {
        let key = ed25519_spki_key(cert)
            .ok_or(Error::InvalidCertificate(CertificateError::BadEncoding))?;
        let trusted = self
            .trust
            .read()
            .map(|t| t.contains_key(&key))
            .unwrap_or(false);
        if trusted {
            Ok(())
        } else {
            Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }
}

fn verify_handshake(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, Error> {
    if dss.scheme != SignatureScheme::ED25519 {
        return Err(Error::PeerIncompatible(
            rustls::PeerIncompatible::NoSignatureSchemesInCommon,
        ));
    }
    let key = ed25519_spki_key(cert).ok_or(Error::InvalidCertificate(CertificateError::BadEncoding))?;
    let vk = VerifyingKey::from_bytes(&key)
        .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;
    let sig: [u8; 64] = dss
        .signature()
        .try_into()
        .map_err(|_| Error::InvalidCertificate(CertificateError::BadSignature))?;
    vk.verify(message, &Signature::from_bytes(&sig))
        .map_err(|_| Error::InvalidCertificate(CertificateError::BadSignature))?;
    Ok(HandshakeSignatureValid::assertion())
}

impl ServerCertVerifier for PeerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.check(end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls13RequiredForQuic,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_handshake(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

impl ClientCertVerifier for PeerVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        self.check(end_entity)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls13RequiredForQuic,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_handshake(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

/// Accepts only a server whose Ed25519 key matches the pinned fingerprint.
#[derive(Debug)]
struct PinnedVerifier {
    pin: [u8; 20],
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let key = ed25519_spki_key(end_entity)
            .ok_or(Error::InvalidCertificate(CertificateError::BadEncoding))?;
        if conduit_proto::auth::pin_bytes(&key) == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls13RequiredForQuic,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_handshake(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

/// Client config for the coord control plane (HTTPS and WSS).
pub fn pinned_client_config(pin: [u8; 20]) -> Result<rustls::ClientConfig> {
    let mut config = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedVerifier { pin }))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn own_cert(identity: &DeviceIdentity) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    (
        vec![CertificateDer::from(identity.cert_der.clone())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.key_der.clone())),
    )
}

pub fn server_config(identity: &DeviceIdentity, trust: &TrustStore) -> Result<rustls::ServerConfig> {
    let (certs, key) = own_cert(identity);
    Ok(rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(PeerVerifier {
            trust: trust.clone(),
        }))
        .with_single_cert(certs, key)?)
}

pub fn client_config(identity: &DeviceIdentity, trust: &TrustStore) -> Result<rustls::ClientConfig> {
    let (certs, key) = own_cert(identity);
    Ok(rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PeerVerifier {
            trust: trust.clone(),
        }))
        .with_client_auth_cert(certs, key)?)
}

/// Device id of the authenticated peer, from its leaf certificate.
pub fn peer_device_id(certs: Option<&[CertificateDer<'_>]>) -> Option<String> {
    let leaf = certs?.first()?;
    ed25519_spki_key(leaf).map(|k| conduit_proto::auth::derive_id(&k))
}

fn read_tlv(d: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *d.first()?;
    let first = *d.get(1)?;
    let mut i = 2usize;
    let len = if first & 0x80 == 0 {
        first as usize
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let mut l = 0usize;
        for _ in 0..n {
            l = (l << 8) | *d.get(i)? as usize;
            i += 1;
        }
        l
    };
    let end = i.checked_add(len)?;
    if end > d.len() {
        return None;
    }
    Some((tag, &d[i..end], &d[end..]))
}

/// Subject public key of an X.509 certificate if it is Ed25519.
pub fn ed25519_spki_key(cert_der: &[u8]) -> Option<[u8; 32]> {
    let (tag, cert, _) = read_tlv(cert_der)?;
    if tag != 0x30 {
        return None;
    }
    let (tag, tbs, _) = read_tlv(cert)?;
    if tag != 0x30 {
        return None;
    }
    let mut rest = tbs;
    if let Some((0xa0, _, r)) = read_tlv(rest) {
        rest = r;
    }
    // serialNumber, signature, issuer, validity, subject
    for _ in 0..5 {
        let (_, _, r) = read_tlv(rest)?;
        rest = r;
    }
    let (tag, spki, _) = read_tlv(rest)?;
    const PREFIX: [u8; 10] = [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
    if tag != 0x30 || spki.len() != 42 || spki[..10] != PREFIX {
        return None;
    }
    spki[10..].try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_device_key_from_cert() {
        let id = DeviceIdentity::generate().unwrap();
        let key = ed25519_spki_key(&id.cert_der).unwrap();
        assert_eq!(hex::encode(key), id.pubkey_hex);
        assert!(ed25519_spki_key(b"\x30\x03\x02\x01\x00").is_none());
    }
}
