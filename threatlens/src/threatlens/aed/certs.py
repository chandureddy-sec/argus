"""AED Slice 2 — CA and per-agent client certificates.

A small, self-contained X.509 CA for the lab: it issues short-lived client certs
for agents (clientAuth) and verifies them (chain to this CA, validity window,
not revoked). The CA private key can be **sealed** (Fernet, keyed by a secret) so
it is never stored as cleartext. EC P-256 throughout.

Lab use only. The CA key must be protected at rest and never logged.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


class CertError(Exception):
    """A certificate failed verification (bad chain, expired, or revoked)."""


def _fernet(secret: str) -> Fernet:
    # Derive a 32-byte Fernet key from the secret (mirrors the product vault).
    raw = hashlib.sha256(secret.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(raw))


def new_agent_csr(agent_id: str) -> tuple[bytes, bytes]:
    """Agent-side: generate a keypair and a CSR for ``agent_id``.

    Returns ``(private_key_pem, csr_pem)``. In real use the agent runs this and
    its private key never leaves the host; only the CSR is sent to the gateway.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, agent_id)]))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return key_pem, csr.public_bytes(serialization.Encoding.PEM)


class CA:
    """The lab certificate authority."""

    def __init__(self, cert: x509.Certificate, key: ec.EllipticCurvePrivateKey) -> None:
        self._cert = cert
        self._key = key

    @classmethod
    def generate(cls, common_name: str = "AED Lab CA", days: int = 3650) -> CA:
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(UTC)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )
        return cls(cert, key)

    def cert_pem(self) -> bytes:
        return self._cert.public_bytes(serialization.Encoding.PEM)

    def fingerprint(self) -> str:
        """SHA-256 of the CA certificate (DER), hex. An agent pins this to verify
        the server before trusting it — the same bytes an OpenSSL/Go consumer
        hashes, so the install command and the agent agree."""
        import hashlib

        der = self._cert.public_bytes(serialization.Encoding.DER)
        return hashlib.sha256(der).hexdigest()

    def seal_key(self, secret: str) -> bytes:
        """Return the CA private key encrypted (Fernet) with ``secret``."""
        pem = self._key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        return _fernet(secret).encrypt(pem)

    @classmethod
    def load(cls, cert_pem: bytes, sealed_key: bytes, secret: str) -> CA:
        """Rebuild a CA from its public cert and a sealed private key."""
        try:
            key_pem = _fernet(secret).decrypt(sealed_key)
        except InvalidToken as e:
            raise CertError("cannot decrypt the CA key (wrong secret?)") from e
        cert = x509.load_pem_x509_certificate(cert_pem)
        key = serialization.load_pem_private_key(key_pem, password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise CertError("unexpected CA key type")
        return cls(cert, key)

    def sign_csr(self, csr_pem: bytes, agent_id: str, days: int = 90) -> bytes:
        """Issue a client (agent) certificate for ``agent_id`` from a CSR."""
        csr = x509.load_pem_x509_csr(csr_pem)
        if not csr.is_signature_valid:
            raise CertError("CSR signature is invalid")
        now = datetime.now(UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, agent_id)]))
            .issuer_name(self._cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .sign(self._key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.PEM)

    def verify(self, cert_pem: bytes, now: datetime, is_revoked: Callable[[str], bool]) -> str:
        """Verify a client cert and return its ``agent_id``.

        Checks: signed by this CA, within its validity window, agent not revoked.
        Raises :class:`CertError` on any failure.
        """
        try:
            cert = x509.load_pem_x509_certificate(cert_pem)
        except ValueError as e:
            raise CertError("not a valid certificate") from e
        pub = self._cert.public_key()
        if not isinstance(pub, ec.EllipticCurvePublicKey):
            raise CertError("unexpected CA public key type")
        algo = cert.signature_hash_algorithm
        if algo is None:
            raise CertError("certificate has no signature hash algorithm")
        try:
            pub.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(algo))
        except InvalidSignature as e:
            raise CertError("certificate is not signed by this CA") from e
        if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
            raise CertError("certificate is expired or not yet valid")
        cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not cns:
            raise CertError("certificate has no agent id")
        agent_id = str(cns[0].value)
        if is_revoked(agent_id):
            raise CertError(f"agent {agent_id} is revoked")
        return agent_id
