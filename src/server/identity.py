"""Identidade persistente RSA; autentica o servidor, sem derivar chaves E2E."""
import datetime as dt
import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.x509.oid import NameOID

from src.common.framing import ProtocolError
from src.common.protocol import CONTROL_HEADER, MAX_SEQ, decode_blob, encode_blob, pack

PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
CONTROL_DOMAIN = b'TP3-control-v1\0'


def public_der(key):
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def context_id(client_id, public_key, salt):
    return hashlib.sha256(b'TP3-session-v1\0' + client_id + public_key + salt).digest()


def transcript_hash(server_public, client_public, client_id, salt):
    return hashlib.sha256(server_public + client_public + client_id + salt).digest()


def validate_certificate(pem):
    try:
        cert = x509.load_pem_x509_certificate(pem)
        key = cert.public_key()
        if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
            raise ValueError('RSA exigido')
        now = dt.datetime.now(dt.timezone.utc)
        if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
            raise ValueError('fora da validade')
        if cert.issuer != cert.subject:
            raise ValueError('certificado deve ser autoassinado')
        key.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
        return key
    except (ValueError, InvalidSignature) as exc:
        raise ProtocolError('certificado inválido') from exc


@dataclass
class ServerIdentity:
    private_key: rsa.RSAPrivateKey = field(repr=False)
    certificate: bytes

    @property
    def public(self):
        return public_der(self.private_key.public_key())

    @classmethod
    def generate(cls):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'TP3 Mensageria Local')])
        now = dt.datetime.now(dt.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(minutes=5))
                .not_valid_after(now + dt.timedelta(days=365))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .sign(key, hashes.SHA256()))
        return cls(key, cert.public_bytes(serialization.Encoding.PEM))

    def save(self, key_path, cert_path):
        key_path, cert_path = Path(key_path), Path(cert_path)
        key_path.parent.mkdir(parents=True, exist_ok=True)
        cert_path.parent.mkdir(parents=True, exist_ok=True)
        if key_path.exists() or cert_path.exists():
            raise FileExistsError('identidade já existe; não será sobrescrita')
        key_bytes = self.private_key.private_bytes(serialization.Encoding.PEM,
                                                   serialization.PrivateFormat.PKCS8,
                                                   serialization.NoEncryption())
        # Arquivo exclusivo e permissão restrita desde sua criação.
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(key_bytes)
        with cert_path.open('xb') as stream:
            stream.write(self.certificate)

    @classmethod
    def load(cls, key_path, cert_path):
        key = serialization.load_pem_private_key(Path(key_path).read_bytes(), password=None)
        cert = Path(cert_path).read_bytes()
        public = validate_certificate(cert)
        if not isinstance(key, rsa.RSAPrivateKey) or public_der(public) != public_der(key.public_key()):
            raise ProtocolError('chave privada incompatível com certificado')
        return cls(key, cert)

    def welcome(self, client_id, client_public, salt):
        digest = transcript_hash(self.public, client_public, client_id, salt)
        signature = self.private_key.sign(digest, PSS, utils.Prehashed(hashes.SHA256()))
        return encode_blob(self.public) + encode_blob(self.certificate) + salt + encode_blob(signature)

    def control(self, kind, recipient, context, seq, data):
        if not 0 <= seq <= MAX_SEQ:
            raise ProtocolError('contador administrativo esgotado')
        unsigned = pack(kind, CONTROL_HEADER.pack(recipient, context, seq) + encode_blob(data))
        signature = self.private_key.sign(CONTROL_DOMAIN + unsigned, PSS, hashes.SHA256())
        return unsigned + encode_blob(signature)


def verify_control(server_key, kind, payload, recipient, context, last_seq):
    if len(payload) < CONTROL_HEADER.size:
        raise ProtocolError('controle truncado')
    target, received_context, seq = CONTROL_HEADER.unpack_from(payload)
    if target != recipient or received_context != context:
        raise ProtocolError('controle de outra sessão')
    if seq <= last_seq:
        raise ProtocolError('replay administrativo rejeitado')
    data, end = decode_blob(payload, CONTROL_HEADER.size)
    signature, final = decode_blob(payload, end)
    if final != len(payload):
        raise ProtocolError('controle com bytes extras')
    try:
        server_key.verify(signature, CONTROL_DOMAIN + pack(kind, payload[:end]), PSS, hashes.SHA256())
    except InvalidSignature as exc:
        raise ProtocolError('assinatura de controle inválida') from exc
    return seq, data
