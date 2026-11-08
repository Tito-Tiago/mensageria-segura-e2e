"""Criptografia ponta a ponta: o servidor não importa este módulo."""
import os
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from src.common.framing import ProtocolError
from src.common.protocol import E2E_HEADER, MAX_PLAINTEXT, MAX_SEQ, aad, parse_e2e, validate_id


def public_bytes(private_key):
    return private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def derive_peer_keys(private_key, own_id, peer_id, peer_public, salt):
    """Extrai PRK de Z e expande duas chaves com papéis estáveis pelo UUID."""
    validate_id(own_id)
    validate_id(peer_id)
    if own_id == peer_id or len(peer_public) != 32 or len(salt) != 16:
        raise ProtocolError('parâmetros de peer inválidos')
    try:
        secret = private_key.exchange(X25519PublicKey.from_public_bytes(peer_public))
    except ValueError as exc:
        raise ProtocolError('chave X25519 inválida') from exc
    extract = hmac.HMAC(salt, hashes.SHA256())
    extract.update(secret)
    prk = extract.finalize()
    a2b = HKDFExpand(algorithm=hashes.SHA256(), length=16, info=b'A2B').derive(prk)
    b2a = HKDFExpand(algorithm=hashes.SHA256(), length=16, info=b'B2A').derive(prk)
    # Z e PRK não são guardados no estado do cliente nem registrados em logs.
    return (a2b, b2a) if own_id < peer_id else (b2a, a2b)


@dataclass
class PeerCipher:
    own_id: bytes
    peer_id: bytes
    key_send: bytes = field(repr=False)
    key_recv: bytes = field(repr=False)
    iv_send: bytes = field(default_factory=lambda: os.urandom(4), repr=False)
    iv_recv: bytes | None = field(default=None, repr=False)
    seq_send: int = 0
    seq_recv: int = -1

    def encrypt_message(self, plaintext):
        if len(plaintext) > MAX_PLAINTEXT:
            raise ProtocolError('mensagem excede 4096 bytes')
        if self.seq_send > MAX_SEQ:
            raise ProtocolError('contador esgotado: reconecte')
        seq = self.seq_send
        self.seq_send += 1  # Reserva antes da operação: nunca reutilizar, mesmo após erro.
        nonce = self.iv_send + seq.to_bytes(8, 'big')
        ciphertext = AESGCM(self.key_send).encrypt(nonce, plaintext, aad(self.own_id, self.peer_id, seq))
        return E2E_HEADER.pack(nonce, self.own_id, self.peer_id, seq) + ciphertext

    def decrypt_message(self, payload):
        nonce, sender, recipient, seq, ciphertext = parse_e2e(payload)
        if sender != self.peer_id or recipient != self.own_id:
            raise ProtocolError('identidade E2E incompatível')
        if seq <= self.seq_recv:
            raise ProtocolError('replay rejeitado')
        if self.iv_recv is not None and nonce[:4] != self.iv_recv:
            raise ProtocolError('IV de sessão incompatível')
        try:
            plaintext = AESGCM(self.key_recv).decrypt(nonce, ciphertext, aad(sender, recipient, seq))
        except InvalidTag as exc:
            raise ProtocolError('tag GCM inválida') from exc
        # Somente um frame autenticado pode modificar o estado de recepção.
        self.iv_recv = nonce[:4]
        self.seq_recv = seq
        return plaintext


def establish_peer(private_key, own_id, peer_id, peer_public, salt):
    send, recv = derive_peer_keys(private_key, own_id, peer_id, peer_public, salt)
    return PeerCipher(own_id, peer_id, send, recv)
