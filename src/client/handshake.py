"""Valida o servidor antes de aceitar seu diretório de chaves públicas."""
import hmac

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils

from src.common.framing import ProtocolError
from src.common.protocol import decode_blob
from src.server.identity import PSS, context_id, public_der, transcript_hash, validate_certificate


def verify_welcome(payload, pinned_certificate, client_id, client_public):
    server_public, pos = decode_blob(payload)
    certificate, pos = decode_blob(payload, pos)
    if not hmac.compare_digest(certificate, pinned_certificate):
        raise ProtocolError('certificado diferente do pin')
    key = validate_certificate(certificate)
    if server_public != public_der(key):
        raise ProtocolError('chave do servidor incompatível')
    salt = payload[pos:pos + 16]
    if len(salt) != 16:
        raise ProtocolError('salt de handshake inválido')
    signature, end = decode_blob(payload, pos + 16)
    if end != len(payload):
        raise ProtocolError('handshake com bytes extras')
    digest = transcript_hash(server_public, client_public, client_id, salt)
    try:
        key.verify(signature, digest, PSS, utils.Prehashed(hashes.SHA256()))
    except InvalidSignature as exc:
        raise ProtocolError('assinatura do handshake inválida') from exc
    return key, context_id(client_id, client_public, salt)
