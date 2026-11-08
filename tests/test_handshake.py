import os
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from src.client.crypto import public_bytes
from src.client.handshake import verify_welcome
from src.common.framing import ProtocolError
from src.common.protocol import Kind, unpack
from src.server.identity import ServerIdentity, context_id, verify_control


@pytest.fixture(scope='module')
def identity():
    return ServerIdentity.generate()


def test_handshake_pin_assinatura_e_transcript(identity):
    client, public, salt = uuid.uuid4().bytes, public_bytes(X25519PrivateKey.generate()), os.urandom(16)
    payload = identity.welcome(client, public, salt)
    key, context = verify_welcome(payload, identity.certificate, client, public)
    assert key.key_size >= 2048 and context == context_id(client, public, salt)
    for pin, cid, pk in [(b'outro', client, public), (identity.certificate, uuid.uuid4().bytes, public),
                         (identity.certificate, client, public_bytes(X25519PrivateKey.generate()))]:
        with pytest.raises(ProtocolError):
            verify_welcome(payload, pin, cid, pk)
    changed = payload[:-1] + bytes([payload[-1] ^ 1])
    with pytest.raises(ProtocolError, match='assinatura'):
        verify_welcome(changed, identity.certificate, client, public)


def test_controles_assinados_replay_e_contexto(identity):
    recipient, context = uuid.uuid4().bytes, os.urandom(32)
    body = identity.control(Kind.PEER, recipient, context, 0, b'lista')
    kind, payload = unpack(body)
    key = identity.private_key.public_key()
    assert verify_control(key, kind, payload, recipient, context, -1) == (0, b'lista')
    with pytest.raises(ProtocolError, match='replay'):
        verify_control(key, kind, payload, recipient, context, 0)
    with pytest.raises(ProtocolError, match='sessão'):
        verify_control(key, kind, payload, recipient, os.urandom(32), -1)
    changed = payload[:-1] + bytes([payload[-1] ^ 1])
    with pytest.raises(ProtocolError, match='assinatura'):
        verify_control(key, kind, changed, recipient, context, -1)


def test_identidade_salva_sem_sobrescrever(identity, tmp_path):
    key, cert = tmp_path / 'server.key', tmp_path / 'server.crt'
    identity.save(key, cert)
    assert key.stat().st_mode & 0o777 == 0o600
    assert ServerIdentity.load(key, cert).public == identity.public
    with pytest.raises(FileExistsError):
        identity.save(key, cert)
