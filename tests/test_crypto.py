import os
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from src.client.crypto import establish_peer, public_bytes
from src.common.framing import ProtocolError
from src.common.protocol import E2E_HEADER, MAX_SEQ


@pytest.fixture
def pair():
    a_id, b_id = uuid.uuid4().bytes, uuid.uuid4().bytes
    a, b = X25519PrivateKey.generate(), X25519PrivateKey.generate()
    salt = os.urandom(16)
    return (establish_peer(a, a_id, b_id, public_bytes(b), salt),
            establish_peer(b, b_id, a_id, public_bytes(a), salt))


def test_chaves_e_envio_nos_dois_sentidos(pair):
    a, b = pair
    assert a.key_send == b.key_recv and a.key_recv == b.key_send
    assert a.key_send != a.key_recv
    for sender, receiver in [(a, b), (b, a)]:
        for text in [b'', 'Olá!'.encode(), b'x' * 4096]:
            assert receiver.decrypt_message(sender.encrypt_message(text)) == text


@pytest.mark.parametrize('offset', [0, 12, 28, 44, 52, -1])
def test_adulteracao_nao_atualiza_estado(pair, offset):
    a, b = pair
    frame = a.encrypt_message(b'exemplo')
    changed = bytearray(frame)
    changed[offset] ^= 1
    with pytest.raises(ProtocolError):
        b.decrypt_message(bytes(changed))
    assert b.seq_recv == -1 and b.iv_recv is None
    assert b.decrypt_message(frame) == b'exemplo'


def test_replay(pair):
    a, b = pair
    frame = a.encrypt_message(b'uma vez')
    b.decrypt_message(frame)
    with pytest.raises(ProtocolError, match='replay'):
        b.decrypt_message(frame)


def test_contador_alto_adulterado_nao_bloqueia(pair):
    a, b = pair
    frame = a.encrypt_message(b'ok')
    nonce, sender, recipient, _, = E2E_HEADER.unpack_from(frame)
    seq = 1234
    altered = E2E_HEADER.pack(nonce[:4] + seq.to_bytes(8, 'big'), sender, recipient, seq) + frame[52:]
    with pytest.raises(ProtocolError, match='tag'):
        b.decrypt_message(altered)
    assert b.decrypt_message(frame) == b'ok'


def test_limite_e_esgotamento(pair):
    a, b = pair
    with pytest.raises(ProtocolError, match='4096'):
        a.encrypt_message(b'x' * 4097)
    a.seq_send = MAX_SEQ
    assert b.decrypt_message(a.encrypt_message(b'ultimo')) == b'ultimo'
    with pytest.raises(ProtocolError, match='esgotado'):
        a.encrypt_message(b'nao')


def test_novo_par_nao_aceita_frame_antigo(pair):
    a, b = pair
    frame = a.encrypt_message(b'antigo')
    fresh = X25519PrivateKey.generate()
    new_b = establish_peer(fresh, b.own_id, a.own_id, public_bytes(X25519PrivateKey.generate()), os.urandom(16))
    with pytest.raises(ProtocolError, match='tag'):
        new_b.decrypt_message(frame)


def test_peer_malformado():
    with pytest.raises(ProtocolError):
        establish_peer(X25519PrivateKey.generate(), uuid.uuid4().bytes, uuid.uuid4().bytes, b'\0' * 32, os.urandom(16))


def test_terceiro_cliente_nao_decifra(pair):
    a, b = pair
    c = establish_peer(X25519PrivateKey.generate(), b.own_id, a.own_id,
                       public_bytes(X25519PrivateKey.generate()), os.urandom(16))
    with pytest.raises(ProtocolError, match='tag'):
        c.decrypt_message(a.encrypt_message(b'so B'))
