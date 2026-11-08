import asyncio
import os
import struct
import uuid

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from src.client.crypto import public_bytes
from src.client.handshake import verify_welcome
from src.common.framing import read_frame, write_frame
from src.common.protocol import Kind, REGISTER, pack, unpack
from src.server.identity import ServerIdentity
from src.server.main import RelayServer


@pytest_asyncio.fixture
async def relay():
    server = RelayServer(ServerIdentity.generate())
    port = await server.start(port=0)
    yield server, port
    await server.close()


async def register(port, identity, client_id=None):
    cid = client_id or uuid.uuid4().bytes
    public = public_bytes(X25519PrivateKey.generate())
    reader, writer = await asyncio.open_connection('127.0.0.1', port)
    await write_frame(writer, pack(Kind.REGISTER, REGISTER.pack(cid, public)), asyncio.Lock())
    kind, payload = unpack(await asyncio.wait_for(read_frame(reader), 2))
    assert kind == Kind.WELCOME
    verify_welcome(payload, identity.certificate, cid, public)
    return cid, reader, writer


async def test_dois_registros_e_anuncios(relay):
    server, port = relay
    _, ar, aw = await register(port, server.identity)
    _, br, bw = await register(port, server.identity)
    assert unpack(await read_frame(ar))[0] == Kind.PEER
    assert unpack(await read_frame(br))[0] == Kind.PEER
    assert len(server.sessions) == 2
    assert all(not hasattr(s, 'key_send') for s in server.sessions.values())
    aw.close()
    bw.close()


async def test_uuid_duplicado_preserva_original(relay):
    server, port = relay
    cid, _, writer = await register(port, server.identity)
    with pytest.raises(asyncio.IncompleteReadError):
        await register(port, server.identity, cid)
    assert server.sessions[cid].writer is not None
    writer.close()


async def test_frame_invalido_desconecta_sem_derrubar_servidor(relay):
    server, port = relay
    reader, writer = await asyncio.open_connection('127.0.0.1', port)
    writer.write(struct.pack('!I', 0xffffffff))
    await writer.drain()
    assert await asyncio.wait_for(reader.read(), 2) == b''
    writer.close()
    _, _, valid = await register(port, server.identity)
    valid.close()


async def test_chave_nula_rejeitada(relay):
    _, port = relay
    reader, writer = await asyncio.open_connection('127.0.0.1', port)
    await write_frame(writer, pack(Kind.REGISTER, REGISTER.pack(uuid.uuid4().bytes, b'\0' * 32)), asyncio.Lock())
    assert await asyncio.wait_for(reader.read(), 2) == b''
    writer.close()
