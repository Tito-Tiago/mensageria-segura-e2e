import asyncio
import os
import socket
import struct
import uuid

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from src.client.crypto import public_bytes
from src.client.connection import SecureClient
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


@pytest.mark.parametrize('cenario', ['timeout', 'encerramento', 'framing'])
async def test_destinatario_sem_leitura_nao_prende_relay(relay, monkeypatch, cenario):
    import src.common.framing as framing
    import src.server.main as relay_module

    # Reduz os prazos de I/O para tornar a regressão rápida.
    monkeypatch.setattr(framing, 'FRAME_TIMEOUT', 0.5)
    monkeypatch.setattr(relay_module, 'FRAME_TIMEOUT', 0.5)
    server, port = relay
    sender = SecureClient()
    other = SecureClient()
    slow_id = uuid.uuid4().bytes
    slow = socket.socket()
    slow.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    slow.setblocking(False)
    try:
        await sender.connect('127.0.0.1', port, server.identity.certificate)
        loop = asyncio.get_running_loop()
        await loop.sock_connect(slow, ('127.0.0.1', port))
        body = pack(Kind.REGISTER, REGISTER.pack(slow_id, public_bytes(X25519PrivateKey.generate())))
        await loop.sock_sendall(slow, struct.pack('!I', len(body)) + body)
        # O socket registra, mas nunca lê WELCOME, controles ou mensagens.
        await sender.wait_for_peer(slow_id)
        session = server.sessions[slow_id]
        session.writer.get_extra_info('socket').setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        for _ in range(100):
            await sender.send_message(slow_id, 'x' * 4096)
        async with asyncio.timeout(3):
            while session.writer.transport.get_write_buffer_size() <= 65536:
                await asyncio.sleep(0.001)

        if cenario == 'encerramento':
            await asyncio.wait_for(server.close(), 2)
            assert not server.sessions and not server.connections and not server.tasks
        else:
            if cenario == 'framing':
                # O handler deve limitar wait_closed também ao rejeitar um frame,
                # mesmo que ainda haja dados de saída bloqueados pelo destinatário.
                await loop.sock_sendall(slow, struct.pack('!I', 0xffffffff))
            async with asyncio.timeout(3):
                while slow_id in server.sessions or session.writer in server.connections:
                    await asyncio.sleep(0.01)
            assert not sender.closed.is_set()
            await other.connect('127.0.0.1', port, server.identity.certificate)
            await sender.wait_for_peer(other.client_id)
            await other.wait_for_peer(sender.client_id)
            await sender.send_message(other.client_id, 'relay operacional')
            assert (await other.receive_message()).text == 'relay operacional'
    finally:
        slow.close()
        for writer in list(server.connections):
            writer.transport.abort()
        await sender.close()
        await other.close()
