import asyncio
import logging
import uuid

import pytest
import pytest_asyncio

from src.client.connection import SecureClient
from src.common.framing import ProtocolError, write_frame
from src.common.protocol import E2E_HEADER, Kind
from src.server.identity import ServerIdentity
from src.server.main import RelayServer


async def event(client, kind):
    async with asyncio.timeout(3):
        while True:
            received, value = await client.events.get()
            if received == kind:
                return value


@pytest_asyncio.fixture
async def system():
    server = RelayServer(ServerIdentity.generate())
    port = await server.start(port=0)
    clients = []

    async def connect(cid=None):
        client = SecureClient(cid)
        clients.append(client)
        await client.connect('127.0.0.1', port, server.identity.certificate)
        return client

    yield server, connect
    await asyncio.gather(*(c.close() for c in clients))
    await server.close()


async def pair(connect):
    a, b = await connect(), await connect()
    await asyncio.gather(a.wait_for_peer(b.client_id), b.wait_for_peer(a.client_id))
    return a, b


async def test_tres_clientes_e_todos_os_pares(system):
    server, connect = system
    a, b = await pair(connect)
    c = await connect()
    for own in (a, b, c):
        for other in (a, b, c):
            if own is not other:
                await own.wait_for_peer(other.client_id)
                await own.send_message(other.client_id, 'Olá, destino escolhido!')
                message = await other.receive_message()
                assert message.sender_id == own.client_id
                assert message.text == 'Olá, destino escolhido!'
    assert len(server.sessions) == 3
    assert all(client.messages.empty() for client in (a, b, c))


async def test_bitflip_replay_e_mensagem_seguinte(system):
    _, connect = system
    a, b = await pair(connect)
    frame = a.peers[b.client_id].encrypt_message(b'valida')
    await a.send_payload(frame[:-1] + bytes([frame[-1] ^ 1]))
    assert await event(b, 'rejected') == 'tag GCM inválida'
    assert b.peers[a.client_id].seq_recv == -1
    await a.send_payload(frame)
    assert (await b.receive_message()).text == 'valida'
    await a.send_payload(frame)
    assert 'replay' in await event(b, 'rejected')
    await a.send_message(b.client_id, 'seguinte')
    assert (await b.receive_message()).text == 'seguinte'


async def test_reconexao_mesmo_uuid_renova_chaves(system):
    _, connect = system
    a, b = await pair(connect)
    old_key = b.peers[a.client_id].key_recv
    old_frame = await a.send_message(b.client_id, 'antiga')
    await b.receive_message()
    await a.close()
    assert a.directory.private_key is None
    await event(b, 'left')
    new_a = await connect(a.client_id)
    await asyncio.gather(new_a.wait_for_peer(b.client_id), b.wait_for_peer(new_a.client_id))
    assert b.peers[new_a.client_id].key_recv != old_key
    await new_a.send_payload(old_frame)
    assert 'tag' in await event(b, 'rejected')
    await new_a.send_message(b.client_id, 'nova')
    assert (await b.receive_message()).text == 'nova'


async def test_remetente_falso_desconecta_apenas_ofensor(system):
    _, connect = system
    a, b = await pair(connect)
    c = await connect()
    await c.wait_for_peer(b.client_id)
    await b.wait_for_peer(c.client_id)
    frame = a.peers[b.client_id].encrypt_message(b'falsa')
    nonce, _, dest, seq = E2E_HEADER.unpack_from(frame)
    await a.send_payload(E2E_HEADER.pack(nonce, c.client_id, dest, seq) + frame[52:])
    await asyncio.wait_for(a.closed.wait(), 3)
    assert b.messages.empty()
    await c.send_message(b.client_id, 'ainda funciona')
    assert (await b.receive_message()).text == 'ainda funciona'


async def test_concorrencia_e_utf8(system):
    _, connect = system
    a, b = await pair(connect)
    await asyncio.gather(*(a.send_message(b.client_id, str(i)) for i in range(30)))
    assert [(await b.receive_message()).text for _ in range(30)] == [str(i) for i in range(30)]
    await a.send_message(b.client_id, 'é' * 2048)
    assert (await b.receive_message()).text == 'é' * 2048
    with pytest.raises(ProtocolError, match='4096'):
        await a.send_message(b.client_id, 'é' * 2049)


async def test_controle_adulterado_fecha_cliente(system):
    server, connect = system
    a = await connect()
    session = server.sessions[a.client_id]
    control = server.identity.control(Kind.ERROR, a.client_id, session.context, session.seq_send, b'erro')
    bad = control[:-1] + bytes([control[-1] ^ 1])
    await write_frame(session.writer, bad, session.write_lock)
    await asyncio.wait_for(a.closed.wait(), 3)
    assert 'assinatura' in await event(a, 'closed')


async def test_limite_de_conexoes():
    server = RelayServer(ServerIdentity.generate(), max_clients=1)
    port = await server.start(port=0)
    a, b = SecureClient(), SecureClient()
    try:
        await a.connect('127.0.0.1', port, server.identity.certificate)
        with pytest.raises((asyncio.IncompleteReadError, ConnectionError)):
            await b.connect('127.0.0.1', port, server.identity.certificate)
        assert not a.closed.is_set()
    finally:
        await a.close()
        await b.close()
        await server.close()


async def test_logs_sem_segredos_ou_conteudo(system, caplog):
    server, connect = system
    caplog.set_level(logging.INFO, logger='relay')
    a, b = await pair(connect)
    token = 'CONTEUDO_PRIVADO_NAO_DEVE_APARECER_NO_LOG'
    frame = await a.send_message(b.client_id, token)
    await b.receive_message()
    forbidden = [token, frame[:12].hex(), a.peers[b.client_id].key_send.hex(),
                 server.sessions[a.client_id].salt.hex()]
    assert all(value not in caplog.text for value in forbidden)
    assert 'encaminhado' in caplog.text
