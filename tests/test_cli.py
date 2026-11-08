import asyncio
import sys
import uuid

import pytest_asyncio

from src.client.connection import SecureClient
from src.server.identity import ServerIdentity
from src.server.main import RelayServer


@pytest_asyncio.fixture
async def cli_system(tmp_path):
    server = RelayServer(ServerIdentity.generate())
    port = await server.start(port=0)
    cert = tmp_path / 'server.crt'
    cert.write_bytes(server.identity.certificate)
    processes = []

    async def launch():
        cid = uuid.uuid4()
        proc = await asyncio.create_subprocess_exec(
            sys.executable, '-m', 'src.client.main', '--port', str(port),
            '--cert', str(cert), '--id', str(cid),
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        processes.append(proc)
        await asyncio.wait_for(proc.stdout.readuntil(b'Conectado.'), 5)
        return cid.bytes, proc

    yield server, port, launch
    for proc in processes:
        if proc.returncode is None:
            proc.terminate()
            await proc.wait()
    await server.close()


async def test_cli_envia_recebe_lista_e_sai(cli_system):
    server, port, launch = cli_system
    cid, proc = await launch()
    peer = SecureClient()
    try:
        await peer.connect('127.0.0.1', port, server.identity.certificate)
        await peer.wait_for_peer(cid)
        await asyncio.wait_for(proc.stdout.readuntil(b'entrou.'), 5)
        proc.stdin.write(f'/send {uuid.UUID(bytes=peer.client_id)} resposta do terminal\n'.encode())
        await proc.stdin.drain()
        assert (await peer.receive_message()).text == 'resposta do terminal'
        await peer.send_message(cid, 'recebida no terminal')
        await asyncio.wait_for(proc.stdout.readuntil(b'recebida no terminal'), 5)
        proc.stdin.write(b'/peers\n/id\n/quit\n')
        await proc.stdin.drain()
        out, err = await asyncio.wait_for(proc.communicate(), 5)
        assert str(uuid.UUID(bytes=peer.client_id)).encode() in out
        assert b'Cliente encerrado.' in out and proc.returncode == 0 and not err
    finally:
        await peer.close()


async def test_cli_sai_ao_servidor_cair_sem_esperar_stdin(cli_system):
    server, _, launch = cli_system
    _, proc = await launch()
    await server.close()
    await asyncio.wait_for(proc.wait(), 5)
    assert proc.returncode == 0
    assert b'Cliente encerrado.' in await proc.stdout.read()
