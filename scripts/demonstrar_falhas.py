"""Demonstrações com relay TCP real e frames manipulados apenas em memória."""
import argparse
import asyncio
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.client.connection import SecureClient
from src.common.protocol import aad, parse_e2e
from src.server.identity import ServerIdentity
from src.server.main import RelayServer


async def next_event(client, kind):
    async with asyncio.timeout(5):
        while True:
            event, value = await client.events.get()
            if event == kind:
                return value


async def demo(scenario='todos'):
    server = RelayServer(ServerIdentity.generate())
    port = await server.start(port=0)
    clients = []

    async def connect(cid=None):
        client = SecureClient(cid)
        clients.append(client)
        await client.connect('127.0.0.1', port, server.identity.certificate)
        return client

    def enabled(name):
        return scenario in ('todos', name)

    try:
        a, b, c = await connect(), await connect(), await connect()
        for own, peer in [(a, b), (b, a), (c, a), (a, c), (b, c), (c, b)]:
            await own.wait_for_peer(peer.client_id)
        print('AMBIENTE: relay TCP local e três clientes registrados.', flush=True)

        if enabled('e2e'):
            frame = await a.send_message(b.client_id, 'mensagem fictícia A para B')
            assert (await b.receive_message()).text == 'mensagem fictícia A para B'
            await b.send_message(a.client_id, 'resposta fictícia B para A')
            assert (await a.receive_message()).text == 'resposta fictícia B para A'
            assert c.messages.empty()
            nonce, sender, recipient, seq, ciphertext = parse_e2e(frame)
            try:
                AESGCM(c.peers[a.client_id].key_recv).decrypt(nonce, ciphertext, aad(sender, recipient, seq))
            except InvalidTag:
                pass
            else:
                raise AssertionError('terceiro cliente conseguiu decifrar')
            print('PASSOU E2E: troca nos dois sentidos; C não recebeu nem conseguiu decifrar.', flush=True)

        if enabled('adulteracao'):
            frame = a.peers[b.client_id].encrypt_message(b'original')
            altered = frame[:-1] + bytes([frame[-1] ^ 1])
            before = b.peers[a.client_id].seq_recv
            await a.send_payload(altered)
            assert await next_event(b, 'rejected') == 'tag GCM inválida'
            assert b.messages.empty() and b.peers[a.client_id].seq_recv == before
            await a.send_payload(frame)
            assert (await b.receive_message()).text == 'original'
            print('PASSOU ADULTERAÇÃO: bitflip rejeitado por GCM; frame íntegro seguinte aceito.', flush=True)

        if enabled('replay'):
            frame = await a.send_message(b.client_id, 'uma única aceitação')
            await b.receive_message()
            await a.send_payload(frame)
            assert 'replay' in await next_event(b, 'rejected')
            assert b.messages.empty()
            print('PASSOU REPLAY: reenvio do mesmo frame rejeitado pelo contador.', flush=True)

        if enabled('framing'):
            reader, writer = await asyncio.open_connection('127.0.0.1', port)
            try:
                writer.write(struct.pack('!I', 0xffffffff))
                await writer.drain()
                assert await asyncio.wait_for(reader.read(), 5) == b''
            finally:
                writer.close()
                await writer.wait_closed()
            await a.send_message(b.client_id, 'relay permanece operacional')
            await b.receive_message()
            assert len(server.sessions) == 3
            print('PASSOU FRAMING: comprimento inválido encerrou só a conexão ofensora.', flush=True)

        if enabled('reconexao'):
            old = await a.send_message(b.client_id, 'sessão anterior')
            await b.receive_message()
            old_key = b.peers[a.client_id].key_recv
            old_id = a.client_id
            await a.close()
            await next_event(b, 'left')
            a = await connect(old_id)
            await asyncio.gather(a.wait_for_peer(b.client_id), b.wait_for_peer(a.client_id))
            assert b.peers[a.client_id].key_recv != old_key
            await a.send_payload(old)
            assert 'tag' in await next_event(b, 'rejected')
            await a.send_message(b.client_id, 'sessão renovada')
            await b.receive_message()
            print('PASSOU RECONEXÃO: mesmo UUID, novas chaves; frame antigo rejeitado.', flush=True)

        if enabled('pinning'):
            from src.common.framing import ProtocolError
            wrong = SecureClient()
            clients.append(wrong)
            try:
                await wrong.connect('127.0.0.1', port, ServerIdentity.generate().certificate)
            except ProtocolError as exc:
                assert 'pin' in str(exc)
            else:
                raise AssertionError('certificado inesperado foi aceito')
            print('PASSOU PINNING: certificado diferente do pin foi recusado.', flush=True)

        print('DEMONSTRAÇÃO CONCLUÍDA: nenhuma chave, nonce, salt ou frame foi impresso.', flush=True)
    finally:
        await asyncio.gather(*(client.close() for client in clients))
        await server.close()


def main():
    parser = argparse.ArgumentParser(description='Demonstrações reproduzíveis com três clientes TCP reais.')
    parser.add_argument('--cenario', choices=['todos', 'e2e', 'adulteracao', 'replay', 'framing', 'reconexao', 'pinning'],
                        default='todos')
    args = parser.parse_args()
    try:
        asyncio.run(demo(args.cenario))
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
