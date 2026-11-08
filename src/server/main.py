"""Servidor relay: conhece chaves públicas, jamais chaves AES dos clientes."""
import argparse
import asyncio
import logging
import os
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from src.common.framing import FRAME_TIMEOUT, ProtocolError, read_frame, write_frame
from src.common.protocol import Kind, PEER_INFO, REGISTER, pack, parse_e2e, unpack, validate_id
from src.server.identity import ServerIdentity, context_id

LOG = logging.getLogger('relay')


@dataclass
class Session:
    client_id: bytes
    public_key: bytes
    writer: asyncio.StreamWriter = field(repr=False)
    context: bytes = field(repr=False)
    salt: bytes = field(repr=False)
    seq_send: int = 0
    seq_recv: int = -1  # Reservado para futuros controles autenticados cliente -> servidor.
    write_lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)
    control_lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)


class RelayServer:
    def __init__(self, identity, *, max_clients=20):
        if max_clients < 1:
            raise ValueError('max_clients deve ser positivo')
        self.identity = identity
        self.max_clients = max_clients
        self.sessions = {}
        self.membership_lock = asyncio.Lock()
        self.connections = set()
        self.tasks = set()
        self.listener = None
        self.closing = False

    async def start(self, host='127.0.0.1', port=8888):
        self.listener = await asyncio.start_server(self.handle, host, port)
        return self.listener.sockets[0].getsockname()[1]

    async def close(self):
        self.closing = True
        if self.listener:
            self.listener.close()
        for writer in list(self.connections):
            # close() tenta escoar o buffer e pode nunca concluir se o peer não lê.
            # No encerramento do relay não há garantia de entrega pendente.
            writer.transport.abort()
        if self.tasks:
            await asyncio.gather(*list(self.tasks), return_exceptions=True)
        # Em Python 3.12+, wait_closed também aguarda transportes ativos.
        # Fechá-los antes evita bloquear o encerramento com clientes conectados.
        if self.listener:
            await self.listener.wait_closed()

    async def send_control(self, session, kind, data):
        # O lock engloba reservar contador, assinar e escrever, preservando a ordem.
        async with session.control_lock:
            seq = session.seq_send
            session.seq_send += 1
            body = self.identity.control(kind, session.client_id, session.context, seq, data)
            await write_frame(session.writer, body, session.write_lock)

    async def notify(self, session, kind, data):
        try:
            await self.send_control(session, kind, data)
        except (ConnectionError, OSError, TimeoutError, ProtocolError):
            session.writer.transport.abort()

    async def register(self, reader, writer):
        body = await asyncio.wait_for(read_frame(reader), FRAME_TIMEOUT)
        kind, payload = unpack(body)
        if kind != Kind.REGISTER or len(payload) != REGISTER.size:
            raise ProtocolError('registro inválido')
        client_id, public = REGISTER.unpack(payload)
        validate_id(client_id)
        try:
            # Rejeita pontos de baixa ordem antes de anunciar uma chave aos clientes.
            X25519PrivateKey.generate().exchange(X25519PublicKey.from_public_bytes(public))
        except ValueError as exc:
            raise ProtocolError('chave pública inválida') from exc
        salt = os.urandom(16)
        session = Session(client_id, public, writer, context_id(client_id, public, salt), salt)
        async with self.membership_lock:
            if client_id in self.sessions:
                raise ProtocolError('UUID já conectado')
            await write_frame(writer, pack(Kind.WELCOME, self.identity.welcome(client_id, public, salt)),
                              session.write_lock)
            existing = list(self.sessions.values())
            self.sessions[client_id] = session
            for peer in existing:
                pair_salt = os.urandom(16)
                # O novo cliente aprende o peer antes que esse peer possa enviar para ele.
                await self.notify(session, Kind.PEER, PEER_INFO.pack(peer.client_id, peer.public_key, pair_salt))
                await self.notify(peer, Kind.PEER, PEER_INFO.pack(client_id, public, pair_salt))
        LOG.info('conectado client_id=%s', client_id.hex())
        return session

    async def relay(self, session, payload):
        _, sender, recipient, _, _ = parse_e2e(payload)
        if sender != session.client_id:
            raise ProtocolError('remetente incompatível com conexão')
        peer = self.sessions.get(recipient)
        if peer is None:
            await self.send_control(session, Kind.ERROR, b'destinatario indisponivel')
            return
        try:
            await write_frame(peer.writer, pack(Kind.E2E, payload), peer.write_lock)
            LOG.info('encaminhado client_id=%s bytes=%d', sender.hex(), len(payload))
        except (ConnectionError, OSError, TimeoutError):
            peer.writer.transport.abort()
            await self.send_control(session, Kind.ERROR, b'destinatario indisponivel')

    async def handle(self, reader, writer):
        if self.closing:
            writer.transport.abort()
            return
        if len(self.connections) >= self.max_clients:
            writer.close()
            await writer.wait_closed()
            return
        self.connections.add(writer)
        task = asyncio.current_task()
        self.tasks.add(task)
        session = None
        try:
            session = await self.register(reader, writer)
            while True:
                kind, payload = unpack(await read_frame(reader))
                if kind != Kind.E2E:
                    raise ProtocolError('tipo não permitido após registro')
                await self.relay(session, payload)
        except asyncio.IncompleteReadError:
            pass
        except (ProtocolError, ConnectionError, OSError, TimeoutError) as exc:
            # Todas as mensagens de ProtocolError são constantes locais, sem payload.
            reason = str(exc) if isinstance(exc, ProtocolError) else 'conexão interrompida'
            LOG.info('rejeitado motivo=%s', reason)
        finally:
            # Uma segunda conexão recusada não pode remover a primeira com mesmo UUID.
            async with self.membership_lock:
                if session is not None and self.sessions.get(session.client_id) is session:
                    del self.sessions[session.client_id]
                    for peer in list(self.sessions.values()):
                        await self.notify(peer, Kind.LEFT, session.client_id)
                    LOG.info('desconectado client_id=%s', session.client_id.hex())
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), FRAME_TIMEOUT)
            except TimeoutError:
                writer.transport.abort()
            except (ConnectionError, OSError):
                pass
            finally:
                self.connections.discard(writer)
                self.tasks.discard(task)


async def run(args):
    identity = ServerIdentity.load(args.key, args.cert)
    server = RelayServer(identity, max_clients=args.max_clients)
    port = await server.start(args.host, args.port)
    print(f'Servidor relay em {args.host}:{port}. Limite: {args.max_clients} clientes.', flush=True)
    try:
        # start_server já está aceitando conexões. Esperar aqui permite que nosso
        # finally feche os clientes antes de wait_closed, inclusive ao receber Ctrl+C.
        await asyncio.Future()
    finally:
        await server.close()


def main():
    parser = argparse.ArgumentParser(description='Servidor de mensageria segura E2E.')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8888)
    parser.add_argument('--key', default='certs/server.key')
    parser.add_argument('--cert', default='certs/server.crt')
    parser.add_argument('--max-clients', type=int, default=20)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(name)s: %(message)s')
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        pass
    except (OSError, ValueError, ProtocolError):
        parser.exit(1, 'Falha ao iniciar. Confira certificado, chave, endereço e parâmetros.\n')


if __name__ == '__main__':
    main()
