"""Cliente programável usado pela CLI, pelos testes e pela demonstração."""
import asyncio
import uuid
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from src.client.crypto import public_bytes
from src.client.handshake import verify_welcome
from src.client.peers import PeerDirectory
from src.common.framing import ProtocolError, read_frame, write_frame
from src.common.protocol import Kind, PEER_INFO, REGISTER, pack, parse_e2e, unpack, validate_id
from src.server.identity import verify_control


@dataclass
class ReceivedMessage:
    sender_id: bytes
    text: str


class SecureClient:
    def __init__(self, client_id=None):
        self.client_id = validate_id(client_id or uuid.uuid4().bytes)
        self.directory = None
        self.writer = None
        self.receiver = None
        self.write_lock = asyncio.Lock()
        self.messages = asyncio.Queue(maxsize=100)
        self.events = asyncio.Queue(maxsize=100)
        self.closed = asyncio.Event()
        self.closed.set()
        self.seq_control_recv = -1
        self.server_key = None
        self.context = None

    @property
    def peers(self):
        return self.directory.entries if self.directory else {}

    def event(self, kind, value):
        # Telemetria da interface é limitada; eventos não contêm material secreto.
        if self.events.full():
            self.events.get_nowait()
        self.events.put_nowait((kind, value))

    async def connect(self, host, port, pinned_certificate):
        if self.writer is not None:
            raise ProtocolError('cliente já conectado; encerre antes de reconectar')
        self.messages = asyncio.Queue(maxsize=100)
        self.events = asyncio.Queue(maxsize=100)
        self.seq_control_recv = -1
        private = X25519PrivateKey.generate()
        self.directory = PeerDirectory(self.client_id, private)
        public = public_bytes(private)
        self.closed.clear()
        try:
            reader, self.writer = await asyncio.wait_for(asyncio.open_connection(host, port), 10)
            await write_frame(self.writer, pack(Kind.REGISTER, REGISTER.pack(self.client_id, public)), self.write_lock)
            kind, payload = unpack(await asyncio.wait_for(read_frame(reader), 10))
            if kind != Kind.WELCOME:
                raise ProtocolError('resposta de registro inválida')
            self.server_key, self.context = verify_welcome(payload, pinned_certificate, self.client_id, public)
            self.receiver = asyncio.create_task(self.receive_loop(reader))
        except BaseException:
            await self.close()
            raise

    async def close(self):
        writer, self.writer = self.writer, None
        if writer:
            writer.close()
        receiver, self.receiver = self.receiver, None
        if receiver and receiver is not asyncio.current_task():
            receiver.cancel()
            await asyncio.gather(receiver, return_exceptions=True)
        if writer:
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
        if self.directory:
            self.directory.clear()
        self.server_key = None
        self.context = None
        self.closed.set()

    async def wait_for_peer(self, peer_id, timeout=5):
        return await self.directory.wait_for(peer_id, timeout)

    async def send_payload(self, payload):
        """Transmite frame já cifrado; os testes também a usam para bitflip/replay."""
        if self.writer is None or self.closed.is_set():
            raise ProtocolError('conexão encerrada')
        await write_frame(self.writer, pack(Kind.E2E, payload), self.write_lock)

    async def send_message(self, recipient, text):
        if recipient not in self.peers:
            raise ProtocolError('destinatário indisponível')
        payload = self.peers[recipient].encrypt_message(text.encode('utf-8'))
        await self.send_payload(payload)
        return payload  # Frame em memória para testes; nunca é impresso nem persistido.

    async def receive_message(self, timeout=5):
        return await asyncio.wait_for(self.messages.get(), timeout)

    def accept_e2e(self, payload):
        try:
            _, sender, _, _, _ = parse_e2e(payload)
            if sender not in self.peers:
                raise ProtocolError('peer desconhecido')
            plaintext = self.peers[sender].decrypt_message(payload)
            try:
                text = plaintext.decode('utf-8')
            except UnicodeDecodeError as exc:
                raise ProtocolError('texto UTF-8 inválido') from exc
            if self.messages.full():
                # Não bloquear a leitura de controles: encerra sessão sobrecarregada.
                raise ProtocolError('fila de mensagens cheia')
            self.messages.put_nowait(ReceivedMessage(sender, text))
        except ProtocolError as exc:
            if str(exc) == 'fila de mensagens cheia':
                raise
            self.event('rejected', str(exc))

    async def receive_loop(self, reader):
        try:
            while True:
                kind, payload = unpack(await read_frame(reader))
                if kind == Kind.E2E:
                    self.accept_e2e(payload)
                    continue
                if kind not in (Kind.PEER, Kind.LEFT, Kind.ERROR):
                    raise ProtocolError('controle inesperado')
                seq, data = verify_control(self.server_key, kind, payload, self.client_id,
                                           self.context, self.seq_control_recv)
                if kind == Kind.PEER:
                    if len(data) != PEER_INFO.size:
                        raise ProtocolError('anúncio de peer inválido')
                    peer, public, salt = PEER_INFO.unpack(data)
                    self.directory.install(peer, public, salt)
                    self.event('joined', peer)
                elif kind == Kind.LEFT:
                    validate_id(data)
                    self.directory.remove(data)
                    self.event('left', data)
                else:
                    # Erros administrativos são códigos fixos, não conteúdo da conversa.
                    self.event('error', 'destinatário indisponível')
                self.seq_control_recv = seq
        except asyncio.IncompleteReadError:
            self.event('closed', 'servidor desconectado')
        except (ProtocolError, ConnectionError, OSError, TimeoutError) as exc:
            reason = str(exc) if isinstance(exc, ProtocolError) else 'conexão interrompida'
            self.event('closed', reason)
        finally:
            self.directory.clear()
            if self.writer:
                self.writer.close()
            self.closed.set()
