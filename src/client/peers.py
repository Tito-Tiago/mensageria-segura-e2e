"""Tabela de peers e estado efêmero de uma conexão do cliente."""
import asyncio

from src.client.crypto import establish_peer
from src.common.framing import ProtocolError


class PeerDirectory:
    def __init__(self, own_id, private_key):
        self.own_id = own_id
        self.private_key = private_key
        self.entries = {}
        self.public_keys = {}
        self.changed = asyncio.Event()

    def install(self, peer_id, public_key, salt):
        if peer_id in self.entries:
            raise ProtocolError('peer já registrado nesta sessão')
        if len(self.entries) >= 1000:
            raise ProtocolError('limite de peers atingido')
        self.entries[peer_id] = establish_peer(self.private_key, self.own_id, peer_id, public_key, salt)
        self.public_keys[peer_id] = public_key
        self.changed.set()

    def remove(self, peer_id):
        self.entries.pop(peer_id, None)
        self.public_keys.pop(peer_id, None)
        self.changed.set()

    def clear(self):
        self.entries.clear()
        self.public_keys.clear()
        self.private_key = None
        self.changed.set()

    async def wait_for(self, peer_id, timeout=5):
        async with asyncio.timeout(timeout):
            while peer_id not in self.entries:
                if self.private_key is None:
                    raise ProtocolError('conexão encerrada')
                self.changed.clear()
                await self.changed.wait()
        return self.entries[peer_id]
