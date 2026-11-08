"""TCP é um fluxo: prefixamos cada mensagem com seu tamanho big-endian."""
import asyncio
import struct

MAX_FRAME = 65536
FRAME_TIMEOUT = 10.0


class ProtocolError(Exception):
    """Erro público e seguro: nunca incluir payloads ou segredos na mensagem."""


async def read_frame(reader, *, timeout=FRAME_TIMEOUT):
    # Sem timeout enquanto o cliente está ocioso; o prazo começa ao chegar o 1º byte.
    first = await reader.readexactly(1)
    try:
        async with asyncio.timeout(timeout):
            header = first + await reader.readexactly(3)
            size = struct.unpack('!I', header)[0]
            if not 2 <= size <= MAX_FRAME:
                raise ProtocolError('framing inválido')
            return await reader.readexactly(size)
    except TimeoutError as exc:
        raise ProtocolError('frame incompleto: timeout') from exc


async def write_frame(writer, body, lock):
    if not 2 <= len(body) <= MAX_FRAME:
        raise ProtocolError('framing inválido')
    async with lock:
        writer.write(struct.pack('!I', len(body)) + body)
        # Também limita o tempo de espera por um destinatário lento.
        await asyncio.wait_for(writer.drain(), FRAME_TIMEOUT)
