import asyncio
import struct

import pytest

from src.common.framing import MAX_FRAME, ProtocolError, read_frame
from src.common.protocol import Kind, pack, unpack


async def test_fragmentacao_e_frames_agrupados():
    reader = asyncio.StreamReader()
    data = struct.pack('!I', 3) + b'abc' + struct.pack('!I', 2) + b'de'
    task = asyncio.create_task(read_frame(reader))
    for byte in data:
        reader.feed_data(bytes([byte]))
        await asyncio.sleep(0)
    assert await task == b'abc'
    assert await read_frame(reader) == b'de'


@pytest.mark.parametrize('size', [0, 1, MAX_FRAME + 1, 0xffffffff])
async def test_comprimento_invalido(size):
    reader = asyncio.StreamReader()
    reader.feed_data(struct.pack('!I', size))
    with pytest.raises(ProtocolError):
        await read_frame(reader)


async def test_frame_incompleto_timeout():
    reader = asyncio.StreamReader()
    reader.feed_data(b'\x00')
    with pytest.raises(ProtocolError, match='timeout'):
        await read_frame(reader, timeout=0.01)


async def test_eof_no_corpo():
    reader = asyncio.StreamReader()
    reader.feed_data(struct.pack('!I', 10) + b'abc')
    reader.feed_eof()
    with pytest.raises(asyncio.IncompleteReadError):
        await read_frame(reader)


def test_versao_e_tipo():
    assert unpack(pack(Kind.REGISTER, b'dados')) == (Kind.REGISTER, b'dados')
    for invalid in [b'', b'\x02\x01', b'\x01\xff']:
        with pytest.raises(ProtocolError):
            unpack(invalid)


async def test_ociosidade_nao_e_frame_incompleto():
    reader = asyncio.StreamReader()
    task = asyncio.create_task(read_frame(reader, timeout=0.01))
    await asyncio.sleep(0.03)
    assert not task.done()
    reader.feed_data(struct.pack('!I', 2) + b'ok')
    assert await task == b'ok'
