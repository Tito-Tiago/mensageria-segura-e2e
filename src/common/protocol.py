"""Contrato binário compartilhado. Inteiros são sempre big-endian."""
import struct
import uuid
from enum import IntEnum

from src.common.framing import ProtocolError

VERSION = 1
MAX_PLAINTEXT = 4096
MAX_SEQ = (1 << 64) - 1
E2E_HEADER = struct.Struct('!12s16s16sQ')
CONTROL_HEADER = struct.Struct('!16s32sQ')  # destino, contexto da conexão, seq
REGISTER = struct.Struct('!16s32s')
PEER_INFO = struct.Struct('!16s32s16s')  # UUID, X25519 raw, salt do par


class Kind(IntEnum):
    REGISTER = 1
    WELCOME = 2
    PEER = 3
    LEFT = 4
    ERROR = 5
    E2E = 6


def pack(kind, payload):
    return bytes((VERSION, kind)) + payload


def unpack(body):
    if len(body) < 2 or body[0] != VERSION:
        raise ProtocolError('versão ou envelope inválido')
    try:
        return Kind(body[1]), body[2:]
    except ValueError as exc:
        raise ProtocolError('tipo desconhecido') from exc


def validate_id(raw):
    if len(raw) != 16:
        raise ProtocolError('UUID inválido')
    value = uuid.UUID(bytes=raw)
    if value.version != 4 or value.variant != uuid.RFC_4122:
        raise ProtocolError('UUID deve ser v4')
    return raw


def encode_blob(data):
    if len(data) > 65535:
        raise ProtocolError('campo excede limite')
    return struct.pack('!H', len(data)) + data


def decode_blob(data, offset=0):
    if offset + 2 > len(data):
        raise ProtocolError('campo truncado')
    size = struct.unpack_from('!H', data, offset)[0]
    end = offset + 2 + size
    if end > len(data):
        raise ProtocolError('campo truncado')
    return data[offset + 2:end], end


def parse_e2e(payload):
    if not E2E_HEADER.size + 16 <= len(payload) <= E2E_HEADER.size + 16 + MAX_PLAINTEXT:
        raise ProtocolError('tamanho E2E inválido')
    nonce, sender, recipient, seq = E2E_HEADER.unpack_from(payload)
    validate_id(sender)
    validate_id(recipient)
    if sender == recipient:
        raise ProtocolError('destinatário igual ao remetente')
    if nonce[4:] != seq.to_bytes(8, 'big'):
        raise ProtocolError('nonce incompatível com contador')
    return nonce, sender, recipient, seq, payload[E2E_HEADER.size:]


def aad(sender, recipient, seq):
    return sender + recipient + seq.to_bytes(8, 'big')
