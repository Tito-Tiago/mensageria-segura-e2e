"""Interface de terminal. A conversa exibida aqui não é um log de aplicação."""
import argparse
import asyncio
import sys
import uuid
from pathlib import Path

from src.client.connection import SecureClient
from src.common.framing import ProtocolError

HELP = ('/peers: listar | /to NUMERO_OU_UUID: escolher | /send NUMERO_OU_UUID TEXTO\n'
        '/id: seu UUID | /help: ajuda | /quit: sair\n'
        'Após /to, digite o texto diretamente para enviar.')


def select_peer(client, value):
    peers = sorted(client.peers)
    try:
        if value.isdecimal():
            index = int(value) - 1
            if not 0 <= index < len(peers):
                raise ValueError
            return peers[index]
        raw = uuid.UUID(value).bytes
        if raw in client.peers:
            return raw
    except (ValueError, IndexError):
        pass
    raise ProtocolError('destinatário inválido; consulte /peers')


async def display_messages(client):
    while True:
        message = await client.messages.get()
        print(f'\n[{uuid.UUID(bytes=message.sender_id)}] {message.text}', flush=True)


async def display_events(client):
    while True:
        kind, value = await client.events.get()
        if kind in ('joined', 'left'):
            action = 'entrou' if kind == 'joined' else 'saiu'
            print(f'\nPeer {uuid.UUID(bytes=value)} {action}. Use /peers.', flush=True)
        else:
            print(f'\nAviso: {value}', flush=True)


async def read_terminal_line(stdin, disconnected):
    """Espera uma linha ou a queda do servidor, sem deixar leitura pendente."""
    line_task = asyncio.create_task(stdin.readline())
    try:
        done, _ = await asyncio.wait(
            [line_task, disconnected], return_when=asyncio.FIRST_COMPLETED)
        if disconnected in done:
            return None
        raw = line_task.result()
        return raw.decode('utf-8').rstrip('\r\n') if raw else None
    finally:
        if not line_task.done():
            line_task.cancel()
            await asyncio.gather(line_task, return_exceptions=True)


async def execute_command(client, line, selected):
    """Executa uma linha e devolve o destinatário selecionado para a próxima."""
    if line == '/help':
        print(HELP)
    elif line == '/id':
        print(uuid.UUID(bytes=client.client_id))
    elif line == '/peers':
        if not client.peers:
            print('Nenhum outro cliente conectado.')
        for index, peer in enumerate(sorted(client.peers), 1):
            print(f'{index}: {uuid.UUID(bytes=peer)}')
    elif line.startswith('/to '):
        selected = select_peer(client, line[4:].strip())
        print(f'Destinatário: {uuid.UUID(bytes=selected)}')
    elif line.startswith('/send '):
        parts = line.split(' ', 2)
        if len(parts) != 3:
            raise ProtocolError('use /send NUMERO_OU_UUID TEXTO')
        target = select_peer(client, parts[1])
        await client.send_message(target, parts[2])
        print('Mensagem enviada.')
    elif line.startswith('/'):
        raise ProtocolError('comando desconhecido; use /help')
    elif line:
        if selected is None:
            raise ProtocolError('escolha destinatário com /to ou use /send')
        await client.send_message(selected, line)
        print('Mensagem enviada.')
    return selected


async def run(args):
    client_id = uuid.UUID(args.id).bytes if args.id else None
    client = SecureClient(client_id)
    transport = None
    tasks = []
    try:
        await client.connect(args.host, args.port, Path(args.cert).read_bytes())
        print(f'Conectado. Seu UUID: {uuid.UUID(bytes=client.client_id)}\n{HELP}', flush=True)
        # Entrada assíncrona real no Linux/macOS: desconectar não deixa thread input presa.
        stdin = asyncio.StreamReader()
        transport, _ = await asyncio.get_running_loop().connect_read_pipe(
            lambda: asyncio.StreamReaderProtocol(stdin), sys.stdin)
        disconnected = asyncio.create_task(client.closed.wait())
        tasks = [asyncio.create_task(display_messages(client)),
                 asyncio.create_task(display_events(client)), disconnected]
        selected = None
        while not client.closed.is_set():
            print('> ', end='', flush=True)
            line = await read_terminal_line(stdin, disconnected)
            if line is None or line == '/quit':
                break
            try:
                selected = await execute_command(client, line, selected)
            except (ProtocolError, ConnectionError, OSError, TimeoutError) as exc:
                reason = str(exc) if isinstance(exc, ProtocolError) else 'falha de conexão'
                print(f'Aviso: {reason}', flush=True)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if transport:
            transport.close()
        await client.close()
        print('Cliente encerrado.', flush=True)


def main():
    parser = argparse.ArgumentParser(description='Cliente de mensageria E2E (terminal Linux/macOS).')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8888)
    parser.add_argument('--cert', default='certs/server.crt')
    parser.add_argument('--id', help='UUID v4 opcional para testar reconexão')
    args = parser.parse_args()
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        pass
    except (OSError, ValueError, ProtocolError, asyncio.IncompleteReadError, TimeoutError):
        parser.exit(1, 'Falha ao conectar. Confira servidor, certificado pinado e UUID v4.\n')


if __name__ == '__main__':
    main()
