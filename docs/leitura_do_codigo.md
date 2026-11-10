# Como entender o projeto

O projeto tem três partes: o terminal recebe comandos, o cliente protege as mensagens e o servidor encaminha os bytes cifrados. Comece pelo caminho de uma mensagem; depois estude os detalhes do registro e do formato binário.

## 1. Enviar uma mensagem

Leia nesta ordem:

1. `src/client/main.py`: `execute_command` interpreta `/to`, `/send` ou texto digitado. Retorna o destinatário selecionado para a próxima linha.
2. `src/client/connection.py`: `send_message` encontra o estado do destinatário e converte o texto para UTF-8.
3. `src/client/crypto.py`: `encrypt_message` reserva o contador, monta nonce/AAD e cifra com AES-GCM.
4. `src/server/main.py`: `relay` confere o remetente e encaminha o corpo cifrado ao destinatário.
5. `src/client/connection.py`: `receive_loop` distingue conversa de controle; `accept_e2e` seleciona o remetente e entrega o texto validado à fila da interface.
6. `src/client/crypto.py`: `decrypt_message` verifica IDs, replay, IV e tag antes de atualizar o estado.

## 2. Entender como as chaves chegam aos clientes

Leia `SecureClient.connect → RelayServer.register → verify_welcome → accept_control → PeerDirectory.install → derive_peer_keys`.

- O cliente gera sua chave privada X25519 localmente e envia a pública.
- O servidor responde com certificado e assinatura; o cliente verifica o pin e a assinatura.
- O servidor anuncia as chaves públicas dos peers em controles assinados.
- Cada cliente combina sua privada com a pública do peer e deriva duas chaves AES com HKDF, uma por sentido.

A chave AES de envio de A corresponde à chave AES de recepção de B. O servidor guarda as chaves públicas, sem as privadas dos clientes ou as chaves AES.

## 3. Entender o terminal

Em `src/client/main.py`, cada função tem um papel:

| Função | Papel |
|---|---|
| `run` | Conectar, repetir leitura/comando e encerrar |
| `read_terminal_line` | Esperar uma linha ou a desconexão do servidor |
| `execute_command` | Interpretar comandos e enviar texto |
| `select_peer` | Resolver número ou UUID do destinatário |
| `display_messages` / `display_events` | Mostrar conversas e avisos |

A leitura assíncrona permite receber mensagens enquanto alguém digita e encerrar quando o servidor cai.

## Requisitos preservados

| Exigência do PDF | Onde conferir |
|---|---|
| Múltiplos clientes e relay sem decifragem | `RelayServer.register`, `relay` e `sessions` |
| Autenticação RSA-PSS e certificado pinado | `ServerIdentity.welcome` e `verify_welcome` |
| X25519 efêmero e HKDF-SHA256 | `SecureClient.connect` e `derive_peer_keys` |
| AES-128-GCM, nonce de 12 bytes e AAD | `PeerCipher.encrypt_message` e `decrypt_message` |
| Contador monotônico e rejeição de replay | `PeerCipher.seq_send`, `seq_recv` e `decrypt_message` |
| Framing com prefixo de 4 bytes | `src/common/framing.py` |
| Reconexão com novas chaves | `SecureClient.connect` e `PeerDirectory.clear` |
| Limite de 4096 bytes e logs sem segredos | `MAX_PLAINTEXT`, `encrypt_message` e logs do relay |
| Demonstrações de E2E, adulteração, replay e framing | `scripts/demonstrar_falhas.py` |

Os detalhes ambíguos do enunciado (formato da chave RSA, salt comum ao par e IV de recepção) continuam explicados em [protocolo.md](protocolo.md).

## O que a simplificação mudou

Funções menores separam a leitura do terminal, a interpretação dos comandos e a aplicação dos controles assinados. No recebimento, mensagens inválidas são descartadas; fila cheia gera um erro que encerra a conexão, sem precisar comparar o texto de exceções.

As proteções criptográficas, os formatos dos frames, os comandos e as demonstrações foram preservados. A simplificação é na organização da leitura; o número total de linhas pode crescer um pouco ao dar nomes próprios a cada etapa.
