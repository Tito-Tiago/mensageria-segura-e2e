# Pessoa 1 — servidor, rede e autenticação

Sua responsabilidade é explicar como o sistema aceita vários clientes, autentica o servidor, distribui chaves públicas e encaminha frames. Você não precisa desenvolver nada. Leia este guia com os arquivos abertos e execute os comandos prontos.

## A ideia em um minuto

O servidor é um ponto de encontro. Cada cliente gera sua própria chave X25519 e envia apenas a pública. O servidor comprova sua identidade com RSA e um certificado que o cliente já conhece. Depois anuncia as chaves públicas dos participantes por mensagens assinadas. A e B derivam suas chaves AES localmente; o servidor apenas lê o destinatário e encaminha o corpo cifrado.

O certificado autentica o servidor, não a identidade pessoal de cada aluno. O diretório pressupõe um servidor confiável para anunciar as chaves certas.

## Ordem de leitura do código

| Ordem | Arquivo | Funções/classes a acompanhar | O que entender |
|---|---|---|---|
| 1 | [protocol.py](../src/common/protocol.py) | `Kind`, `pack`, `unpack`, `REGISTER`, `PEER_INFO` | Tipos e formatos compartilhados |
| 2 | [framing.py](../src/common/framing.py) | `read_frame`, `write_frame` | Prefixo de tamanho e limites do TCP |
| 3 | [identity.py](../src/server/identity.py) | `ServerIdentity.generate`, `save`, `load` | RSA, certificado e chave privada local |
| 4 | [identity.py](../src/server/identity.py) | `welcome`, `transcript_hash`, `context_id` | Registro assinado e contexto da conexão |
| 5 | [handshake.py](../src/client/handshake.py) | `verify_welcome` | Pinning e verificação no cliente |
| 6 | [main.py do servidor](../src/server/main.py) | `Session`, `register`, `send_control`, `notify` | Tabela de sessões e anúncios autenticados |
| 7 | [identity.py](../src/server/identity.py) | `control`, `verify_control` | Proteção das atualizações administrativas |
| 8 | [main.py do servidor](../src/server/main.py) | `relay`, `handle`, `close`, `run` | Encaminhamento, erros e encerramento |

## Caminho do registro no código

1. `RelayServer.start` cria o listener TCP e o `asyncio` chama `handle` para cada conexão.
2. `handle` aplica o limite de conexões e pede a `register` que leia o primeiro frame.
3. `read_frame` lê o tamanho e depois exatamente o corpo. `unpack` confere versão e tipo.
4. `register` exige UUID v4 e X25519 raw de 32 bytes, recusa chave de baixa ordem e UUID já ativo.
5. `ServerIdentity.welcome` assina o hash que vincula a chave RSA, a chave pública do cliente, o UUID e o salt de registro.
6. No cliente, `verify_welcome` compara o certificado ao pin, valida os campos e verifica a assinatura contra os dados que o próprio cliente enviou.
7. O servidor registra a sessão e envia PEER assinado aos dois lados de cada par, com o mesmo salt do par.
8. `verify_control` no cliente confere destino, contexto, sequência e assinatura antes de aceitar o anúncio.

O salt do handshake vincula o contexto de registro. O salt do par é um valor separado, igual para os dois peers, usado no HKDF deles.

## Três trechos para apresentar

### 1. Framing

Abra `read_frame`. O primeiro byte inicia o prazo para terminar o frame; os outros três completam o prefixo de tamanho. A função rejeita tamanho menor que 2 ou maior que 65536 antes de ler o corpo. O `readexactly` resolve a fragmentação do TCP. O cliente pode ficar ocioso entre frames.

Fala sugerida: “O TCP transporta um fluxo de bytes. Um recebimento não corresponde necessariamente a uma mensagem. Por isso lemos quatro bytes de tamanho e depois o corpo completo, com limite e timeout.”

### 2. Autenticação

Abra `welcome` e `verify_welcome`. Mostre o hash do transcript, RSA-PSS e a comparação com o certificado pinado. `Prehashed` indica que o hash H já foi calculado. A autoassinatura do certificado é verificada, mas a confiança vem da distribuição prévia do pin.

Fala sugerida: “O cliente não confia em qualquer certificado recebido. Ele compara com a cópia previamente configurada e verifica a assinatura sobre seu registro. Uma mudança na chave pública ou no UUID faz a verificação falhar.”

### 3. Relay

Abra `relay`. `parse_e2e` confere a estrutura pública. O servidor verifica o remetente contra a conexão, procura `recipient_id` em `sessions` e chama `write_frame` com o mesmo payload. Não existe chamada a AES-GCM nesse caminho.

Fala sugerida: “O servidor sabe quem envia, para quem e o tamanho. Ele não tem a chave privada X25519 dos clientes nem a chave AES e, portanto, não decifra o corpo da conversa.”

## Estrutura de dados que você deve explicar

`Session` contém `client_id`, `public_key`, `writer`, contexto, salt de registro, contador administrativo e locks. O `seq_send` é de controles do servidor. `seq_recv` está reservado nesta versão, pois não há uma sequência de controles cliente-servidor após o registro.

Os contadores E2E ficam nos clientes e são separados por par/direção. Um contador global no servidor confundiria conversas diferentes. O lock de membros coordena anúncios/saídas e o lock de escrita evita intercalar frames concorrentes.

## Perguntas prováveis e respostas

1. **Por que usar framing se o TCP já é confiável?** TCP entrega bytes em ordem, mas não preserva os limites das mensagens. Veja `read_frame`.
2. **Como um certificado autoassinado pode ser confiável?** Pela comparação com o certificado previamente distribuído por canal confiável. Autoassinatura sozinha não identifica o servidor esperado. Veja `verify_welcome`.
3. **RSA está cifrando a conversa?** Não. RSA-PSS autentica handshake e controles; AES-GCM cifra a conversa entre clientes. Veja `welcome` e `relay`.
4. **O que é assinado no handshake?** O hash da chave RSA serializada, chave X25519 do cliente, UUID e salt de registro, nessa ordem. Veja `transcript_hash`.
5. **Por que assinar também a lista de peers?** Uma assinatura inicial não protege atualizações posteriores. Cada controle vincula conteúdo, tipo, destino, contexto e contador. Veja `control`.
6. **O servidor pode fingir ser outro cliente?** O modelo confia nele para distribuir chaves. Não há verificação independente contra substituição maliciosa pelo próprio servidor; não devemos prometer isso.
7. **Como evitamos um cliente enviar usando o UUID de outro?** O relay compara `sender_id` com o UUID registrado naquele socket. Isso não equivale a autenticar uma identidade pessoal. Veja `relay`.
8. **O que ocorre com UUID duplicado?** A segunda conexão é recusada e a primeira permanece ativa. Veja `register` e o `finally` de `handle`.
9. **O que ocorre com framing inválido?** A conexão ofensora é encerrada; as demais sessões continuam funcionando. Veja `read_frame` e `handle`.
10. **Como o servidor atende vários clientes?** `asyncio` coordena tarefas de I/O concorrentes. Há locks para mudanças compartilhadas e escrita por socket. Veja `start`, `register` e `write_frame`.
11. **Quais dados podem aparecer nos logs?** Eventos, UUIDs, tamanhos e razões de rejeição. Não chaves, segredos, salts, nonces ou conversas. Veja chamadas a `LOG.info`.
12. **Como a aplicação encerra sem travar?** Fecha sockets ativos antes de aguardar o listener. A CLI não depende de uma thread bloqueada em `input`. Veja `RelayServer.close`, `run` e os testes de CLI.

## Comandos da sua parte

Na raiz do projeto, com dependências e identidade já preparadas:

```bash
.venv/bin/python -m src.server.main
```

O outro integrante abre os clientes. Mostre os logs de conexão/roteamento, sem despejar o conteúdo dos frames. Para demonstrar framing e pinning, em outro terminal:

```bash
.venv/bin/python -m scripts.demonstrar_falhas --cenario framing
.venv/bin/python -m scripts.demonstrar_falhas --cenario pinning
```

Esses comandos criam um ambiente TCP separado e descartável com os mesmos módulos; não atacam o servidor manual. Explique essa separação. Ao final, encerre clientes com `/quit` e servidor com Ctrl+C.

## Conferência antes de apresentar

Você está pronto quando consegue seguir `read_frame → register → welcome → verify_welcome → control/verify_control → relay`, explicar a tabela de sessões e reproduzir a demonstração. Para cada função, diga o que recebe, o que valida, o que altera e qual falha impede.

Glossário: relay = encaminhador; framing = delimitação de mensagens; pin = cópia confiável do certificado; transcript = bytes vinculados pela assinatura; contexto = identificador da conexão atual; rendezvous = distribuição das informações necessárias para os peers se encontrarem.
