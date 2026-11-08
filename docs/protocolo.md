# Especificação do protocolo TP3, versão 1

Esta especificação descreve o código efetivamente implementado. O enunciado pede UUID v4, X25519 raw, RSA-PSS, HKDF-SHA256, AES-128-GCM, framing e testes de segurança; envelope, serialização RSA, controles assinados e coordenação dos pares são decisões do projeto.

## Modelo de confiança

Os clientes possuem previamente uma cópia confiável do certificado autoassinado do servidor. O relay é confiável para anunciar chaves corretamente, mas não recebe chaves privadas X25519 nem chaves AES das conversas. Não há autenticação de identidades pessoais dos clientes. Um UUID é um identificador escolhido pelo cliente e único entre conexões ativas.

## Transporte

Todos os inteiros são unsigned big-endian. UUIDs são 16 bytes binários RFC 4122, versão 4. Chaves públicas X25519 têm 32 bytes raw.

```text
uint32 tamanho_do_envelope
uint8 versão = 1
uint8 tipo
bytes payload
```

O tamanho inclui versão/tipo e payload, excluindo os 4 bytes do próprio prefixo. Envelope mínimo: 2 bytes. Máximo global: 65536 bytes, validado antes da leitura do corpo. Tipos e seus tamanhos internos são validados adicionalmente.

`read_frame` aceita fragmentação e múltiplos frames consecutivos. O prazo de 10 segundos começa no primeiro byte do frame; ficar ocioso entre frames não causa desconexão. O registro inicial tem, adicionalmente, prazo total de 10 segundos. Escritas são serializadas por conexão e `drain` tem limite de 10 segundos.

Um blob variável é `uint16 comprimento || bytes`. A representação assinada é binária, sem JSON ou ordem de dicionário.

| Tipo | Valor | Direção | Payload |
|---|---|---|---|
| REGISTER | 1 | Cliente → servidor | UUID(16) + X25519(32) |
| WELCOME | 2 | Servidor → cliente | Chave RSA, certificado, salt e assinatura |
| PEER | 3 | Servidor → cliente | Controle assinado com UUID(16), X25519(32), salt_par(16) |
| LEFT | 4 | Servidor → cliente | Controle assinado com UUID que saiu(16) |
| ERROR | 5 | Servidor → cliente | Controle assinado com código de erro |
| E2E | 6 | Cliente → servidor → cliente | Corpo cifrado descrito abaixo |

Depois de REGISTER, o servidor aceita apenas E2E. Mensagens inválidas, UUID duplicado ativo e chave de baixa ordem encerram a conexão ofensora. Antes de concluir o registro não existe contexto autenticado para enviar ERROR; a rejeição ocorre por desconexão.

## Registro e WELCOME

1. Cliente gera uma chave privada X25519 nova e envia apenas seu UUID e a chave pública raw.
2. Servidor valida o registro, inclusive rejeitando pontos X25519 de baixa ordem, e cria `salt_handshake` aleatório de 16 bytes.
3. Servidor monta:

```text
blob(pk_server_RSA_DER_SPKI)
blob(server_certificate_PEM)
salt_handshake(16)
blob(assinatura_RSA_PSS)
```

4. O digest assinado é `SHA256(pk_server_RSA_DER_SPKI || pk_client_X25519_raw || client_id || salt_handshake)`.
5. A assinatura usa RSA de 2048 bits, PSS com MGF1/SHA-256, salt PSS de 32 bytes e `Prehashed(SHA256)`. O salt do PSS é próprio do esquema de assinatura e não é o salt de HKDF.
6. Cliente compara exatamente o certificado recebido com o pin, confere validade, RSA de pelo menos 2048 bits, autoassinatura e correspondência da chave DER. Verifica a assinatura contra seu próprio registro.
7. Ambos calculam `context = SHA256("TP3-session-v1\0" || client_id || pk_client_raw || salt_handshake)`.

**Ambiguidade resolvida:** o PDF define `pk_server` como RSA, mas também menciona uma chave efêmera do servidor e bytes raw sem especificar seu papel/formato. A implementação usa a definição RSA com DER/SPKI. A troca ECDH das conversas é exclusivamente cliente-cliente; não há uma segunda chave ECDH do servidor para conversar com os clientes.

## Controles autenticados

PEER, LEFT e ERROR usam:

```text
recipient_id(16) || context(32) || seq_control(8) || blob(data) || blob(signature)
```

A assinatura RSA-PSS/SHA-256 cobre:

```text
"TP3-control-v1\0" || versão || tipo || recipient_id || context || seq_control || blob(data)
```

No cliente: validar destino, contexto, contador maior que o último, estrutura e assinatura antes de aplicar a atualização. Só depois atualizar `seq_control_recv`. O contador inicial do servidor é zero; o último recebido no cliente começa em menos um. A chave X25519 nova e o salt novo vinculam o contexto à conexão atual, impedindo aplicar controles antigos ao reconectar.

`Session.seq_send` representa o próximo controle do servidor. `Session.seq_recv = -1` fica reservado: esta versão não define controles incrementais cliente-servidor além do registro. O relay não usa um contador global E2E do cliente, pois cada par/direção tem contador próprio no destinatário.

## Rendezvous e HKDF

Quando um cliente entra, o servidor anuncia seus peers e o anuncia aos existentes. Cada par recebe o mesmo `salt_par` aleatório de 16 bytes, diferente dos salts individuais de handshake. Novos pares não alteram o estado dos pares já ativos.

**Ambiguidade resolvida:** salts individuais diferentes produziriam chaves incompatíveis entre peers; por isso o projeto acrescenta um salt por estabelecimento de par, distribuído em controles assinados. Salt não é uma chave e não precisa ser secreto, mas não é impresso nos logs, conforme a política do PDF.

Ordenar UUIDs binários: menor é A, maior é B. Derivar:

```text
Z_AB = X25519(sk_A, pk_B) = X25519(sk_B, pk_A)
PRK = HMAC-SHA256(key=salt_par, data=Z_AB)
Key_A2B = HKDF-Expand(PRK, info=ASCII "A2B", length=16)
Key_B2A = HKDF-Expand(PRK, info=ASCII "B2A", length=16)
```

A usa A2B para enviar e B2A para receber; B faz o inverso. Z e PRK não permanecem na tabela. A chave privada X25519 fica no cliente durante sua conexão, para estabelecer pares com novos participantes.

## Corpo E2E

```text
nonce(12) || sender_id(16) || recipient_id(16) || seq_no(8) || ciphertext || tag(16)
nonce = IV_base(4) || seq_no(8)
AAD = sender_id || recipient_id || seq_no
```

Texto é UTF-8, até 4096 bytes. Cabeçalho fixo: 52 bytes; corpo com tag: 68 a 4164 bytes. Envelope completo: 70 a 4166 bytes; com prefixo TCP: 74 a 4170 bytes.

Cada direção de cada par tem uma chave diferente, um IV base aleatório e um contador. O primeiro envio usa zero. O próximo número é reservado antes da cifragem; número reservado nunca é reutilizado. Após `2^64 - 1`, é necessário novo estabelecimento.

**Ambiguidade resolvida:** o IV de recepção precisa ser o IV de envio do peer. Ele é aprendido do primeiro frame com tag válida; não é sorteado independentemente. O receptor confere os últimos 8 bytes do nonce contra o contador e, após fixar o prefixo, rejeita mudanças de IV dentro daquela sessão.

Ordem de recepção: conferir tamanho/UUIDs/nonce, identificar o peer/destino, rejeitar contador antigo, conferir IV estabelecido, verificar GCM, fixar IV e avançar contador. Um frame com contador alto e tag inválida não altera o estado. Tags não substituem a checagem de replay: um frame legítimo repetido ainda tem tag legítima.

## Estado e concorrência

- `RelayServer.sessions`: UUID → conexão, chave pública, contexto, salt de registro e contadores administrativos; sem Z/chaves AES.
- `PeerDirectory.entries`: UUID do peer → `PeerCipher`, com chaves, IVs e contadores E2E. `public_keys` mantém as chaves públicas correspondentes.
- Lock de membros coordena entrada/saída e anúncios; locks por conexão coordenam escritas. Controles reservam contador e escrevem sob o mesmo lock administrativo.
- Filas do cliente são limitadas a 100 mensagens e 100 eventos. Fila de conversas cheia encerra a sessão; a fila de eventos descarta o evento mais antigo.
- Limite padrão: 20 conexões aceitas pelo handler, incluindo conexões ainda sem registro; parâmetro configurável.

O servidor confere que o remetente do E2E pertence ao socket e encaminha o mesmo payload para o destinatário. O cabeçalho é público; o servidor não verifica tag nem decifra. Replay é bloqueado pelo cliente destinatário.

## Saída, falhas e reconexão

Na saída, o servidor remove a sessão e envia LEFT autenticado. Os clientes removem o estado do peer. Reconectar com o mesmo UUID requer novo par X25519, handshake e salts de pares; frames antigos deixam de autenticar. UUID ainda ativo é recusado sem remover o original.

Ao encerrar o servidor, primeiro fechar o listener para novas conexões e abortar os transportes ativos, aguardar os handlers e só então esperar o listener terminar. Abortar descarta dados pendentes: o encerramento não promete sua entrega. Somente chamar `close` pode bloquear esperando um destinatário que não lê. Falhas de escrita e de notificação também abortam o transporte; no fechamento normal de um handler, `wait_closed` tem prazo de 10 segundos e aborta ao excedê-lo. A conexão permanece rastreada até terminar essa limpeza. Essa ordem evita bloquear `wait_closed` no Python 3.12 com transportes ativos. A CLI usa entrada assíncrona para sair se o servidor cair mesmo quando ninguém pressiona Enter.

O cliente pode continuar após rejeitar um E2E adulterado/repetido. Controle inválido é falha de autenticação do canal administrativo e encerra a conexão. Tamanho inválido encerra somente a conexão ofensora.

## Logs e limites das garantias

Não registrar chaves privadas, Z, PRK, chaves AES, salts, nonces ou conversas. Logs permitidos: conexão/saída, UUID, tamanho e razão de rejeição. Ferramentas de teste manipulam frames apenas em memória. Vetores públicos de teste no código são identificados como tais e não são usados pelas sessões reais.

O certificado autentica o servidor; não certifica identidades pessoais dos clientes. GCM autentica em relação à chave compartilhada, sem produzir assinatura individual ou prova de autoria perante terceiros. Um servidor malicioso que substitua chaves fica fora do modelo. IDs e padrões de tráfego permanecem visíveis.

Chaves efêmeras descartadas impedem que o comprometimento futuro apenas da chave RSA revele sessões passadas. Não existe ratchet por mensagem nem garantia contra comprometimento dos clientes ativos. Limpar referências em Python não garante apagar fisicamente toda cópia de memória.

## Referências

- [X25519 em cryptography](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/x25519/).
- [RSA-PSS e Prehashed em cryptography](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/).
- [AES-GCM em cryptography](https://cryptography.io/en/latest/hazmat/primitives/aead/).
- [RFC 5869: HKDF](https://www.rfc-editor.org/rfc/rfc5869.html).
- [RFC 7748, seção 6.1: vetor público usado nos testes](https://www.rfc-editor.org/rfc/rfc7748.html#section-6.1).
