# Pessoa 2 — cliente e criptografia ponta a ponta

Sua responsabilidade é explicar como dois clientes estabelecem chaves e como a conversa é cifrada, autenticada e protegida contra replay. Você não precisa desenvolver nada. Acompanhe as funções no código e ensaie os comandos prontos.

## A ideia em um minuto

A gera uma chave privada X25519 e publica a correspondente chave pública. B faz o mesmo. A combina sua privada com a pública de B; B combina sua privada com a pública de A. Ambos obtêm o mesmo segredo Z sem transmiti-lo. O HKDF transforma Z em duas chaves AES distintas, uma para cada sentido. AES-GCM cifra a mensagem e autentica também os IDs e o contador. O contador permite rejeitar reenvios.

## Ordem de leitura do código

| Ordem | Arquivo | Funções/classes a acompanhar | O que entender |
|---|---|---|---|
| 1 | [connection.py](../src/client/connection.py) | `SecureClient.connect` | Chave efêmera nova e início da conexão |
| 2 | [crypto.py](../src/client/crypto.py) | `public_bytes`, `derive_peer_keys`, `establish_peer` | X25519, PRK e HKDF por direção |
| 3 | [peers.py](../src/client/peers.py) | `PeerDirectory.install`, `remove`, `clear` | Estado por peer e descarte na saída |
| 4 | [crypto.py](../src/client/crypto.py) | `PeerCipher.encrypt_message` | Reserva de contador, nonce, AAD e AES-GCM |
| 5 | [protocol.py](../src/common/protocol.py) | `E2E_HEADER`, `parse_e2e`, `aad` | Campos e validações públicas do frame |
| 6 | [crypto.py](../src/client/crypto.py) | `PeerCipher.decrypt_message` | Anti-replay, tag e atualização segura de estado |
| 7 | [connection.py](../src/client/connection.py) | `send_message`, `accept_e2e`, `receive_loop`, `close` | Integração da rede e da criptografia |
| 8 | [main.py do cliente](../src/client/main.py) | `run`, `select_peer`, `display_messages` | Comandos e entrada/saída simultâneas |
| 9 | [demonstrar_falhas.py](../scripts/demonstrar_falhas.py) | `demo` | Frames adulterados/repetidos apenas em memória |

## Como A e B concordam nas direções

O nome A não depende de quem abriu a conversa: A é quem tem o menor UUID binário. Ambos conhecem os UUIDs e chegam à mesma ordem.

```text
A envia com Key_A2B  -> B recebe com Key_A2B
B envia com Key_B2A  -> A recebe com Key_B2A
```

`derive_peer_keys` faz X25519, usa HMAC-SHA256 para HKDF-Extract e `HKDFExpand` para os labels `A2B` e `B2A`. O salt do par é o mesmo nos dois lados e vem em um controle assinado. Z e PRK são intermediários, não campos persistentes da tabela.

## Caminho de uma mensagem

1. `/to` escolhe destinatário ou `/send` informa diretamente o UUID/número.
2. `SecureClient.send_message` codifica texto UTF-8 e encontra o `PeerCipher` do destinatário.
3. `encrypt_message` verifica o limite de bytes e reserva um contador que não será reutilizado.
4. Monta `nonce = IV_base(4) || seq_no(8)` e `AAD = sender_id || recipient_id || seq_no`.
5. `AESGCM.encrypt` retorna ciphertext com tag de 16 bytes ao final.
6. `send_payload` envia E2E ao relay. O relay encaminha o mesmo corpo cifrado.
7. No destino, `receive_loop` entrega o corpo a `accept_e2e`, que seleciona o peer remetente.
8. `decrypt_message` confere estrutura, IDs, contador, IV e tag. Só após a autenticação fixa o IV de recepção e avança `seq_recv`.
9. `accept_e2e` decodifica o texto validado e o coloca na fila da interface. `display_messages` o mostra.

A confirmação “Mensagem enviada” significa que o frame foi enviado ao relay; não é um recibo de leitura/entrega do destinatário. A demonstração confirma a recepção observando o cliente destinatário.

## Três trechos para apresentar

### 1. Derivação

Abra `derive_peer_keys`. A chave privada fica local; a pública é recebida do peer. O resultado de `exchange` é entrada do HKDF, não uma chave AES escolhida diretamente. Mostre os labels e a ordem dos UUIDs.

Fala sugerida: “Os dois lados calculam o mesmo segredo com combinações diferentes de chave privada e pública. O servidor vê apenas as públicas. Derivamos duas chaves para separar os sentidos da conversa.”

### 2. Cifragem

Abra `encrypt_message`. Mostre o contador reservado antes da cifragem, o nonce de 12 bytes e o AAD. O prefixo aleatório permanece por direção/sessão; o contador muda em cada envio.

Fala sugerida: “A mensagem fica cifrada. Os IDs e o contador continuam visíveis para o roteamento, mas entram no AAD: alterá-los impede autenticar a mensagem. O nonce nunca pode se repetir com a mesma chave.”

### 3. Validação

Abra `decrypt_message`. Mostre a rejeição de replay, a chamada de decifragem e a atualização do estado depois dela. Um pacote adulterado com contador enorme não pode avançar `seq_recv`.

Fala sugerida: “A tag detecta adulteração, mas um replay tem uma tag legítima. Precisamos também recusar contadores já aceitos. Só alteramos o estado depois de autenticar o frame.”

## A tabela de peers

`PeerDirectory.entries` mapeia o UUID de cada peer para um `PeerCipher`, com `key_send`, `key_recv`, `seq_send`, `seq_recv`, `iv_send` e `iv_recv`. `public_keys` guarda as chaves públicas correspondentes. Cada par tem seu próprio estado.

O IV de recepção começa desconhecido e é aprendido do primeiro frame com tag válida. Sortear um IV independente para receber faria os lados discordarem. Ao sair um peer, sua entrada é removida; ao reconectar, novo X25519 e novos salts geram outras chaves.

## Perguntas prováveis e respostas

1. **Como os clientes obtêm o mesmo segredo sem enviá-lo?** A usa `sk_A` com `pk_B`, B usa `sk_B` com `pk_A`. X25519 produz o mesmo Z. Veja `derive_peer_keys`.
2. **Por que usar HKDF depois do ECDH?** Para derivar chaves de tamanho adequado, incorporando salt e separando usos com labels. Veja HKDF-Extract/Expand em `derive_peer_keys`.
3. **Salt é uma senha ou chave secreta?** Não. É parâmetro da derivação. Os dois peers precisam usar o mesmo valor; neste trabalho ele não é registrado nos logs.
4. **Por que há duas chaves?** Para separar A→B de B→A. A chave de envio de um lado corresponde à chave de recepção do outro. Veja a comparação dos UUIDs.
5. **O que é AAD?** Metadados autenticados sem cifragem. Aqui são remetente, destinatário e contador. Veja `aad` e as chamadas AES-GCM.
6. **O que acontece se repetir nonce?** Reutilizar nonce com a mesma chave compromete a segurança de GCM. Por isso há contador monotônico, reserva de números e nova sessão antes de reiniciar. Veja `encrypt_message`.
7. **A tag sozinha bloqueia replay?** Não. O frame repetido conserva tag válida; a checagem de `seq_recv` o rejeita. Veja `decrypt_message`.
8. **Por que atualizar contador só depois da tag?** Um atacante poderia forjar contador alto e impedir mensagens futuras se o estado fosse atualizado antes de autenticar. Veja a ordem no final de `decrypt_message`.
9. **Quem cria o IV de recepção?** O remetente gera o prefixo de envio; o destinatário o aprende do primeiro frame autenticado e o fixa. Veja `iv_recv`.
10. **O que acontece na reconexão?** Há novo handshake, chave X25519, salts e IVs. O mesmo UUID não implica reutilizar chaves. Veja `connect`, `PeerDirectory.clear` e o teste de reconexão.
11. **Por que o comprometimento futuro da RSA não revela as conversas?** RSA só autentica; as chaves AES dependem das privadas X25519 efêmeras dos clientes. Isso exige que o estado antigo seja descartado e não protege um cliente ativo comprometido.
12. **Um terceiro cliente pode decifrar?** Não com suas chaves de outros pares. A demonstração tenta autenticar o frame A-B com a chave de C e recebe falha GCM. Não se trata de resistência a um servidor malicioso que substitua chaves.

## Comandos da sua parte

Com o servidor manual iniciado pelo outro integrante, abra dois ou três clientes, um em cada terminal:

```bash
.venv/bin/python -m src.client.main
```

Selecione o destinatário pelo UUID exibido:

```text
/peers
/to 1
Olá!
```

Para a validação de segurança, em outro terminal:

```bash
.venv/bin/python -m scripts.demonstrar_falhas --cenario adulteracao
.venv/bin/python -m scripts.demonstrar_falhas --cenario replay
.venv/bin/python -m scripts.demonstrar_falhas --cenario reconexao
```

Cada comando cria seu próprio ambiente TCP descartável com os mesmos módulos. Abra também `demo` para mostrar onde o bit é invertido ou o frame é reenviado. Não imprima chaves ou frames para explicar o teste.

## Conferência antes de apresentar

Você está pronto quando consegue seguir `connect → install → derive_peer_keys → encrypt_message → send_payload → accept_e2e → decrypt_message`, explicar nonce/AAD/contador e reproduzir as falhas. Para cada função, diga o que recebe, o que valida, o que altera e qual falha impede.

Glossário: E2E = ponta a ponta; ECDH = acordo de segredo; efêmera = chave renovada por conexão; HKDF = derivação de chaves; nonce = valor que não se repete sob a mesma chave; tag = autenticador; replay = repetição de frame; forward secrecy = proteção de sessões passadas contra comprometimento futuro da chave de autenticação, nas condições do modelo.
