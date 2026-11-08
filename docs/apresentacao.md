# Roteiro da apresentação

Divisão: Pessoa 1 apresenta servidor/rede/autenticação; Pessoa 2 apresenta cliente/criptografia E2E. Ambos participam da conversa e explicam o fluxo geral. Os nomes pessoais podem ser inseridos no roteiro da fala, sem alterar código.

## Preparação

1. Abrir a raiz do projeto em todos os terminais.
2. Conferir dependências e certificado conforme o README. A identidade já existe no ambiente original; em um clone novo, gerar uma vez.
3. Abrir o editor em `src/common/framing.py`, `src/server/main.py`, `src/server/identity.py`, `src/client/handshake.py` e `src/client/crypto.py`.
4. Separar quatro terminais: um servidor e três clientes. Um quinto terminal é útil para os testes automáticos.
5. Ensaiar antes da apresentação. Não alterar código nem imprimir chaves/frames ao vivo.

## Sequência de 10 a 12 minutos

| Tempo aproximado | Quem | Ação e fala |
|---|---|---|
| 0:00–0:30 | Ambos | Apresentar integrantes e objetivo: vários clientes, conversas E2E e servidor relay |
| 0:30–2:30 | Pessoa 1 | Mostrar framing, sessões, registro, pinning e assinatura; abrir os trechos correspondentes |
| 2:30–4:30 | Pessoa 2 | Mostrar derivação X25519/HKDF, nonce/AAD e AES-GCM; explicar contadores |
| 4:30–6:30 | Ambos | Subir servidor, conectar três clientes, trocar mensagens A↔B e selecionar C por UUID |
| 6:30–8:30 | Pessoa 2 | Rodar adulteração e replay; mostrar manipulação em memória na função `demo` |
| 8:30–9:30 | Pessoa 1 | Rodar framing inválido e explicar que só a conexão ofensora caiu |
| 9:30–10:30 | Ambos | Resumir garantias e limites; se houver tempo, mostrar reconexão/pinning |

## Conversa ao vivo

Pessoa 1, terminal do servidor:

```bash
.venv/bin/python -m src.server.main
```

Pessoa 2, repetir em três terminais separados:

```bash
.venv/bin/python -m src.client.main
```

Identificar os clientes pelos UUIDs exibidos. Em A, executar `/peers`, escolher B pelo número correspondente com `/to NUMERO` e enviar uma mensagem fictícia. Em B, responder usando a mesma sequência. Mostrar que C não recebe essa conversa; depois selecionar C e enviar outra mensagem dirigida a ele.

A ordem da lista depende dos UUIDs. Não presumir que “1” sempre significa o mesmo participante em todos os clientes. Usar `/send UUID TEXTO` elimina essa ambiguidade.

## Demonstrações de segurança

Estes comandos criam um relay e três clientes novos em porta local efêmera. Eles validam os mesmos módulos em um ambiente isolado do servidor manual, sem proxy externo nem modificações de código.

Pessoa 2:

```bash
.venv/bin/python -m scripts.demonstrar_falhas --cenario adulteracao
.venv/bin/python -m scripts.demonstrar_falhas --cenario replay
```

Explicar o bitflip na tag/ciphertext em memória e o reenvio do mesmo frame. A saída confirma a rejeição real pelo destinatário. No teste de adulteração, o frame íntegro é aceito em seguida, confirmando que a falha não corrompeu o contador.

Pessoa 1:

```bash
.venv/bin/python -m scripts.demonstrar_falhas --cenario framing
```

Explicar o envio de comprimento `0xffffffff`: o relay encerra essa conexão antes de ler um corpo enorme e os três clientes existentes continuam trocando mensagens.

Se o tempo permitir:

```bash
.venv/bin/python -m scripts.demonstrar_falhas --cenario reconexao
.venv/bin/python -m scripts.demonstrar_falhas --cenario pinning
```

Para rodar tudo em uma sequência:

```bash
.venv/bin/python -m scripts.demonstrar_falhas
```

## Falas de encerramento

Pessoa 1: “Autenticamos o servidor com certificado pinado e assinatura RSA-PSS. O diretório também é assinado. O relay guarda chaves públicas e encaminha os frames, sem possuir as chaves AES das conversas.”

Pessoa 2: “X25519 e HKDF estabelecem chaves por direção. AES-GCM protege texto e metadados autenticados; o contador rejeita replay. Renovar as chaves efêmeras e descartar estado antigo protege sessões passadas contra comprometimento futuro apenas da chave RSA.”

Ambos devem saber acrescentar: “Confiamos no servidor para distribuir as chaves corretas. Não implementamos autenticação pessoal independente nem ratchet por mensagem.”

## Ensaio e problemas comuns

- Se não conectar: conferir servidor, porta, diretório atual e caminho do certificado; não desativar o pinning.
- Se não houver peers: conectar outro cliente e aguardar seu anúncio. Se reconectar com mesmo UUID, encerrar antes a sessão anterior.
- Se a geração disser que a identidade já existe: ela não foi sobrescrita; use os arquivos existentes. Um clone novo não contém esses arquivos.
- Se um teste não puder abrir sockets: executar em ambiente que permita TCP local.
- Se necessário encerrar tudo: `/quit` nos clientes e Ctrl+C no servidor. O encerramento com cliente ativo também foi testado.

Cada pessoa deve responder às perguntas de seu guia sem consultar e explicar pelo menos um trecho de código da outra área. Nenhuma etapa do ensaio exige escrever ou corrigir código.
