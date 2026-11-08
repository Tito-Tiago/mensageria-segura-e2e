# Plano de implementação pelo assistente e estudo por dois integrantes

Fonte dos requisitos: Trabalho Prático 3 — Sistema de Mensageria Segura Multi-Cliente, PDF fornecido localmente e não versionado.

Este plano substitui a divisão anterior de desenvolvimento. O assistente implementará, integrará, testará, corrigirá e documentará o sistema completo. Os dois integrantes estudarão partes diferentes do código pronto, ensaiarão os comandos fornecidos e apresentarão o trabalho.

**Estado atual: implementação concluída e validada em 08/11/2026.** Este documento preserva o plano de execução. O [README](README.md) descreve os comandos atuais, os [resultados de validação](docs/testes.md) registram 42 testes aprovados e os guias reais estão em [Pessoa 1](docs/estudo_pessoa_1.md) e [Pessoa 2](docs/estudo_pessoa_2.md). A implementação também inclui `src/client/connection.py`, que separa a API do cliente da interface de terminal.

## 1. Responsabilidades

| Atividade | Responsável |
|---|---|
| Definir detalhes do protocolo e resolver ambiguidades de implementação | Assistente |
| Programar servidor, cliente e módulos compartilhados | Assistente |
| Preparar geração de certificado, configuração e dependências | Assistente |
| Implementar testes, executar, investigar falhas e corrigir | Assistente |
| Preparar demonstrações de segurança reproduzíveis | Assistente |
| Escrever README e documentação técnica | Assistente |
| Produzir dois guias de estudo vinculados ao código final | Assistente |
| Preparar roteiro de fala e perguntas com respostas | Assistente |
| Estudar rede, servidor e autenticação | Pessoa 1 |
| Estudar cliente, derivação de chaves e proteção E2E | Pessoa 2 |
| Executar comandos prontos, ensaiar e apresentar | Os dois integrantes |

Nenhuma etapa de programação, integração ou elaboração da documentação será atribuída aos integrantes. Os guias não pressuporão que vocês tenham acompanhado o desenvolvimento.

## 2. Escopo da implementação

Aplicação de terminal em Python, usando `asyncio` para TCP e `cryptography` para as primitivas criptográficas, com:

- Servidor multi-cliente que atua somente como relay, sem chaves simétricas E2E.
- Certificado RSA autoassinado previamente pinado nos clientes e handshake RSA-PSS/SHA-256.
- Pares X25519 efêmeros gerados localmente a cada conexão.
- Distribuição autenticada das chaves públicas e dos metadados dos pares.
- HKDF-SHA256 com chaves de 16 bytes e labels `A2B` e `B2A`.
- AES-128-GCM, tag de 16 bytes, AAD e contadores por par e por direção.
- Listagem de participantes, seleção de destinatário, envio e recebimento simultâneos.
- Proteção contra replay, adulteração, falsificação do remetente no relay e framing inválido.
- Desconexão, reconexão e limpeza/renovação do estado.
- Limite de 4096 bytes por mensagem após codificação UTF-8.
- Logs estritamente limitados aos eventos e metadados permitidos no PDF.

Demonstrar com três clientes para evidenciar o comportamento multi-cliente. Interface gráfica, banco de dados, grupos, arquivos e histórico persistente não integrarão o escopo principal. Rotação periódica é opcional no enunciado e não será prioridade.

## 3. Decisões técnicas para executar sem pendências para a dupla

O assistente documentará as escolhas abaixo como interpretações de implementação, distinguindo-as das exigências explícitas do PDF.

### Identidade e handshake

Adotar a definição do PDF em que `pk_server` é a chave pública RSA do certificado. Usar sua serialização DER/SubjectPublicKeyInfo no transcript, pois o enunciado não define uma representação RSA raw. A chave X25519 do cliente será obrigatoriamente raw de 32 bytes.

Assinar `H = SHA256(pk_server_bytes || pk_client || client_id || salt_handshake)` com RSA-PSS, MGF1/SHA-256 e salt PSS de 32 bytes, usando a API de hash pré-calculado. Distinguir o salt interno do PSS dos salts do handshake e do HKDF.

O cliente verificará o certificado previamente pinado e a assinatura. Receber um certificado pela conexão não será suficiente para confiar nele. A chave privada RSA será gerada localmente e excluída do versionamento.

O PDF também menciona uma chave efêmera do servidor sem definir consistentemente seu papel na arquitetura E2E. Registrar essa ambiguidade. A troca ECDH que protege conversas ocorrerá entre clientes; o servidor não participará da derivação dessas chaves.

### Salt e direção das chaves

Usar um salt aleatório de 16 bytes no handshake de cada conexão e outro salt de 16 bytes por estabelecimento de par, entregue igualmente aos dois participantes por controles autenticados. Isso concilia os salts individuais de registro com a necessidade de parâmetros iguais no HKDF dos peers.

Ordenar os UUIDs binários: o menor será A e o maior, B. Aplicar `HKDF-Extract(salt_par, Z_AB)` e `HKDF-Expand` com labels ASCII `A2B` e `B2A`, produzindo 16 bytes por direção. Descartar referências ao segredo ECDH intermediário depois da derivação.

### Nonces e contadores

Cada remetente gerará seu IV base aleatório de 4 bytes por par/sessão. Construir `nonce = IV_base || seq_no`, com contador de 8 bytes big-endian. O destinatário aprenderá o prefixo do primeiro frame autenticado e o fixará como IV de recepção; não gerará um IV independente para receber.

Começar com próximo envio igual a zero e último recebimento igual a menos um. Reservar cada número de envio uma única vez. Conferir IDs, tamanho, monotonicidade e correspondência entre nonce e contador. Atualizar o estado de recepção somente depois da autenticação GCM; uma mensagem adulterada com contador alto não poderá bloquear mensagens legítimas futuras.

Na reconexão, gerar novo par X25519, salt de handshake, salts dos pares e IVs. Não reiniciar contadores com as mesmas chaves; ao esgotá-los, exigir novo estabelecimento.

### Controles e diretório

Assinar mensagens administrativas, incluindo tipo, destinatário, contexto da conexão atual, contador e conteúdo. Vincular o contexto ao registro atual e à chave efêmera do cliente. Recusar controles repetidos ou de conexões anteriores. Manter contadores administrativos separados dos contadores E2E.

No relay, verificar se `sender_id` corresponde à conexão registrada. Recusar UUID já conectado e tratar destinatário ausente. Distribuir entrada e saída de peers sem interferir nas chaves dos pares que continuam ativos.

### Transporte e limites

Usar prefixo de tamanho de 4 bytes big-endian e envelope com versão, tipo e payload. O corpo E2E seguirá:

```text
nonce(12) || sender_id(16) || recipient_id(16) || seq_no(8) || ciphertext || tag(16)
AAD = sender_id || recipient_id || seq_no
```

O corpo E2E terá entre 68 e 4164 bytes para o limite de texto adotado; envelope e prefixo serão contabilizados separadamente. Definir limites próprios para controles/certificado, validar comprimentos antes de alocar o corpo e tratar leituras incompletas com timeout.

Suportar frames fragmentados ou agrupados no TCP e serializar escritas concorrentes por conexão. Adotar inicialmente limite configurável de 20 clientes, com erro controlado quando atingido.

### Garantias e limites

Explicar o modelo com servidor confiável para distribuir chaves: o protocolo não define verificação independente das identidades dos clientes contra um servidor malicioso que substitua chaves. O relay que segue o protocolo não recebe o material necessário para decifrar conversas.

Delimitar sigilo perfeito ao comprometimento futuro da chave RSA do servidor, com chaves X25519 efêmeras e descarte de estado antigo. Não alegar sigilo por mensagem, proteção contra comprometimento dos clientes ativos nem apagamento físico garantido da memória em Python.

## 4. Estrutura prevista e divisão para estudo

Os guias finais serão atualizados para os arquivos e as funções realmente implementados.

```text
README.md
requirements.txt
.gitignore
src/
  common/
    framing.py          # Pessoa 1: transporte TCP e limites
    protocol.py         # Ambos: formatos e campos
  server/
    main.py             # Pessoa 1: sessões, diretório e relay
    identity.py         # Pessoa 1: RSA, certificado e assinaturas
  client/
    main.py             # Pessoa 2: comandos e coordenação do cliente
    handshake.py        # Pessoa 1: validação do servidor no cliente
    crypto.py           # Pessoa 2: X25519, HKDF e AES-GCM
    peers.py            # Pessoa 2: estado, IVs e contadores por par
scripts/
  gerar_certificado.py
  demonstrar_falhas.py
tests/
  test_framing.py
  test_handshake.py
  test_crypto.py
  test_integracao.py
docs/
  protocolo.md
  testes.md
  estudo_pessoa_1.md
  estudo_pessoa_2.md
  apresentacao.md
certs/
  server.crt            # público; chave privada fora do versionamento
```

Preferir funções curtas, nomes explícitos e comentários em português sobre decisões relevantes. Não implementar primitivas criptográficas manualmente. Verificar o ambiente disponível e registrar as versões efetivamente usadas das dependências.

## 5. Sequência de implementação pelo assistente

As etapas serão executadas em ordem, com integração e validação progressivas. Não se atribuem dias de desenvolvimento aos integrantes nem se promete duração sem verificar o ambiente.

| Etapa | Trabalho do assistente | Critério para avançar |
|---|---|---|
| 1. Preparação | Verificar ambiente/instruções locais; criar estrutura, dependências e especificação | Projeto importável e contrato binário definido |
| 2. Transporte | Framing, limites, timeout e escrita serializada | Fragmentação, agrupamento e frames inválidos testados |
| 3. Registro | Certificado, handshake, pinning e tabela de sessões | Registro válido funciona; autenticação incorreta falha |
| 4. Criptografia | X25519, HKDF, AES-GCM, AAD, IVs e contadores | Chaves compatíveis nos dois sentidos e falhas rejeitadas |
| 5. Rendezvous | Distribuição autenticada de peers/salts e relay | Três clientes com pares independentes |
| 6. Interface | CLI, listagem, destinatário, envio/recebimento simultâneos | Conversa completa com comandos documentados |
| 7. Robustez | Reconexão, quedas, UUID duplicado, recursos e logs | Falhas isoladas e estado antigo recusado |
| 8. Demonstrações | Troca E2E, bitflip, replay e framing inválido | Quatro cenários obrigatórios reproduzíveis |
| 9. Material didático | README, guias, perguntas e roteiro vinculados ao código | Dupla consegue estudar e ensaiar sem desenvolver |
| 10. Verificação final | Executar testes e comandos finais; corrigir e registrar resultados | Entrega validada com limitações reais declaradas |

Prioridade pela avaliação: handshake/rendezvous (30%), AES-GCM/nonce/contador (25%), replay/adulteração (20%), organização/documentação/demo (15%) e práticas de segurança (10%). Concluir as correções necessárias antes de repassar a implementação para estudo.

## 6. Testes e demonstrações que o assistente entregará

| Cenário | Resultado esperado | Quem explica |
|---|---|---|
| Dois clientes trocando mensagens E2E | Decifragem correta nos dois sentidos | Ambos |
| Bitflip no ciphertext/tag | Rejeição por falha de autenticação GCM | Pessoa 2 |
| Reenvio de frame aceito | Rejeição de replay | Pessoa 2 |
| Framing inválido | Encerramento controlado da conexão ofensora | Pessoa 1 |
| Certificado inesperado/assinatura inválida | Registro ou continuação recusados | Pessoa 1 |
| Três clientes e pares simultâneos | Chaves/contadores isolados por par | Ambos |
| Cliente C tenta abrir frame A-B com suas próprias chaves | Falha de autenticação | Pessoa 2 |
| Alteração de IDs, nonce ou contador | Rejeição sem avanço indevido de estado | Pessoa 2 |
| Frame adulterado com contador alto | Próxima mensagem legítima continua aceita | Pessoa 2 |
| Controles alterados, repetidos ou antigos | Diretório não aceita atualização inválida | Pessoa 1 |
| Frames fragmentados, agrupados, incompletos ou excessivos | Parser correto e recursos limitados | Pessoa 1 |
| Reconexão com mesmo UUID | Novo estabelecimento; frames antigos rejeitados | Ambos |
| UUID ativo, queda abrupta e excesso de clientes | Falha tratada sem derrubar outras sessões | Pessoa 1 |
| Texto UTF-8 no limite e acima de 4096 bytes | Limite aplicado em bytes | Pessoa 2 |
| Revisão de logs e estado do servidor | Ausência de dados proibidos e de chaves E2E no relay | Ambos |

Os quatro primeiros são os testes mínimos obrigatórios do PDF. Todos serão implementados e executados pelo assistente. Os integrantes receberão comandos e explicações das saídas.

A demonstração de bitflip/replay manipulará frames somente em memória, sem salvar ou imprimir frames completos, nonces, salts, chaves ou segredos. O texto das conversas aparecerá na interface dos clientes, sem virar log. O servidor exibirá apenas metadados permitidos. Registrar em `docs/testes.md` resultados efetivamente observados.

## 7. Estudo da Pessoa 1 — rede, servidor e autenticação

**Pergunta central:** como o cliente encontra os demais e confia no servidor, enquanto o servidor apenas encaminha a conversa?

Ordem de leitura:

1. Visão geral da arquitetura e fluxo de registro de um cliente.
2. `framing.py`: prefixo de tamanho, leitura exata, limites e erros TCP.
3. `identity.py` e `handshake.py`: certificado pinado, transcript, hash e assinatura RSA-PSS.
4. Tabela `sessions`: conexão, chave pública, contexto e contadores administrativos.
5. Entrada de um novo cliente e distribuição autenticada dos peers.
6. Relay de A para B e conferência de `sender_id`.
7. Saída, reconexão, limite de recursos e framing inválido.

Deverá conseguir explicar:

- Por que TCP exige framing e como o tamanho é validado.
- Por que um certificado autoassinado precisa ser previamente pinado.
- O que a assinatura autentica e por que ela não cifra as conversas.
- Por que controles e E2E têm estados separados.
- Quais informações o servidor conhece e quais segredos não possui.

**Parte prática:** iniciar servidor, explicar conexões e estrutura de sessões, mostrar trechos de roteamento/autenticação e executar o comando pronto de framing inválido.

## 8. Estudo da Pessoa 2 — cliente e criptografia E2E

**Pergunta central:** como dois clientes obtêm as mesmas chaves sem transmiti-las e detectam mensagens adulteradas ou repetidas?

Ordem de leitura:

1. Geração X25519 e diferença entre chave pública e privada.
2. `crypto.py`: ECDH, segredo Z, HKDF e direções A2B/B2A.
3. `peers.py`: chaves, IVs e contadores separados por destinatário.
4. Construção de nonce/AAD e cifragem AES-GCM.
5. Recepção, validações e atualização de estado somente após autenticação.
6. Integração com CLI e recebimento concorrente.
7. Testes de bitflip, replay e reconexão e suas funções responsáveis.

Deverá conseguir explicar:

- Por que Z não é transmitido e por que salt não é uma chave.
- Como HKDF produz chaves de envio/recepção compatíveis nos peers.
- Por que nonce precisa ser único por chave.
- Como AAD autentica IDs e contador sem cifrá-los.
- Por que tag detecta adulteração, mas sozinha não bloqueia replay.
- Qual é a relação entre chaves efêmeras, reconexão e sigilo perfeito.

**Parte prática:** enviar e receber mensagens, mostrar trechos de derivação/cifragem/validação e executar os comandos prontos de bitflip e replay.

## 9. Material didático que acompanhará o código

O assistente produzirá para cada integrante:

- Lista dos arquivos e funções reais a ler, em ordem recomendada.
- Explicação dos trechos importantes: entradas, saídas, validações e mudanças de estado.
- Caminho de uma mensagem pelo código, desde o comando até o recebimento.
- Relação entre requisitos do PDF e implementação.
- Glossário dos nomes e parâmetros do projeto.
- De 8 a 12 perguntas prováveis, com respostas curtas e referências às funções.
- Comandos exatos da demonstração e resultados esperados.
- Roteiro de fala indicando quais trechos abrir e quando.

As referências serão conferidas após a implementação. Não inventar números de linha ou nomes de funções ausentes. Ambos estudarão também o fluxo geral: conectar → validar servidor → receber peers → derivar chaves → cifrar → encaminhar → validar/decifrar → desconectar.

Não será necessário decorar a matemática interna das primitivas. Será necessário compreender o papel de cada algoritmo, seus parâmetros e onde cada proteção aparece no código.

## 10. Estudo de última hora e apresentação

Proposta de três horas por integrante após a entrega validada. O tempo é uma orientação de organização, sem garantia de domínio em prazo fixo.

| Bloco | Duração sugerida | Atividade |
|---|---|---|
| 1 | 20 minutos | Ambos leem a visão geral e o fluxo completo |
| 2 | 60 minutos | Cada pessoa acompanha seu guia e os trechos do código |
| 3 | 30 minutos | Cada pessoa executa comandos e relaciona saídas à implementação |
| 4 | 25 minutos | Responder às perguntas do próprio guia sem consultar |
| 5 | 25 minutos | Um explica sua parte ao outro e revisam as dúvidas |
| 6 | 20 minutos | Ensaio conjunto cronometrado com os testes obrigatórios |

Ao estudar uma função, responder: o que recebe, o que valida, o que altera e qual falha impede. Se houver mais tempo, ampliar leitura e ensaio.

Roteiro sugerido para 10 a 12 minutos, ajustável ao tempo permitido:

1. **Ambos:** integrantes e objetivo — cerca de 30 segundos.
2. **Pessoa 1:** arquitetura, framing, autenticação, registro e diretório — 2 minutos.
3. **Pessoa 2:** ECDH, HKDF, AES-GCM, AAD e contadores — 2 minutos.
4. **Ambos:** troca de mensagens com múltiplos clientes — 2 minutos.
5. **Pessoa 2:** bitflip e replay — 2 minutos.
6. **Pessoa 1:** framing inválido e continuidade do servidor — 1 minuto.
7. **Ambos:** garantias, limites e encerramento — 1 minuto.

Abrir os trechos de código durante suas respectivas explicações. Cada integrante terá conteúdo técnico e demonstração próprios. O roteiro final especificará terminais e comandos, sem exigir alterações manuais de código ao vivo.

## 11. Critérios da entrega pronta para estudo

- [x] Código completo de servidor, cliente e módulos compartilhados.
- [x] Handshake, pinning e controles autenticados verificados.
- [x] E2E nas duas direções e pelo menos três clientes conectados.
- [x] Quatro testes obrigatórios reproduzidos e testes relevantes de integração aprovados.
- [x] Reconexão, falhas de transporte e isolamento das sessões verificados.
- [x] Logs e arquivos sem exposição dos dados proibidos.
- [x] Geração de certificado e instruções reproduzíveis de instalação/execução.
- [x] Especificação do protocolo e resultados reais de validação registrados.
- [x] Dois guias de estudo vinculados ao código final.
- [x] Roteiro, perguntas e comandos da apresentação preparados.
- [x] Comandos finais documentados executados e problemas encontrados corrigidos.

O enunciado não informa prazo, plataforma de envio, exigência de slides ou formato de relatório. A entrega planejada inclui documentação em Markdown e roteiro de apresentação; não presume entregas formais adicionais ausentes no PDF.

## 12. Referências técnicas de apoio

Além do enunciado, as referências oficiais já consultadas orientarão a implementação. Conferir compatibilidade com as versões instaladas durante a execução:

- [X25519 — cryptography](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/x25519/): troca de segredo e chaves efêmeras por handshake.
- [RSA — cryptography](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/): RSA-PSS e assinatura de hash pré-calculado.
- [AEAD — cryptography](https://cryptography.io/en/latest/hazmat/primitives/aead/): AES-GCM, AAD, tags e unicidade do nonce por chave.
- [RFC 5869 — HKDF](https://www.rfc-editor.org/rfc/rfc5869.html): etapas Extract e Expand.
