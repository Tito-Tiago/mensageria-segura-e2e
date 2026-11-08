# Evidências de validação

Validação local realizada em 08/11/2026. Ambiente: Linux, Python 3.12.3, cryptography 50.0.2, pytest 9.2.0 e pytest-asyncio 1.4.1.post1. Os testes usam TCP real em loopback e portas efêmeras; não houve serviço externo nem dados reais de conversa.

## Comandos e resultados observados

```bash
.venv/bin/python -m pytest -q
```

Resultado da execução final: **45 passed**, sem falhas. A duração observada foi aproximadamente dois segundos; pode variar em outros ambientes.

```bash
.venv/bin/python -m scripts.demonstrar_falhas
```

Saída observada:

```text
AMBIENTE: relay TCP local e três clientes registrados.
PASSOU E2E: troca nos dois sentidos; C não recebeu nem conseguiu decifrar.
PASSOU ADULTERAÇÃO: bitflip rejeitado por GCM; frame íntegro seguinte aceito.
PASSOU REPLAY: reenvio do mesmo frame rejeitado pelo contador.
PASSOU FRAMING: comprimento inválido encerrou só a conexão ofensora.
PASSOU RECONEXÃO: mesmo UUID, novas chaves; frame antigo rejeitado.
PASSOU PINNING: certificado diferente do pin foi recusado.
DEMONSTRAÇÃO CONCLUÍDA: nenhuma chave, nonce, salt ou frame foi impresso.
```

```bash
.venv/bin/python -m pip check
.venv/bin/python -m compileall -q src scripts tests
```

Resultados: `No broken requirements found.` e compilação sem erros.

Também foram executados a geração local da identidade e os comandos `--help` do cliente e do servidor. Os arquivos locais de identidade são ignorados pelo Git. A permissão 600 e a recusa de sobrescrita da chave privada têm teste automatizado.

## Cobertura dos testes

| Arquivo | Cenários verificados |
|---|---|
| [test_framing.py](../tests/test_framing.py) | Frames byte a byte, frames agrupados, comprimentos inválidos, EOF no corpo, timeout de frame incompleto, ociosidade sem timeout, versão e tipo |
| [test_crypto.py](../tests/test_crypto.py) | Chaves por direção, envio nos dois sentidos, vazio/UTF-8/4096 bytes, adulteração de campos e tag, replay, contador alto inválido, esgotamento, chave nula, chaves de outro cliente, vetor público RFC 7748 e labels HKDF, estabilidade do IV |
| [test_handshake.py](../tests/test_handshake.py) | Pin, assinatura, vínculo ao UUID/chave do registro, controles assinados, replay/contexto de controles, persistência e permissão da identidade |
| [test_server.py](../tests/test_server.py) | Anúncios para dois clientes, ausência de chave AES na sessão, UUID duplicado, framing inválido sem queda global, chave de baixa ordem e destinatário sem leitura durante timeout de escrita, encerramento e rejeição de framing |
| [test_integracao.py](../tests/test_integracao.py) | Todos os pares de três clientes, bitflip/replay com continuação, reconexão com mesmo UUID, remetente falso, envios concorrentes, limite UTF-8, controle adulterado, limite de clientes e política de logs |
| [test_cli.py](../tests/test_cli.py) | Cliente em subprocesso envia/recebe/lista/sai; saída automática se servidor cai; servidor real encerra por SIGINT com cliente ativo |

A suíte contém 45 casos após expansão dos testes parametrizados. O teste de compatibilidade da derivação compara a composição Extract/Expand do projeto com a API HKDF completa usando o segredo conhecido do vetor público da [RFC 7748, seção 6.1](https://www.rfc-editor.org/rfc/rfc7748.html#section-6.1). Esses valores são dados públicos de teste, nunca chaves das sessões executadas.

## Correspondência com os quatro mínimos do enunciado

1. **Troca E2E:** mensagens corretas nos dois sentidos, com terceiro cliente sem receber e incapaz de autenticar o frame com suas chaves.
2. **Adulteração:** bit invertido em frame real encaminhado pelo relay produz rejeição GCM no destinatário; frame íntegro seguinte é aceito.
3. **Replay:** o mesmo frame aceito é reenviado e recusado pelo contador do destinatário.
4. **Framing inválido:** comprimento acima do limite encerra a conexão ofensora, enquanto clientes legítimos continuam operacionais.

Os cenários da ferramenta usam os mesmos módulos da aplicação. Eles criam um ambiente independente em vez de alterar frames de um servidor manual externo. Payloads são manipulados somente em memória, sem captura persistente.

## Correções encontradas pela validação

O teste de queda do servidor revelou que aguardar o listener antes de fechar conexões ativas bloqueava o encerramento no Python 3.12. A ordem foi corrigida. Uma verificação adicional do comando real por SIGINT identificou a mesma espera dentro de `serve_forever`; o comando agora aguarda um futuro e usa seu próprio `finally` para encerrar corretamente. Os testes de subprocesso cobrem ambos os caminhos.

A revisão também reproduziu um bloqueio quando o destinatário deixa de ler: `close` ainda tentava escoar os buffers TCP após o timeout de escrita. Falhas de escrita e o encerramento global agora abortam os transportes, e a espera normal por `wait_closed` tem prazo máximo. Três regressões com socket TCP real e buffers reduzidos verificam a remoção da sessão após timeout, a continuidade de conversas legítimas, o encerramento com saída pendente e a limpeza após framing inválido. Os prazos de I/O são reduzidos apenas nesses testes.

## Limites da validação

- Testado localmente em Linux; macOS e Windows não foram executados. A CLI foi projetada para terminal Linux/macOS.
- Não foram realizados auditoria independente, teste de carga prolongado nem prova formal de segurança.
- O teste de logs verifica os caminhos exercitados; as chamadas de logging também foram revisadas no código.
- Não foi simulada autenticação pessoal dos clientes nem defesa contra servidor malicioso: essas garantias não fazem parte do protocolo implementado.
- O certificado autoassinado e as decisões sobre salt/serialização/controles estão documentados em [protocolo.md](protocolo.md).
