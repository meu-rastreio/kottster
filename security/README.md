# Análise de segurança (Semgrep · HoundDog.ai · OSV · Socket · Claude Code)

Piloto descrito em *Integração de Semgrep, Socket e HoundDog.ai com Claude Code* (v2, 20/10/2026).
Os scanners geram evidências reproduzíveis; o Claude Code revisa o contexto e propõe correções.
Nada é publicado automaticamente.

## Rodar localmente

```bash
bash security/scan.sh
```

Requisitos: Docker e Node ≥ 20. Resultado em `.security-reports/<commit>/` (ignorado pelo git), ou em
`.security-reports/<commit>-dirty/` quando há alterações não commitadas, que também entram no scan:

| Arquivo | Conteúdo |
| --- | --- |
| `findings.json` | Achados normalizados, deduplicados e sanitizados (pode ir para a IA / CI) |
| `findings.md` | Resumo em tabela |
| `raw/` | Saídas brutas dos scanners — podem conter segredos; **não compartilhar** |

Depois, no Claude Code: `/security-triage` (opcionalmente com caminhos: `/security-triage src/pages/api`).

## Ferramentas

| Ferramenta | Versão | Cobre | Observação |
| --- | --- | --- | --- |
| Semgrep CE | 1.182.0 | Padrões de código e segredos (`p/default`, `p/secrets`, `security/semgrep-rules.yml`) | Regras do registry: Semgrep Rules License — **uso interno apenas** |
| HoundDog.ai | 3.11.0 | Fluxo de dados sensíveis (PII, tokens) para logs, terceiros, storage | Roda local com `--no-ai-review`; plano grátis só gera JSON; termos restringem oferta a terceiros |
| OSV-Scanner | v2.6.0 | Vulnerabilidades conhecidas nos lockfiles (npm, yarn, pnpm, Maven) | Gratuito, sem token |
| Socket CLI | 1.9.0 | Risco de supply chain das dependências | Só roda com `SOCKET_CLI_API_TOKEN` (secret da organização no GitHub); org Socket em `SOCKET_ORG` (padrão `meu-rastreio`); entram na tabela só os alertas de risco (malware, typosquatting, CVE fora do OSV, código suspeito ou ofuscado, pacote deprecado) médios ou mais graves; os demais ficam no dashboard Socket |

Para pular um scanner: `SKIP_SEMGREP=1`, `SKIP_HOUNDDOG=1`, `SKIP_OSV=1`, `SKIP_SOCKET=1`.

## Como funciona

- Os scanners rodam em containers com versão fixada e veem um **snapshot somente leitura** com os
  arquivos rastreados e os não rastreados que não estão no `.gitignore`. Arquivos ignorados (`.env`,
  `node_modules`, builds) nunca chegam a eles e a árvore de trabalho não é alterada.
- O HoundDog exige metadados git, então o `.git` é montado (somente leitura) só no container dele.
  Ele roda com `--no-ai-review`, para a análise ficar local.
- O OSV sai com código 1 quando encontra vulnerabilidades (tratado como sucesso). Em repositórios sem
  manifestos de pacote, aparece como `skipped` A base consultada é a do [osv.dev](https://osv.dev).
- Se o OSV não conseguir resolver as dependências de um manifesto (ex.: `pom.xml` com versão `RELEASE` ou
  `LATEST`, que impede a resolução transitiva do Maven), ele aparece como `partial`: o resultado cobre só
  parte dos pacotes e não fecha achados no Faraday. Fixe a versão no manifesto para voltar a `ok`.
- Socket: o relatório de política (`raw/socket.json`) só lista alertas que a política da organização marca
  como warn/error e não traz severidade, por isso o scan completo (`raw/socket-scan.json`, via
  `socket scan view`) é o que entra na tabela, filtrado pelos tipos de risco listados acima. CVEs que o OSV
  já reporta para o mesmo pacote e versão (comparando todos os IDs e aliases do grupo) não se repetem.
- `normalize.mjs` mascara valores com cara de credencial (com ou sem aspas, chaves conhecidas, JWT, chaves
  privadas, URLs com senha) antes de gravar `findings.json`/`findings.md`. Uma saída de scanner corrompida
  marca o scanner como `failed` em vez de parecer um resultado limpo.

## Contrato do achado

Cada item de `findings.json` tem `id` estável (ferramenta + regra + arquivo + código normalizado,
sem número de linha), ferramenta e versão, regra e licença, arquivo/linha, severidade, confiança,
CWE/OWASP, trecho sanitizado (achados de segredo nunca levam código) e `status`. Quando o mesmo
código aparece em mais de um lugar, o achado é um só e `occurrences` lista todos os locais; a decisão
registrada vale para todos eles.

Decisões ficam versionadas em `security/decisions.json`, para que o mesmo problema não seja reaberto:

```json
{
  "3f2a9c0d1e4b5a67": {
    "status": "falso-positivo",
    "justificativa": "valor vem de constante interna",
    "responsavel": "nome",
    "data": "2026-10-21"
  }
}
```

Status: `novo` (padrão), `confirmado`, `suspeita`, `falso-positivo`, `risco-aceito`, `corrigido`.

## CI (`.github/workflows/security-scan.yml`)

- Roda a cada push na main, em pull requests, manualmente e toda segunda-feira; publica `findings.md` no resumo do job
  e `findings.json` como artefato (30 dias). As saídas brutas não são enviadas.
- **Em pull request:** um job separado comenta o resultado no PR (um comentário só, atualizado a cada push),
  com até 50 achados em aberto e o link para o relatório completo. Esse job não roda código do PR.
- **Na main** (push, execução manual e semanal): o job `faraday` envia o `findings.json` para o workspace
  `meu-rastreio` do Faraday, com um asset por repositório, e fecha lá os achados que não aparecem mais.
  Ele usa a variável `FARADAY_URL`, a variável `FARADAY_USERNAME`, o secret `FARADAY_PASSWORD` e o secret
  `FARADAY_CF_KEY` (enviado no header `X-CI-Key`, que a regra do Cloudflare usa para liberar a API).
  O Faraday Community não tem token de API fixo nem mais de um usuário, por isso o CI autentica com
  usuário e senha. O nome do achado no Faraday leva o ID estável (`[id]`) e o `external_id` também.
  Status: `risco-aceito` vira `risk-accepted`; `falso-positivo` e `corrigido` viram `closed`; o resto `open`.
  O Faraday não atualiza severidade nem texto de um achado já existente, só o status.
- **Não bloqueia** o merge durante o piloto.
- Socket: usa o secret `SOCKET_CLI_API_TOKEN` cadastrado na organização meu-rastreio, **só** em push na main,
  execução manual e na rodada semanal. Em pull requests o Socket fica `skipped`: o PR controla o `scan.sh`
  que roda, e o token não deve ficar exposto a um script ainda não revisado. Quem tem acesso de escrita
  ao repositório ainda consegue usar secrets editando workflows em uma branch; o controle real é quem
  tem esse acesso.
- Revisão do Claude no PR: desativada por padrão. Para ativar, crie o secret `ANTHROPIC_API_KEY`
  e a variável `SECURITY_CLAUDE_REVIEW=true`. O Claude só lê o código e comenta no PR.

## Dados enviados ao Claude

Os scanners rodam localmente, mas a revisão por IA não é local: trechos lidos pelo Claude são
processados pela Anthropic. Não use em código de clientes sem autorização registrada.
