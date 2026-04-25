## Objetivo

- Estabilizar codigo.
- Evitar refatoracoes amplas.
- Garantir que cada mudanca seja pequena, reversivel e validada.
- Priorizar risco real, startup, loops, concorrencia e usabilidade.

## Regras De Conduta

- NUNCA criar branch novo nem PR novo sem autorizacao explicita.
- Nao criar worktree ou pasta sem aprovacao.
- Nao fechar ou abrir PR sem pedido explicito.
- Nao editar nada antes de aprovar plano.
- Nao alterar arquivo preexistente sem listar impacto antes.
- Nao misturar idiomas: comunicacao tecnica em PT-BR. Codigo e comentarios em ASCII.
- Sem acentos, cedilha, emoji ou em dash em codigo e mensagens tecnicas.
- Nao fazer mudancas fora do escopo. Se algo extra parecer necessario, parar e pedir confirmacao.
- Nada de `try/catch` vazio, nada de supressao que esconda erro real, nada de self-healing silencioso.
- Evitar qualquer mudanca de layout ou posicionamento na GUI sem pedido explicito.
- Nao adicionar wrappers, mixins, helpers, aliases ou camadas novas sem necessidade comprovada.
- Nao usar `git reset --hard` nem comandos destrutivos.
- Cada ciclo deve fechar com estabilidade e usabilidade preservadas.

## Controle De Escopo

Antes de qualquer edicao, registrar em 3 linhas:
1. Objetivo do slice.
2. Arquivos que podem mudar.
3. Arquivos proibidos no slice.

Se houver ambiguidade, default para diagnostico e testes sem editar.

## Processo

0. Commits atomicos e rollback facil por feature.
1. Diagnosticar e isolar o problema com evidencia: arquivo, linha, log ou reproducao.
2. Propor plano curto e diff previsto antes de editar, sempre com o menor patch possivel.
3. Implementar em slice pequeno.
4. Validar localmente com tooling compativel com a stack do repositorio.
5. Priorizar correcoes de risco real; evitar refatoracao transversal fora de escopo.
6. Itens nao bloqueantes devem ser registrados no backlog apropriado quando existir.
7. Quando alterar config, fazer backup com timestamp.

## Higiene De Workspace

- Rodar `git status --short` no inicio.
- Confirmar pasta e branch de trabalho.
- Nao commitar arquivos locais ou secretos sem confirmacao.
- Se aparecer mudanca em `.gitignore*` fora do pedido, parar e perguntar.
- Estabilizar import, startup e pontos de concorrencia com mudancas minimas e verificaveis.
- Verificar status e condicoes de loops antes de alterar comportamento.

## Error Handling E Performance

- Tratamento de erro deve existir por bloco funcional relevante, nao a cada poucas linhas.
- Evitar excesso de condicionais e `try/catch` fragmentado.
- Proibido `try/catch` vazio e proibido esconder falha real.
- Cada tratamento deve ter saida clara: log objetivo e retorno ou acao coerente com o fluxo.
- Em qualquer fix, validar que a solucao nao cria custo alto desnecessario.
- Quando houver tradeoff real, parar e pedir permissao com 2 opcoes objetivas.
- Busca ampla com `rg`, `find` e similares usa timeout padrao de 60s, salvo aprovacao explicita para mudar.

## Tooling E Validacao

- Para Python neste repo ou em ferramentas auxiliares Python: usar `uv` para `python`, `python3`, `pip` e `pip3`.
- Para Node, usar exclusivamente `pnpm` ou `bun`.
- Para PowerShell, preferir `pwsh` quando disponivel.
- Em host nao Windows, tratar `pwsh` 7.x como runtime de validacao estatica e de compatibilidade parcial.
- Nao prometer compatibilidade funcional completa de Windows PowerShell 5.1 em macOS.
- Para repositorio PowerShell, validar em ordem:
  1. parse do arquivo com o parser do PowerShell
  2. `Invoke-ScriptAnalyzer` quando o modulo estiver instalado
  3. `Pester` quando houver testes
  4. dot-source, import ou startup compativel com o tipo de artefato
- Quando houver fluxo Windows-only, declarar explicitamente o bloqueio de runtime no report.

## Politica Para PowerShell 5.1 E 7.x

- Assumir como alvo principal do projeto: Windows PowerShell 5.1 e PowerShell 7+ em Windows, conforme documentacao do repo.
- Em macOS ou Linux:
  - usar `pwsh` para parse, ScriptAnalyzer, Pester e smoke de carregamento quando possivel
  - nao validar chamadas Windows-only como WMI, CIM remoto, registry remoto, services, drivers e event logs locais como se estivessem cobertas por execucao real
  - registrar claramente o que foi validado de forma estatica e o que ficou bloqueado por plataforma
- Melhorias devem ser pequenas e focadas em observabilidade, robustez e reducao de falhas silenciosas.

## Kluster

- As regras do Kluster sao obrigatorias e nao devem ser alteradas por este arquivo.
- Depois de qualquer mudanca em arquivo, executar revisao automatica do Kluster quando a ferramenta estiver disponivel na sessao.

## Definition Of Done

1. Objetivo principal do slice atendido.
2. Sem regressao conhecida nos fluxos sensiveis tocados.
3. Validacoes tecnicas compativeis com a plataforma executadas ou bloqueio declarado.
4. Impacto, risco residual e proximo passo documentados na resposta final.
