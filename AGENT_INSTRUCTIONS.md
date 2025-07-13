# Instruções para Agente de Programação

## Contexto do Projeto

Repositório de scripts PowerShell para auditoria SCADA preventiva.

## Estrutura do Código

### Arquivos Principais
- **NMR5_Baseline.ps1**: Script base para auditoria (146KB)
- **teste_apagar.ps1**: Script de desenvolvimento/testes (151KB)

### Pasta Referencia/
Scripts históricos e versões de referência.

## Regras de Desenvolvimento

### 1. Princípios XP
- **Incremental**: Sempre construir sobre código funcional existente
- **Não-destrutivo**: NUNCA remover funcionalidades existentes
- **Testável**: Scripts devem ser executáveis no CLI

### 2. Compatibilidade
- **PowerShell 5.1+** e **PowerShell 7+**
- **Windows/Windows Server**
- **Métodos**: CIM + WMI + WMIC + Registry + Comandos Nativos

### 3. Fluxo de Trabalho
1. Confirmar entendimento da tarefa
2. Apresentar plano mínimo
3. Aguardar aprovação
4. Trabalhar incrementalmente

## Arquitetura Atual

