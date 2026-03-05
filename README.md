# Security Automation Toolkit (S.A.T.)

S.A.T. é um projeto prático de **Security Detection Engineering em Python**, simulando um pipeline de análise utilizado em **Security Operations Centers (SOC)**, com ingestão de logs, correlação temporal de eventos e geração de alertas estruturados compatíveis com SIEM.

A ferramenta evoluiu de scripts independentes para uma arquitetura modular orquestrada via CLI, incorporando:

- ingestão de logs
- normalização de eventos em **JSONL**
- correlação temporal (**sliding window**)
- regras de detecção comportamental
- geração de alertas estruturados **compatíveis com SIEM**

O projeto foi desenvolvido como **portfólio técnico focado em SOC / Blue Team**.

---

# Objetivo do Projeto

Demonstrar, de forma prática e aplicada:

- Automação em Segurança da Informação
- Organização e consolidação de evidências técnicas
- Estruturação de eventos no modelo similar a SIEM
- Implementação de regras de detecção comportamental
- Correlação temporal de eventos (sliding window)
- Geração de alertas enriquecidos com contexto temporal
- Pipeline de análise inspirado em SOC
- Arquitetura modular orientada a CLI

---

# Arquitetura do Projeto

```text
security-automation-toolkit/
├── sat/
│   ├── __main__.py
│   ├── cli.py
│   ├── soc/
│   │   ├── ingest.py
│   │   ├── detection.py
│   │   ├── models.py
│   ├── config/
│   └── utils/
│
├── scripts/
│   ├── port_scanner.py
│   ├── log_analyzer.py
│   ├── password_checker.py
│   ├── report_builder.py
│   └── auth_sample.log
│
├── examples/
│   └── ssh_events_sample.jsonl
│
├── outputs/
│   ├── alerts_bruteforce.jsonl
│   └── alerts_compromise.jsonl
│
├── reports/
│   └── final_report.json
│
├── logs/
│   └── sat.log
│
└── README.md
```
  
---


---

## Detection Engine (SOC Simulation)

O S.A.T. implementa regras de detecção inspiradas em **workflows reais de SOC**.

As regras utilizam **correlação temporal (sliding window)** para identificar padrões suspeitos em eventos de autenticação.

---

# Detection Rules

## SAT-SSH-001 — SSH Brute Force Detection

Detecta múltiplas falhas de autenticação SSH provenientes do mesmo endereço IP dentro de uma janela de tempo definida.

**Técnica MITRE ATT&CK**

T1110 — Brute Force

---

## SAT-SSH-002 — Possible Account Compromise

Correla múltiplas falhas de login SSH seguidas de um login bem-sucedido dentro da mesma janela temporal.

Esse padrão pode indicar tentativa de brute force que resultou em comprometimento de conta.

**Técnicas MITRE ATT&CK**

T1110 — Brute Force  
T1078 — Valid Accounts

---

Os alertas são exportados em formato **JSONL SIEM-ready**, permitindo ingestão futura em ferramentas de monitoramento como SIEM, SOAR ou pipelines de análise de segurança.

## Funcionalidades — v1.3 (SOC Simulation Mode)

### 1. Ingestão e Normalização de Logs

#### Comando:
```bash
python -m sat ingest auth
```
- Leitura de `scripts/auth_sample.log` (log de exemplo incluído no projeto)
- Extração de timestamp real
- Normalização de eventos em JSONL
- Geração de `outputs/soc_events_auth.jsonl`

Cada evento normalizado contém:

- timestamp
- source
- event_type
- severity
- user
- src_ip
- raw

---

### 2. Execução das Regras de Detecção

#### Brute Force Detection:
```bash
python -m sat detect bruteforce --threshold 5 --window 120
```
#### Possible Compromise Detection:
```bash
python -m sat detect compromise
```
#### Saída:
  outputs/alerts_bruteforce.jsonl
  outputs/alerts_compromise.jsonl


## Pipeline de Detecção

O fluxo de processamento do S.A.T. segue etapas inspiradas em arquiteturas de monitoramento utilizadas em SOC:

1. **Ingestão de Logs**
2. **Normalização de Eventos**
3. **Correlação Temporal**
4. **Execução de Regras de Detecção**
5. **Geração de Alertas Estruturados**
6. **Consolidação em Relatório**

```text
Logs → Ingest → Normalize → Detect → Alert → Report
```

Os alertas são automaticamente incorporados ao relatório HTML, influenciando o score de risco.

---

## Execução dos Módulos de Automação

Além do modo SOC, o S.A.T. mantém módulos independentes de automação executados via CLI.

Todos os módulos são orquestrados pelo comando:
  python -m sat run <módulo>

  
---

### Scanner de Portas TCP

Executa varredura de portas TCP e gera evidência estruturada.

#### Exemplos:
```bash
python -m sat run portscan -- 127.0.0.1 --common
```

#### Saída:
  outputs/port_scan.json

### Análise de Logs

Analisa arquivos de log com base em palavra-chave.

#### Exemplo:
```bash
python -m sat run loganalyzer -- --file scripts/auth.log --keyword Failed
```

#### Saída:
  outputs/log_report.json

### Verificador de Senhas

Executa análise simples de força de senha.

#### Exemplo:
```bash
python -m sat run password
```
#### Saída:
  outputs/password_report.json

### Relatório Consolidado

Consolida resultados dos módulos e classifica risco.
```bash
python -m sat run report
```
### Geração opcional de HTML:
```bash
python -m sat run report --html
```
#### Saída:
  reports/final_report.json
  reports/report.html

### O relatório inclui:

- Dashboard visual
- Score dinâmico de risco (0–100)
- Classificação automática (baixo / médio / alto)
- Alertas SOC destacados
- Consolidação de evidências técnicas
- Recomendações de segurança

## Funcionalidades Originais (Automação e Relatórios)

- Scanner de portas TCP
- Análise básica de logs
- Verificação de força de senha
- Consolidação de resultados em JSON
- Classificação automática de risco
- Geração de relatório executivo em HTML via Jinja2

---

### Competências Demonstradas

### Monitoramento e Detecção

- Normalização de logs em JSONL
- Correlação temporal de eventos
- Detecção comportamental
- Geração de alertas estruturados
- Enrichment de evidências
- MITRE ATT&CK mapping

### Arquitetura e Engenharia

- Arquitetura modular em Python
- Pipeline inspirado em SOC
- CLI modular (python -m sat)
- Separação entre ingestão, detecção e apresentação
- Logging estruturado
- Geração de relatórios automatizados

---

## Evolução Planejada

- Engine de regras baseada em YAML
- Correlação multi-evento
- Classificação dinâmica de risco
- Timeline de incidentes
- Integração com SIEM
- Simulação completa de investigação SOC

---

## Aviso

Este projeto foi desenvolvido exclusivamente para fins educacionais.
Não deve ser utilizado em ambientes de produção ou sistemas sem autorização.

---

## Autor

**Keven Silva**

Estudante de Segurança da Informação  
Foco em **SOC / Blue Team / Detection Engineering**

Projeto desenvolvido como portfólio técnico para vagas de estágio e júnior em Cibersegurança.
