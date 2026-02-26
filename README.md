# Security Automation Toolkit (S.A.T.)

S.A.T. é um projeto prático em Cibersegurança desenvolvido em Python com foco na simulação de fluxo de trabalho de um Security Operations Center (SOC).

A ferramenta evoluiu de scripts independentes para uma arquitetura modular orquestrada via CLI, incorporando ingestão de logs, normalização de eventos em formato JSONL, correlação temporal (sliding window) e geração de alertas estruturados com impacto direto no cálculo de risco.

---

## Objetivo do Projeto

Demonstrar, de forma prática e aplicada:

- Automação em Segurança da Informação  
- Organização e consolidação de evidências técnicas  
- Estruturação de eventos no modelo similar a SIEM  
- Implementação de regras de detecção comportamental  
- Correlação temporal de eventos (sliding window)  
- Geração de alertas enriquecidos com contexto temporal  
- Integração de pipeline SOC com relatório executivo  
- Arquitetura modular orientada a CLI    

O projeto foi desenvolvido como portfólio técnico com foco em estágio/júnior em Segurança da Informação, especialmente em SOC / Blue Team.

---

## Arquitetura do Projeto


security-automation-toolkit/
├── sat/
│ ├── __main__.py
│ ├── cli.py
│ ├── soc/
│ │ ├── ingest.py
│ │ ├── detection.py
│ │ ├── models.py
│ ├── config/
│ └── utils/
├── scripts/
│ ├── port_scanner.py
│ ├── log_analyzer.py
│ ├── password_checker.py
│ ├── report_builder.py
│ └── auth_sample.log
├── outputs/
│ ├── soc_events_auth.jsonl
│ └── soc_alerts.jsonl
├── reports/
│ └── final_report.json
├── logs/
│ └── sat.log
└── README.md
  
---

## Funcionalidades — v1.2 (SOC Simulation Mode)

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

### 2. Detecção de Brute Force SSH

Regra baseada em correlação temporal:

Se um endereço IP registrar múltiplas falhas de login SSH dentro de uma janela de tempo definida, é gerado um alerta de severidade alta.

A detecção utiliza algoritmo de sliding window para correlação temporal.

#### Comando:
```bash
python -m sat detect bruteforce --threshold 5 --window 120
```
## Parâmetros:

- threshold: número mínimo de falhas
- window: janela de tempo (segundos)

#### Saída:
  outputs/soc_alerts.jsonl

## Exemplo de alerta:
{
  "alert_type": "brute_force_detected",
  "severity": "high",
  "src_ip": "192.168.1.10",
  "failed_attempts": 5,
  "window_seconds": 120,
  "first_seen": "2026-02-25T10:00:01",
  "last_seen": "2026-02-25T10:01:40",
  "status": "open"
}

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
- Recomendações

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
- Extração e manipulação de timestamp
- Correlação temporal (sliding window)
- Geração de alertas estruturados
- Enriquecimento de contexto (first_seen / last_seen)
- Integração de alertas ao cálculo dinâmico de risk scoring

### Arquitetura e Engenharia

- Arquitetura modular desacoplada
- Orquestração via CLI (`python -m sat`)
- Separação entre ingestão, detecção e apresentação
- Logging estruturado para auditoria
- Controle de execução via subprocess com ambiente isolado
- Geração dinâmica de relatórios via Jinja2

---

## Evolução Planejada

- Correlação entre múltiplos eventos
- Classificação dinâmica de severidade (risk scoring)
- Status de alerta (open, investigating, closed)
- Simulação de incidente com linha do tempo
- Integração futura com formato compatível com SIEM

---

## Aviso

Este projeto foi desenvolvido exclusivamente para fins educacionais.
Não deve ser utilizado em ambientes de produção ou sistemas sem autorização.

---

## Autor

Keven Silva  
Estudante de Segurança da Informação 
Projeto voltado para portfólio técnico e desenvolvimento profissional na área de Cibersegurança 
Foco em SOC / Blue Team
