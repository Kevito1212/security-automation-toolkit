# Security Automation Toolkit (S.A.T.)

Projeto prático em **Cibersegurança** com foco em **automação de tarefas básicas de Segurança da Informação**, **análise inicial de riscos** e **geração de relatórios técnicos em HTML**, desenvolvido em Python.

O projeto evolui de scripts independentes para uma **ferramenta orquestrada via CLI**, seguindo padrões comuns utilizados em ambientes corporativos de segurança.

---

## Objetivo do Projeto

Demonstrar, de forma prática e aplicada, conceitos fundamentais de:

- Segurança da Informação
- Automação de tarefas de segurança
- Análise e organização de evidências
- Classificação inicial de riscos
- Geração de relatórios técnicos
- Uso de CLI como camada de orquestração

Este projeto foi pensado como **portfólio técnico**, com foco em **estágio/júnior em Segurança da Informação**.

---

## Funcionalidades

### Versão Atual — v1.1

- Scanner de portas TCP para identificação de serviços expostos
- Consolidação de resultados de varredura
- Classificação básica de risco (low / medium / high)
- Geração de relatório técnico em HTML com resumo executivo
- Execução unificada por meio de CLI

### Funcionalidades em Evolução — v2 (planejado)

- Verificação de senhas fracas com base em listas comuns
- Análise simples de logs de autenticação
- Logging estruturado
- Configuração centralizada via arquivo YAML
- Expansão de módulos educacionais ofensivos e defensivos

---

## Tecnologias Utilizadas

- Python 3.10+
- Redes TCP/IP
- Segurança da Informação
- Automação de tarefas
- Análise de logs
- CLI (Command Line Interface)

---

## Como Executar

### Pré-requisitos

- Python 3.10 ou superior
- Ambiente local (Windows ou Linux)

Verificar versão do Python:

```bash
python --version
```

## Execução via CLI (recomendado)

### Teste rápido da CLI
```bash
python -m sat.cli ping
```

### Listar arquivos gerados
```bash
python -m sat.cli list-outputs
```

### Execução dos Módulos

### Scanner de Portas
```bash
python -m sat.cli run portscan 127.0.0.1 --common
python -m sat.cli run portscan 127.0.0.1 --ports 22,80,443
python -m sat.cli run portscan 127.0.0.1 --ports 1-200 --timeout 0.1
```

#### Arquivo gerado:
```bash
outputs/port_scan.json
```

### Analisador de Logs
```bash
python scripts/log_analyzer.py
python scripts/log_analyzer.py --file scripts/auth.log --keyword failed
```

#### Arquivo gerado:
```bash
outputs/log_report.json
```

### Verificador de Senhas
```bash
python -m sat.cli run password
```

#### Arquivo gerado:
```bash
outputs/password_report.json
```

### Relatório HTML
```bash
python -m sat.cli run report
```

#### Arquivo gerado:
```text
outputs/final_report.json
reports/out/report.html
```

---

## Estrutura do Projeto
security-automation-toolkit/
├── sat/
│   ├── __init__.py
│   └── cli.py
├── config/
│   └── config.yaml
├── scripts/
│   ├── port_scanner.py
│   ├── log_analyzer.py
│   ├── password_checker.py
│   ├── report_builder.py
│   └── auth.log
├── docs/
│   ├── scanner_explicacao.md
│   ├── password_checker_explicacao.md
│   └── log_analyzer_explicacao.md
├── outputs/
│   ├── port_scan.json
│   ├── log_report.json
│   ├── password_report.json
│   └── final_report.json
├── reports/
│   ├── report_template.html
│   └── out/
│       └── report.html
└── README.md

---

## Aviso Importante
Este projeto foi desenvolvido exclusivamente para fins educacionais e demonstração de conceitos.
Não deve ser utilizado em ambientes de produção nem em sistemas sem autorização prévia.

---

## Autor
Keven Silva  
Estudante de Segurança da Informação

