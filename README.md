# Security Automation Toolkit (S.A.T.)

Projeto prático em **Cibersegurança** com foco em **automação de tarefas básicas de Segurança da Informação**, **análise inicial de riscos** e **geração de relatórios técnicos em HTML**, desenvolvido em Python.

O projeto evolui de scripts independentes para uma **ferramenta orquestrada via CLI**, seguindo padrões comuns utilizados em ambientes corporativos de segurança.

## Arquitetura do Projeto

O Security Automation Toolkit (S.A.T.) segue um padrão próximo ao utilizado em ambientes corporativos de segurança:

- **Configuração centralizada** via `config.yaml`
- **CLI (`sat`) como ponto único de execução**
- **Módulos desacoplados** executados via orquestração
- **Logging estruturado** para auditoria e troubleshooting
- **Separação clara** entre código, configuração, logs e outputs

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

- Logs em formato JSON (preparação para SIEM)
- Configuração por ambiente (dev / prod)
- Códigos de saída padronizados
- Testes automatizados básicos
- Exportação de relatórios em múltiplos formatos


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
python -m sat ping
```

### Listar arquivos gerados
```bash
python -m sat list-outputs
```

### Execução dos Módulos

### Scanner de Portas
```bash
python -m sat run portscan -- 127.0.0.1 --common
python -m sat run portscan -- 127.0.0.1 --ports 22,80,443
python -m sat run portscan -- 127.0.0.1 --ports 1-200 --timeout 0.1
```

#### Arquivo gerado:
```bash
outputs/port_scan.json
```

### Analisador de Logs
```bash
python -m sat run loganalyzer -- --file scripts/auth.log --keyword failed --out outputs/log_report.json
```

#### Arquivo gerado:
```bash
outputs/log_report.json
```

### Verificador de Senhas
```bash
python -m sat run password
```

#### Arquivo gerado:
```bash
outputs/password_report.json
```

### Relatório Consolidado
```bash
python -m sat run report
```

#### Arquivo gerado:
```text
outputs/final_report.json
```

---

## Estrutura do Projeto
security-automation-toolkit/
├── sat/
│   ├── __init__.py
│   ├── __main__.py          # Entry point do pacote (python -m sat)
│   ├── cli.py               # CLI principal (orquestração)
│   ├── config/
│   │   └── config.yaml      # Configuração centralizada
│   └── utils/
│       ├── config_loader.py # Loader e validação de config
│       └── logger.py        # Logging estruturado
│
├── scripts/                 # Módulos executados via CLI
│   ├── port_scanner.py
│   ├── log_analyzer.py
│   ├── password_checker.py
│   ├── report_builder.py
│   └── auth.log
│
├── docs/                    # Documentação técnica dos módulos
│   ├── scanner_explicacao.md
│   ├── password_checker_explicacao.md
│   └── log_analyzer_explicacao.md
│
├── outputs/                 # Evidências e resultados intermediários
│   ├── port_scan.json
│   ├── log_report.json
│   └── password_report.json
│
├── reports/                 # Relatórios consolidados
│   └── final_report.json
│
├── logs/                    # Logs estruturados da aplicação
│   └── sat.log
│
└── README.md


---

## Aviso Importante
Este projeto foi desenvolvido exclusivamente para fins educacionais e demonstração de conceitos.
Não deve ser utilizado em ambientes de produção nem em sistemas sem autorização prévia.

---

## Autor
Keven Silva  
Estudante de Segurança da Informação

