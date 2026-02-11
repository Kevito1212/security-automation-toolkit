# Security Automation Toolkit (S.A.T.)

Projeto prático em **Cibersegurança** com foco em **automação de tarefas básicas de Segurança da Informação**, **análise inicial de riscos** e **geração de relatórios técnicos em HTML**, desenvolvido em Python.

O projeto evolui de scripts independentes para uma **ferramenta orquestrada via CLI**, seguindo padrões comuns utilizados em ambientes corporativos de segurança.

## Arquitetura do Projeto

O Security Automation Toolkit (S.A.T.) segue um padrão próximo ao utilizado em ambientes corporativos de segurança:

- **Configuração centralizada** via `config.yaml`
- **CLI (`python -m sat`) como ponto único de execução**
- **Módulos desacoplados** executados via orquestração
- **Logging estruturado** para auditoria e troubleshooting
- **Consolidação de resultados em JSON**
-  **Renderização de relatório executivo via Jinja2**

---

## Objetivo do Projeto

Demonstrar, de forma prática e aplicada, conceitos fundamentais de:

- Automação em Segurança da Informação  
- Organização e consolidação de evidências técnicas  
- Classificação inicial de risco baseada em achados  
- Geração de relatórios executivos estruturados  
- Arquitetura modular orientada a CLI  
- Separação entre coleta, processamento e apresentação 

Este projeto foi pensado como **portfólio técnico**, com foco em **estágio/júnior em Segurança da Informação**.

---

## Funcionalidades — v1.1

- Scanner de portas TCP
- Análise básica de logs (tentativas de login)
- Verificação de força de senha
- Consolidação de resultados em `final_report.json`
- Classificação automática de risco (low / medium / high)
- Geração de relatório executivo em HTML
- Registro de:
  - Data de geração dos dados
  - Data de renderização do relatório
- Execução unificada via CLI

---

## Evolução Planejada — v2

- Logs em formato JSON (preparação para integração com SIEM)
- Configuração por ambiente (dev / prod)
- Exportação de relatório em PDF
- Testes automatizados básicos
- Padronização de códigos de saída
- Refinamento da métrica de risco

---

## Tecnologias Utilizadas

- Python 3.10+
- Jinja2 (renderização HTML)
- Redes TCP/IP
- Estruturação de CLI
- Automação de tarefas
- Análise básica de logs
- Organização de evidências técnicas

---

## ▶ Como Executar

### Pré-requisitos

- Python 3.10 ou superior
- Ambiente local (Windows ou Linux)

Verificar versão:

```bash
python --version
´´´

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
python -m sat run loganalyzer -- --file scripts/auth.log --keyword failed
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
```bash
reports/final_report.json
```

### Gerar Relatório Executivo em HTML
```bash
python -m scripts.render_html_test
```

#### Arquivo gerado:
```bash
reports/report.html
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
│       ├── logger.py        # Logging estruturado
│       └── html_renderer.py
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
Estudante de Segurança da Informação
Projeto voltado para portfólio técnico e desenvolvimento profissional na área de Cibersegurança

