# Security Automation Toolkit

Projeto prático em Cibersegurança com foco em automação de tarefas básicas de segurança da informação utilizando Python. O projeto simula controles de segurança comuns em ambientes corporativos, com ênfase em aprendizado prático, análise de risco e documentação técnica.

---

## Objetivo do Projeto
Demonstrar, de forma prática, conceitos fundamentais de Segurança da Informação, automação e monitoramento, por meio do desenvolvimento de scripts simples, funcionais e bem documentados.

---

## Funcionalidades
- Scanner de portas para identificação de serviços de rede expostos
- Verificação de senhas fracas com base em listas comuns
- Análise simples de logs de autenticação
- Scripts desenvolvidos para fins educacionais e testes controlados

---

## Como executar

### Scanner de portas
```bash 
# Scan utilizando portas comuns
python scripts/port_scanner.py 127.0.0.1 --common

# Scan com portas específicas
python scripts/port_scanner.py 127.0.0.1 --ports 22,80,443

# Scan com range de portas e timeout ajustado
python scripts/port_scanner.py 127.0.0.1 --ports 1-200 --timeout 0.1
```
A execução do scanner gera um relatório em formato JSON contendo:
- host analisado
- portas escaneadas
- portas abertas
- timestamps da execução

Arquivo gerado:

outputs/port_scan.json

### Analisador de logs
```bash
python scripts/log_analyzer.py
python scripts/log_analyzer.py --file scripts/auth.log --keyword failed
```
Arquivo gerado:

outputs/log_report.json

### Verificador de senhas
```bash
python scripts/password_checker.py
```
Arquivo gerado:

outputs/password_report.json

### Relatório final
```bash
python scripts/report_builder.py
```
Arquivo gerado:

outputs/final_report.json


## Tecnologias Utilizadas
- Python 3
- Redes TCP/IP
- Segurança da Informação
- Automação de tarefas
- Análise de logs

---

## Estrutura do Projeto
security-automation-toolkit/
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
└── README.md


---

## Aviso Importante
Este projeto foi desenvolvido exclusivamente para fins educacionais e demonstração de conceitos. Não deve ser utilizado em ambientes de produção nem em sistemas sem autorização prévia.

---

## Próximos Passos
- Evoluir os scripts com novas verificações de segurança
- Implementar geração de relatórios automatizados
- Criar visualizações simples dos resultados
- Expandir o projeto para ambientes simulados mais complexos

---

## Autor
Keven Silva  
Estudante de Segurança da Informação

