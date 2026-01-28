# Scanner de Portas – Documentação

## Objetivo
Este script foi desenvolvido para identificar portas de rede abertas em um host, auxiliando na detecção de serviços expostos que podem representar riscos à segurança da informação.

## Como funciona
O script utiliza a biblioteca socket do Python para tentar estabelecer conexões TCP em portas previamente definidas. Caso a conexão seja bem-sucedida, a porta é considerada aberta.

## Por que isso é importante em segurança
Portas abertas indicam serviços em execução. Serviços mal configurados ou desnecessários aumentam a superfície de ataque de um ambiente, podendo ser explorados por atacantes.

## Exemplo de risco
- Porta 22 (SSH) aberta pode ser alvo de ataques de força bruta.
- Porta 3306 (MySQL) exposta pode permitir acesso indevido ao banco de dados.

## Mitigações
- Fechar portas não utilizadas
- Restringir acesso por firewall
- Utilizar autenticação forte e monitoramento
