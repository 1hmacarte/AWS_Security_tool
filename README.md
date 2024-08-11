# AWS_Security_tool

Ferramenta de Avaliação de Segurança AWS 

Objetivo 

A ferramenta de Avaliação de Segurança AWS foi desenvolvida para ajudar administradores e analistas de segurança a monitorar e identificar possíveis vulnerabilidades e configurações incorretas em suas contas AWS. O objetivo é fornecer uma avaliação detalhada das melhores práticas de segurança, focando em componentes essenciais como IAM, CloudTrail, VPC, KMS, Secrets Manager, S3, WAF e CloudWatch. 

Funcionalidades 

Análise IAM: Identifica usuários e grupos com permissões privilegiadas, usuários inativos e usuários sem MFA, além de analisar políticas IAM não utilizadas. 

Monitoramento CloudTrail: Verifica se o CloudTrail está habilitado e realiza outras verificações de segurança. 

Avaliação de VPC: Identifica VPCs com grupos de segurança padrão, que podem representar um risco de segurança. 

Avaliação de KMS: Verifica chaves KMS para garantir que sejam gerenciadas pelo cliente. 

Monitoramento Secrets Manager: Identifica segredos não utilizados, ajudando a evitar riscos de exposição de dados sensíveis. 

Análise de S3: Detecta buckets S3 com acesso público. 

Avaliação de WAF: Verifica ACLs da Web com permissões abertas. 

Verificação CloudWatch: Avalia grupos de logs do CloudWatch para garantir que estejam criptografados. 

Como a Ferramenta Funciona 

A ferramenta se conecta à sua conta AWS usando suas credenciais e coleta informações sobre os recursos configurados. Em seguida, realiza uma análise detalhada com base nas melhores práticas de segurança da AWS e gera um relatório em formato HTML com uma visão geral dos resultados. O relatório destaca potenciais problemas de segurança e fornece links para a documentação oficial da AWS para cada problema identificado. 

Próximos passos : https://github.com/1hmacarte/AWS_Security_tool/blob/master/README.md

![image](https://github.com/user-attachments/assets/2e304244-b3d1-4b3a-ab23-8bb8d3c60697)

![image](https://github.com/1hmacarte/assets/blob/drwa/AWS%20Assessment%20dash1.PNG)



 
