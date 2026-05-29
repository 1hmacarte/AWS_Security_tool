# CloudAssess

## Visão Geral

A **CloudAssess** é uma ferramenta projetada para realizar uma avaliação abrangente das configurações de segurança na sua conta AWS. Ela verifica uma série de serviços AWS, incluindo IAM, CloudTrail, VPC, KMS, Secrets Manager, S3, WAF e CloudWatch, e gera um relatório detalhado com recomendações e melhores práticas de segurança.

## Funcionalidades

- **Análise IAM**: Identificação de usuários sem MFA, usuários inativos, e grupos/usuários com permissões privilegiadas.
- **Monitoramento CloudTrail**: Verifica se o CloudTrail está habilitado.
- **Avaliação VPC**: Identifica grupos de segurança padrão em VPCs.
- **Avaliação KMS**: Verifica se as chaves KMS são gerenciadas pelo cliente.
- **Monitoramento Secrets Manager**: Identifica segredos não utilizados.
- **Análise S3**: Detecta buckets S3 com acesso público.
- **Avaliação WAF**: Verifica ACLs da Web com permissões abertas.
- **Verificação CloudWatch**: Avalia grupos de logs do CloudWatch para garantir criptografia.

## Pré-requisitos

- **Python 3.x**
- **Boto3**
- **Jinja2**

## Instalação

1. Clone o repositório:
1. Clone o repositório:

    ```bash
    git clone https://github.com/1hmacarte/AWS_Security_tool.git
    cd AWS_Security_tool
    ```

2. (Opcional) Crie e ative um ambiente virtual:

    ```bash
    python -m venv .venv
    # Windows
    .venv\Scripts\Activate.ps1
    # Linux / macOS
    source .venv/bin/activate
    ```

3. Instale as dependências:

    ```bash
    pip install -r requirements.txt
    ```

3. Configure suas credenciais AWS. Você pode fazer isso de várias maneiras, como configurando variáveis de ambiente ou usando um arquivo de configuração.

**Conectar sem chaves (sem chaves estáticas)**

Recomendado: evite armazenar `AWS_ACCESS_KEY_ID` e `AWS_SECRET_ACCESS_KEY` no código. Abaixo estão formas comuns de conectar sem usar chaves estáticas.

- Executando dentro da AWS (EC2, ECS, Lambda): atribua uma *IAM Role* ao recurso (Instance Profile / Task Role / Function Role). O SDK (boto3) usará automaticamente as credenciais temporárias fornecidas pelo metadata service.

- Desenvolvimento local com AWS SSO (IAM Identity Center):

        ```bash
        aws configure sso --profile meu-perfil
        aws sso login --profile meu-perfil
        ```

        Depois use o profile no CLI ou no Python (`boto3.Session(profile_name='meu-perfil')`).

**Uso rápido (Windows PowerShell) — sem chaves estáticas**

Verifique o CLI e a identidade ativa:

```powershell
aws --version
aws sts get-caller-identity
```

Se usar AWS SSO e ainda não logou, configure e faça login:

```powershell
aws configure sso --profile meu-perfil
aws sso login --profile meu-perfil
```

Executar a ferramenta (usa a cadeia de credenciais padrão: SSO, profile, ENV ou metadata):

```powershell
python src/aws_security_assessment.py
```

Exemplos alternativos:

```powershell
# Usar um profile/region específicos
python src/aws_security_assessment.py --profile meu-perfil --region us-east-1

# Não abrir o navegador (útil em servidor)
python src/aws_security_assessment.py --no-browser

# Forçar prompts interativos
python src/aws_security_assessment.py --interactive
```

Resultado: o script exibirá a identidade ativa e imprimirá o caminho do relatório (ex.: `Report saved to: C:\...\aws_security_dashboard.html`). Para abrir manualmente:

```powershell
start C:\full\path\to\aws_security_dashboard.html
```

- Ferramentas úteis para desenvolvimento local (opcionais): `aws-vault`, `awsume` — armazenam credenciais de forma segura e geram credenciais temporárias.

- Uso no Python com `boto3` (sem chaves estáticas):

        ```python
        import boto3

        # Usa a cadeia de credenciais padrão: SSO/profile, variáveis de ambiente,
        # shared credentials file, ou metadata do EC2/ECS
        session = boto3.Session()
        sts = session.client('sts')
        print(sts.get_caller_identity())

        # Ou usar um profile configurado com SSO
        # session = boto3.Session(profile_name='meu-perfil')
        ```

Verifique sempre a identidade ativa para confirmar a conexão:

```bash
aws sts get-caller-identity --profile meu-perfil
# ou se estiver usando credentials do ambiente/metadata
aws sts get-caller-identity
```

## Uso

1. Execute a ferramenta:

    ```bash
    python src/aws_security_assessment.py
    ```

2. Insira suas credenciais AWS e a região desejada quando solicitado.

3. A ferramenta irá gerar um relatório em formato HTML chamado `aws_security_dashboard.html`. Este relatório fornecerá uma visão detalhada das suas configurações de segurança na AWS.

4. Abra o relatório no navegador:

    ```bash
    start aws_security_dashboard.html
    ```

Exemplos de execução (sem chaves estáticas)

- Executa usando a cadeia de credenciais padrão (SSO/profile, env vars, metadata):

    ```bash
    python src/aws_security_assessment.py
    ```

    Saída esperada (exemplo):

    ```text
    Using AWS profile: default/credential-chain; region: us-east-1
    Connected to AWS account 123456789012 as arn:aws:iam::123456789012:user/me
    Report saved to: /full/path/to/aws_security_dashboard.html
    ```

- Executa sem abrir o navegador (útil em servidores):

    ```bash
    python src/aws_security_assessment.py --no-browser
    ```

- Usando um profile SSO já configurado:

    ```bash
    python src/aws_security_assessment.py --profile meu-perfil --region us-east-1
    ```

- Forçar prompts interativos:

    ```bash
    python src/aws_security_assessment.py --interactive
    ```

## Estrutura

- `src/aws_security_assessment.py`: ponto de entrada da aplicação.
- `src/config.py`: leitura das credenciais e criação dos clientes AWS.
- `src/services/`: verificações por serviço AWS.
- `src/reporting.py`: renderização e abertura do relatório HTML.
- `src/templates/aws_security_dashboard.html`: template do dashboard.

## Recomendações

- **Segurança de Credenciais**: Não compartilhe suas credenciais AWS. Use perfis de usuário com permissões mínimas necessárias.
- **Auditoria Regular**: Execute a ferramenta regularmente para garantir que suas configurações de segurança estejam atualizadas.
- **Integração CI/CD**: Considere integrar esta ferramenta em seu pipeline de CI/CD para verificar automaticamente as configurações de segurança ao fazer deploy de novos recursos na AWS.

## Contribuição

Sinta-se à vontade para enviar PRs com melhorias e correções. Sugestões e feedbacks são bem-vindos!

## Licença

Este projeto está licenciado sob a [MIT License](LICENSE).

## Documentação e Referências

- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [AWS Security Best Practices](https://aws.amazon.com/whitepapers/security-best-practices/)
