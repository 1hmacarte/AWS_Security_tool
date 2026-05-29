import boto3
from botocore.exceptions import ClientError, NoCredentialsError


def get_aws_config():
    """Get AWS profile and region from user input.

    If the user leaves the profile blank, the default credentials chain will be
    used (environment variables, shared credentials, SSO, or instance metadata).
    """
    aws_profile = input("Enter your AWS profile name (leave blank to use default): ")
    aws_region = input("Enter your AWS Region (leave blank to use default/ENV): ")
    aws_profile = aws_profile.strip() or None
    aws_region = aws_region.strip() or None
    return aws_profile, aws_region


def initialize_clients(aws_profile, aws_region):
    """Initialize boto3 session and service clients.

    Returns a dict with AWS service clients. Attempts to validate the
    credentials by calling STS and prints the active identity.
    """
    session = boto3.Session(profile_name=aws_profile, region_name=aws_region)

    # Validate credentials / show active identity (best-effort)
    try:
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        account = identity.get("Account")
        arn = identity.get("Arn")
        print(f"Connected to AWS account {account} as {arn}")
    except (NoCredentialsError, ClientError) as e:
        print("Warning: não foi possível validar as credenciais AWS:", str(e))

    return {
        "iam": session.client("iam"),
        "cloudtrail": session.client("cloudtrail"),
        "vpc": session.client("ec2"),
        "kms": session.client("kms"),
        "secrets_manager": session.client("secretsmanager"),
        "s3": session.client("s3"),
        "waf": session.client("waf"),
        "cloudwatch": session.client("logs"),
    }