import boto3


def get_aws_config():
    aws_profile = input("Enter your AWS SSO profile name: ")
    aws_region = input("Enter your AWS Region: ")
    return aws_profile, aws_region


def initialize_clients(aws_profile, aws_region):
    session = boto3.Session(profile_name=aws_profile, region_name=aws_region)

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