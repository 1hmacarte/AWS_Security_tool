import os
import argparse

from config import get_aws_config, initialize_clients
from reporting import generate_html_template, open_in_browser, save_report
from services import (
    assess_cloudtrail,
    assess_cloudwatch,
    assess_iam,
    assess_kms,
    assess_s3,
    assess_secrets_manager,
    assess_vpc,
    assess_waf,
)


def perform_assessment():
    parser = argparse.ArgumentParser(description="Run AWS security assessment")
    parser.add_argument("--profile", help="AWS profile name (optional)")
    parser.add_argument("--region", help="AWS region (optional)")
    parser.add_argument("--interactive", action="store_true", help="Prompt for profile and region")
    parser.add_argument("--no-browser", action="store_true", help="Do not open the HTML report in a browser")
    args = parser.parse_args()

    if args.interactive:
        aws_profile, aws_region = get_aws_config()
    else:
        aws_profile = args.profile or os.getenv("AWS_PROFILE")
        aws_region = args.region or os.getenv("AWS_REGION")

    print(f"Using AWS profile: {aws_profile or 'default/credential-chain'}; region: {aws_region or 'default'}")
    clients = initialize_clients(aws_profile, aws_region)

    results = {
        "IAM": assess_iam(clients["iam"]),
        "CloudTrail": assess_cloudtrail(clients["cloudtrail"]),
        "VPC": assess_vpc(clients["vpc"]),
        "KMS": assess_kms(clients["kms"]),
        "Secrets Manager": assess_secrets_manager(clients["secrets_manager"]),
        "S3": assess_s3(clients["s3"]),
        "WAF": assess_waf(clients["waf"]),
        "CloudWatch": assess_cloudwatch(clients["cloudwatch"]),
    }

    html_template = generate_html_template(results)
    report_path = save_report(html_template)
    print(f"Report saved to: {report_path}")

    if not args.no_browser:
        open_in_browser(report_path)

    return report_path


if __name__ == "__main__":
    perform_assessment()