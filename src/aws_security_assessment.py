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
    aws_profile, aws_region = get_aws_config()
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
    open_in_browser(report_path)
    return report_path


if __name__ == "__main__":
    perform_assessment()