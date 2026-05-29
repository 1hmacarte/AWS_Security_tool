from .common import build_finding


def assess_cloudwatch(cloudwatch_client):
    results = []

    log_groups = cloudwatch_client.describe_log_groups(limit=50)
    for log_group in log_groups["logGroups"]:
        if not log_group.get("kmsKeyId"):
            results.append(
                build_finding(
                    "CloudWatch log group is not encrypted",
                    [log_group["logGroupName"]],
                    "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/EncryptLogData.html",
                )
            )

    return results