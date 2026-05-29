from .common import build_finding


def assess_cloudtrail(cloudtrail_client):
    results = []

    trails = cloudtrail_client.describe_trails()
    if not trails["trailList"]:
        results.append(
            build_finding(
                "CloudTrail is not enabled",
                ["No CloudTrail trails were found."],
                "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html",
            )
        )

    return results