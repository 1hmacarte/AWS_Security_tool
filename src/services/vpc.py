from .common import build_finding


def assess_vpc(vpc_client):
    results = []

    vpcs = vpc_client.describe_vpcs()
    for vpc in vpcs["Vpcs"]:
        vpc_id = vpc["VpcId"]
        security_groups = vpc_client.describe_security_groups(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )["SecurityGroups"]
        for security_group in security_groups:
            if security_group.get("GroupName") == "default":
                results.append(
                    build_finding(
                        "VPC has the default security group",
                        [vpc_id],
                        "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Security.html",
                    )
                )
                break

    return results