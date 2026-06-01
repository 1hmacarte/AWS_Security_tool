from datetime import datetime, timezone

from .common import build_finding


def assess_iam(iam_client):
    results = []
    inactive_users = []
    users_no_mfa = []
    privileged_users = []
    privileged_groups = []
    unused_policies = []

    current_date = datetime.now(timezone.utc)

    response = iam_client.list_users()
    for user in response["Users"]:
        username = user["UserName"]

        user_info = iam_client.get_user(UserName=username)["User"]
        last_activity = user_info.get("PasswordLastUsed")
        if last_activity is not None:
            last_activity_date = last_activity.replace(tzinfo=timezone.utc)
            days_inactive = (current_date - last_activity_date).days
            if days_inactive > 90:
                inactive_users.append(f"{username} last active on {last_activity_date.date()}")

        mfa_devices = iam_client.list_mfa_devices(UserName=username)["MFADevices"]
        if not mfa_devices:
            users_no_mfa.append(username)

        user_policies = iam_client.list_attached_user_policies(UserName=username)["AttachedPolicies"]
        for policy in user_policies:
            privileged_users.append(f"{username} ({policy['PolicyName']})")

    response = iam_client.list_groups()
    for group in response["Groups"]:
        group_name = group["GroupName"]
        group_policies = iam_client.list_attached_group_policies(GroupName=group_name)["AttachedPolicies"]
        for policy in group_policies:
            privileged_groups.append(f"{group_name} ({policy['PolicyName']})")

    policies = iam_client.list_policies(Scope="Local")
    for policy in policies["Policies"]:
        policy_name = policy["PolicyName"]
        attached_entities = iam_client.list_entities_for_policy(PolicyArn=policy["Arn"])
        if not (
            attached_entities["PolicyGroups"]
            or attached_entities["PolicyUsers"]
            or attached_entities["PolicyRoles"]
        ):
            unused_policies.append(policy_name)

    if inactive_users:
        results.append(
            build_finding(
                "Inactive IAM Users (more than 90 days)",
                inactive_users,
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_manage.html",
            )
        )

    if users_no_mfa:
        results.append(
            build_finding(
                "IAM Users without MFA",
                users_no_mfa,
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html",
            )
        )

    if privileged_users:
        results.append(
            build_finding(
                "IAM Users with Privileged Permissions",
                privileged_users,
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html",
            )
        )

    if privileged_groups:
        results.append(
            build_finding(
                "IAM Groups with Privileged Access",
                privileged_groups,
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html",
            )
        )

    if unused_policies:
        results.append(
            build_finding(
                "Unused IAM Policies",
                unused_policies,
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html",
            )
        )

    return results