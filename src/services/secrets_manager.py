from .common import build_finding


def assess_secrets_manager(secrets_manager_client):
    results = []

    secrets = secrets_manager_client.list_secrets()
    for secret in secrets["SecretList"]:
        secret_name = secret["Name"]
        versions = secrets_manager_client.list_secret_version_ids(SecretId=secret_name)["Versions"]
        if not versions:
            results.append(
                build_finding(
                    "Secrets Manager secret is not being used",
                    [secret_name],
                    "https://docs.aws.amazon.com/secretsmanager/latest/userguide/best-practices.html",
                )
            )

    return results