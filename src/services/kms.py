from .common import build_finding


def assess_kms(kms_client):
    results = []

    keys = kms_client.list_keys()
    for key in keys["Keys"]:
        key_id = key["KeyId"]
        key_metadata = kms_client.describe_key(KeyId=key_id)
        if key_metadata["KeyMetadata"]["KeyManager"] != "CUSTOMER":
            results.append(
                build_finding(
                    "KMS key is not customer-managed",
                    [key_id],
                    "https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#customer-managed-cmk",
                )
            )

    return results