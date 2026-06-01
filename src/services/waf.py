from .common import build_finding


def assess_waf(waf_client):
    results = []

    web_acls = waf_client.list_web_acls(Limit=100)
    for acl in web_acls["WebACLs"]:
        acl_id = acl["WebACLId"]
        rules = waf_client.get_web_acl(WebACLId=acl_id)["WebACL"]["Rules"]
        for rule in rules:
            if rule["Action"]["Type"] == "ALLOW":
                results.append(
                    build_finding(
                        "WAF web ACL has an allow rule",
                        [acl_id],
                        "https://docs.aws.amazon.com/waf/latest/developerguide/waf-security-best-practices.html",
                    )
                )
                break

    return results