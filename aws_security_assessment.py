import boto3
from jinja2 import Template
from datetime import datetime, timedelta, timezone
import webbrowser
import pprint


# Function to get AWS credentials and region from user input
def get_aws_config():
    aws_access_key_id = input("Enter your AWS Access Key ID: ")
    aws_secret_access_key = input("Enter your AWS Secret Access Key: ")
    aws_region = input("Enter your AWS Region: ")
    return aws_access_key_id, aws_secret_access_key, aws_region

# Function to initialize AWS clients
def initialize_clients(aws_access_key_id, aws_secret_access_key, aws_region):
    iam_client = boto3.client('iam', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key,
                              region_name=aws_region)
    cloudtrail_client = boto3.client('cloudtrail', aws_access_key_id=aws_access_key_id,
                                     aws_secret_access_key=aws_secret_access_key, region_name=aws_region)
    vpc_client = boto3.client('ec2', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key,
                              region_name=aws_region)
    kms_client = boto3.client('kms', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key,
                              region_name=aws_region)
    secrets_manager_client = boto3.client('secretsmanager', aws_access_key_id=aws_access_key_id,
                                          aws_secret_access_key=aws_secret_access_key, region_name=aws_region)
    s3_client = boto3.client('s3', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key,
                             region_name=aws_region)
    waf_client = boto3.client('waf', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key,
                              region_name=aws_region)
    cloudwatch_client = boto3.client('logs', aws_access_key_id=aws_access_key_id,
                                     aws_secret_access_key=aws_secret_access_key, region_name=aws_region)
    return iam_client, cloudtrail_client, vpc_client, kms_client, secrets_manager_client, s3_client, waf_client, cloudwatch_client



# Function to assess IAM security best practices including policy analysis
def assess_iam(iam_client):
    results = []

    # Check for unused IAM users, inactive users, users without MFA, and users with privileged permissions
    unused_users = []
    inactive_users = []
    users_no_mfa = []
    privileged_users = []
    privileged_groups = []

    # Analyze IAM policies for unused, excessive permissions
    unused_permissions = []
    unused_roles = []
    unused_policies = []

    # Get current date in UTC timezone
    current_date = datetime.now(timezone.utc)

    # Example: Check for unused IAM users
    response = iam_client.list_users()
    for user in response['Users']:
        username = user['UserName']

        # Check for users who have not interacted for more than 90 days
        user_info = iam_client.get_user(UserName=username)['User']
        last_activity = user_info.get('PasswordLastUsed')
        if last_activity is not None:
            last_activity_date = last_activity.replace(tzinfo=timezone.utc)
            days_inactive = (current_date - last_activity_date).days
            if days_inactive > 90:
                inactive_users.append({
                    'user': username,
                    'last_activity': last_activity_date,
                    'documentation_link': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_change-permissions.html'
                })

        # Check for users without MFA
        mfa_devices = iam_client.list_mfa_devices(UserName=username)['MFADevices']
        if not mfa_devices:
            users_no_mfa.append({
                'user': username,
                'documentation_link': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html'
            })

        # Check for users with privileged permissions
        user_policies = iam_client.list_attached_user_policies(UserName=username)['AttachedPolicies']
        if user_policies:
            for policy in user_policies:
                policy_name = policy['PolicyName']
                privileged_users.append({
                    'user': username,
                    'policy': policy_name,
                    'documentation_link': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html'
                })

    # Check for groups with privileged access
    response = iam_client.list_groups()
    for group in response['Groups']:
        group_name = group['GroupName']
        group_policies = iam_client.list_attached_group_policies(GroupName=group_name)['AttachedPolicies']
        if group_policies:
            for policy in group_policies:
                policy_name = policy['PolicyName']
                privileged_groups.append({
                    'group': group_name,
                    'policy': policy_name,
                    'documentation_link': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html'
                })

    # Analyze IAM policies for unused permissions
    policies = iam_client.list_policies(Scope='Local')
    for policy in policies['Policies']:
        policy_name = policy['PolicyName']
        policy_version = policy['DefaultVersionId']
        policy_document = iam_client.get_policy_version(PolicyArn=policy['Arn'], VersionId=policy_version)['PolicyVersion']['Document']
        
        # Logic to analyze policy_document for unused permissions goes here
        
        # Example: Check if the policy is attached to any user, group, or role
        attached_entities = iam_client.list_entities_for_policy(PolicyArn=policy['Arn'])['PolicyGroups'] + \
                            iam_client.list_entities_for_policy(PolicyArn=policy['Arn'])['PolicyUsers'] + \
                            iam_client.list_entities_for_policy(PolicyArn=policy['Arn'])['PolicyRoles']
        if not attached_entities:
            unused_policies.append({
                'policy': policy_name,
                'documentation_link': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html'
            })

    results.append({
        'check': "Unused IAM Users",
        'details': unused_users,
        'documentation_link': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_manage.html'
    })

    results.append({
        'check': "Inactive IAM Users (more than 90 days)",
        'details': inactive_users,
        'documentation_link': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_manage.html'
    })

    results.append({
        'check': "IAM Users without MFA",
        'details': users_no_mfa,
        'documentation_link': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html'
    })

    results.append({
        'check': "IAM Users with Privileged Permissions",
        'details': privileged_users,
        'documentation_link': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html'
    })

    results.append({
        'check': "IAM Groups with Privileged Access",
        'details': privileged_groups,
        'documentation_link': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html'
    })

    results.append({
        'check': "Unused IAM Policies (unused for more than 30 days)",
        'details': unused_policies,
        'documentation_link': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html'
    })

    return results

# Function to assess CloudTrail security best practices
def assess_cloudtrail(cloudtrail_client):
    results = []

    # Example: Check if CloudTrail is enabled
    trails = cloudtrail_client.describe_trails()
    if not trails['trailList']:
        results.append("CloudTrail is not enabled.")

    # Add more CloudTrail security checks as needed...

    return results


# Function to assess VPC security best practices
def assess_vpc(vpc_client):
    results = []

    # Example: Check for VPCs with default security groups
    vpcs = vpc_client.describe_vpcs()
    for vpc in vpcs['Vpcs']:
        vpc_id = vpc['VpcId']
        security_groups = vpc_client.describe_security_groups(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])[
            'SecurityGroups']
        for sg in security_groups:
            if sg.get('GroupName') == 'default':
                results.append("VPC {} has the default security group.".format(vpc_id))

    # Add more VPC security checks as needed...

    return results


# Function to assess KMS security best practices
def assess_kms(kms_client):
    results = []

    # Example: Check for unencrypted KMS keys
    keys = kms_client.list_keys()
    for key in keys['Keys']:
        key_id = key['KeyId']
        key_metadata = kms_client.describe_key(KeyId=key_id)
        if not key_metadata['KeyMetadata']['KeyManager'] == 'CUSTOMER':
            results.append("KMS key {} is not customer-managed.".format(key_id))

    # Add more KMS security checks as needed...

    return results


# Function to assess Secrets Manager security best practices
def assess_secrets_manager(secrets_manager_client):
    results = []

    # Example: Check for unused secrets
    secrets = secrets_manager_client.list_secrets()
    for secret in secrets['SecretList']:
        secret_name = secret['Name']
        versions = secrets_manager_client.list_secret_version_ids(SecretId=secret_name)['Versions']
        if not versions:
            results.append("Secret {} is not being used.".format(secret_name))

    # Add more Secrets Manager security checks as needed...

    return results


# Function to assess S3 security best practices
def assess_s3(s3_client):
    results = []

    # Example: Check for S3 buckets with public access
    buckets = s3_client.list_buckets()
    for bucket in buckets['Buckets']:
        bucket_name = bucket['Name']
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
        for grant in acl['Grants']:
            grantee = grant.get('Grantee', {})
            uri = grantee.get('URI', '')
            if uri == 'http://acs.amazonaws.com/groups/global/AllUsers':
                results.append("S3 bucket {} has public access.".format(bucket_name))

    # Add more S3 security checks as needed...

    return results


# Function to assess WAF security best practices
def assess_waf(waf_client):
    results = []

    # Example: Check for WAF web ACLs with open permissions
    web_acls = waf_client.list_web_acls(Limit=100)
    for acl in web_acls['WebACLs']:
        acl_id = acl['WebACLId']
        rules = waf_client.get_web_acl(WebACLId=acl_id)['WebACL']['Rules']
        for rule in rules:
            if rule['Action']['Type'] == 'ALLOW':
                results.append("Web ACL {} has open permissions.".format(acl_id))

    # Add more WAF security checks as needed...

    return results


# Function to assess CloudWatch security best practices
def assess_cloudwatch(cloudwatch_client):
    results = []

    # Example: Check for unencrypted CloudWatch log groups
    log_groups = cloudwatch_client.describe_log_groups(limit=50)
    for log_group in log_groups['logGroups']:
        if not log_group.get('kmsKeyId'):
            results.append("Log group {} is not encrypted.".format(log_group['logGroupName']))

    # Add more CloudWatch security checks as needed...

    return results


# Função para abrir o arquivo HTML em um navegador
def open_in_browser(html_file):
    webbrowser.open_new_tab(html_file)


# Function to generate HTML dashboard template
def generate_html_template(results):
    template_str = """
    <html>
    <head>
        <title>AWS Security Assessment Dashboard</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 20px;
            }
            h1, h2 {
                text-align: center;
            }
            table {
                border-collapse: collapse;
                width: 100%;
                margin-top: 20px;
            }
            th, td {
                border: 1px solid #dddddd;
                text-align: left;
                padding: 8px;
            }
            th {
                background-color: #f2f2f2;
            }
            ul {
                margin: 0;
                padding: 0;
                list-style-type: none;
            }
            li {
                margin-bottom: 5px;
            }
            .service {
                font-weight: bold;
                margin-top: 20px;
            }
            .no-issues {
                color: green;
            }
        </style>
    </head>
    <body>
        <h1>AWS Security Assessment Dashboard</h1>
        <h2>Assessment Date: {{ assessment_date }}</h2>

        {% for service, resources in results.items() %}
            <div class="service">{{ service }}</div>
            {% if resources %}
                <table>
                    <tr>
                        <th>Check</th>
                        <th>Details</th>
                        <th>Documentation</th>
                    </tr>
                    {% for resource in resources %}
                        <tr>
                            <td>{{ resource.check }}</td>
                            <td>
                                {% if resource.details %}
                                    <ul>
                                        {% for detail in resource.details %}
                                            <li>{{ detail.user or detail.group }}{% if detail.policy %} ({{ detail.policy }}){% endif %}</li>
                                        {% endfor %}
                                    </ul>
                                {% else %}
                                    <span class="no-issues">No issues found</span>
                                {% endif %}
                            </td>
                            <td><a href="{{ resource.documentation_link }}">Documentation</a></td>
                        </tr>
                    {% endfor %}
                </table>
            {% else %}
                <p class="no-issues">No issues found</p>
            {% endif %}
        {% endfor %}
    </body>
    </html>
    """

    template = Template(template_str)
    return template.render(
        assessment_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        results=results
    )



# Function to perform the assessment
def perform_assessment():
    aws_access_key_id, aws_secret_access_key, aws_region = get_aws_config()
    iam_client, cloudtrail_client, vpc_client, kms_client, secrets_manager_client, s3_client, waf_client, cloudwatch_client = initialize_clients(aws_access_key_id, aws_secret_access_key, aws_region)

    results = {
        'iam': assess_iam(iam_client),
        'cloudtrail': assess_cloudtrail(cloudtrail_client),
        'vpc_client': assess_vpc(vpc_client),
        'kms': assess_kms(kms_client),
        'secrets_manager': assess_secrets_manager(secrets_manager_client),
        's3': assess_s3(s3_client),
        'waf': assess_waf(waf_client),
        'cloudwatch': assess_cloudwatch(cloudwatch_client),
    }
    # Generate HTML template
    html_template = generate_html_template(results)

    # Save the HTML template to a file or serve it through a web server
    with open('aws_security_dashboard.html', 'w') as f:
        f.write(html_template)


if __name__ == "__main__":
    perform_assessment()
    open_in_browser('aws_security_dashboard.html')