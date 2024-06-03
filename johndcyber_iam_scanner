rimport boto3
import json
import logging
import csv
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("johndcyber_iam_scanner.log"),
        logging.StreamHandler()
    ]
)

# Initialize the IAM client
iam_client = boto3.client('iam')

# Define high-risk actions and their MITRE ATT&CK mappings for categorization
high_risk_actions = {
    "iam:CreateUser": "T1078",
    "iam:DeleteUser": "T1531",
    "iam:PutUserPolicy": "T1098",
    "iam:AttachUserPolicy": "T1098",
    "iam:DetachUserPolicy": "T1098",
    "iam:UpdateUser": "T1098",
    "iam:CreateAccessKey": "T1078",
    "iam:DeleteAccessKey": "T1531",
    "iam:UpdateAccessKey": "T1098",
    "iam:CreateRole": "T1078",
    "iam:DeleteRole": "T1531",
    "iam:PutRolePolicy": "T1098",
    "iam:AttachRolePolicy": "T1098",
    "iam:DetachRolePolicy": "T1098",
    "iam:UpdateRole": "T1098",
    "sts:GetCallerIdentity": "T1538",
    "sts:AssumeRole": "T1528",
    "ec2:Create*": "T1106",
    "ec2:Delete*": "T1531",
    "ec2:Modify*": "T1106",
    "s3:Put*": "T1106",
    "s3:Delete*": "T1531",
    "kms:Encrypt": "T1106",
    "kms:Decrypt": "T1106",
    "kms:ReEncrypt*": "T1106",
    "kms:CreateGrant": "T1106",
    "lambda:InvokeFunction": "T1106",
    "iam:PassRole": "T1098",
    "iam:CreatePolicy": "T1098",
    "iam:AttachRolePolicy": "T1098",
    "iam:PutRolePolicy": "T1098",
    "iam:CreateAccessKey": "T1078",
    "iam:DeleteAccessKey": "T1531"
}

# Define PACU IAM module actions
pacu_iam_actions = [
    "iam:CreateUser", "iam:AttachUserPolicy", "iam:DetachUserPolicy",
    "iam:CreateAccessKey", "iam:DeleteAccessKey", "iam:UpdateAccessKey",
    "iam:CreateRole", "iam:PutRolePolicy", "iam:AttachRolePolicy",
    "iam:DetachRolePolicy", "iam:PassRole"
]

# Define common read-only actions
read_only_actions = [
    "s3:Get*", "s3:List*",
    "ec2:Describe*", "rds:Describe*",
    "cloudwatch:Get*", "cloudwatch:List*",
    "iam:Get*", "iam:List*"
]


def get_all_policies():
    """
    Get all IAM policies.
    """
    policies = []
    try:
        paginator = iam_client.get_paginator('list_policies')
        for response in paginator.paginate(Scope='Local'):
            policies.extend(response['Policies'])
    except Exception as e:
        logging.error(f"Failed to get policies: {e}")
    return policies


def get_policy_document(policy_arn):
    """
    Get the policy document for a given policy ARN.
    """
    try:
        version = iam_client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
        policy_version = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=version)['PolicyVersion']
        policy_document = policy_version['Document']
        return policy_document
    except Exception as e:
        logging.error(f"Failed to get policy document for {policy_arn}: {e}")
        return None


def categorize_risk(actions, resources):
    """
    Categorize the risk level based on actions and resources using IAM risk model.
    """
    high_risk_keywords = ['delete', 'put', 'create', 'update', 'attach', 'detach']
    risk_level = 'Low'
    mitre_techniques = set()

    if '*' in actions and '*' in resources:
        return 'High', {"T1078"}

    for action in actions:
        if action in pacu_iam_actions or action in high_risk_actions:
            risk_level = 'High'
            mitre_techniques.add(high_risk_actions.get(action, "T1078"))
        elif any(keyword in action.lower() for keyword in high_risk_keywords):
            if risk_level != 'High':
                risk_level = 'Medium'
                mitre_techniques.add(high_risk_actions.get(action, "T1106"))
        elif action.endswith(':*') or '*' in action:
            if risk_level != 'High':
                risk_level = 'Medium'
                mitre_techniques.add(high_risk_actions.get(action, "T1106"))

    if all(action in read_only_actions for action in actions):
        risk_level = 'Low'

    return risk_level, mitre_techniques


def find_overly_permissive_details(policy_document):
    """
    Find details of overly permissive actions and resources in a policy document.
    """
    try:
        if isinstance(policy_document, str):
            policy_document = json.loads(policy_document)
        permissive_details = []
        for statement in policy_document.get('Statement', []):
            if statement.get('Effect') == 'Allow':
                actions = statement.get('Action', [])
                resources = statement.get('Resource', [])
                if isinstance(actions, str):
                    actions = [actions]
                if isinstance(resources, str):
                    resources = [resources]
                # Exclude common read-only actions
                actions = [action for action in actions if action not in read_only_actions]
                if not actions:
                    continue
                risk_level, mitre_techniques = categorize_risk(actions, resources)
                if risk_level in ['High', 'Medium', 'Low']:
                    permissive_details.append({
                        "Actions": actions,
                        "Resources": resources,
                        "Risk": risk_level,
                        "MITRE Techniques": mitre_techniques
                    })
        return permissive_details
    except Exception as e:
        logging.error(f"Error checking policy document: {e}")
        return []


def get_roles_with_policy(policy_arn):
    """
    Get roles attached to a specific policy.
    """
    roles = []
    try:
        paginator = iam_client.get_paginator('list_entities_for_policy')
        for response in paginator.paginate(PolicyArn=policy_arn):
            roles.extend(response['PolicyRoles'])
    except Exception as e:
        logging.error(f"Failed to get roles for policy {policy_arn}: {e}")
    return roles


def describe_policy_access(actions):
    """
    Describe the type of access (read/write) actions grant.
    """
    try:
        access_types = set()
        for action in actions:
            if any(keyword in action.lower() for keyword in ['put', 'post', 'delete', 'update', 'create']):
                access_types.add('write')
            elif any(keyword in action.lower() for keyword in ['get', 'list', 'read', 'describe']):
                access_types.add('read')
        return ', '.join(access_types) if access_types else 'unknown'
    except Exception as e:
        logging.error(f"Error describing policy access: {e}")
        return 'unknown'


def generate_html_report(overly_permissive_policies, filename):
    """
    Generate an HTML report highlighting overly permissive roles in red.
    """
    html_content = """
    <html>
    <head>
        <title>Overly Permissive IAM Policies Report</title>
        <style>
            table {width: 100%; border-collapse: collapse;}
            th, td {border: 1px solid black; padding: 8px; text-align: left;}
            th {background-color: #f2f2f2;}
            .high-risk {background-color: red; color: white;}
            .medium-risk {background-color: orange; color: black;}
            .low-risk {background-color: yellow; color: black;}
        </style>
    </head>
    <body>
        <h2>Overly Permissive IAM Policies Report</h2>
        <p>This report identifies IAM roles and policies that are overly permissive, potentially exposing your AWS environment to risks. The roles are categorized into High, Medium, and Low risk levels based on the sensitivity of the actions they allow and their alignment with the MITRE ATT&CK framework.</p>
        <ul>
            <li><span style="color:red;">High Risk:</span> Allows highly sensitive actions such as user creation, policy attachment, and access key management. These roles pose a significant risk if compromised.</li>
            <li><span style="color:orange;">Medium Risk:</span> Allows wildcard actions on specific resources or a combination of sensitive actions. These roles should be reviewed and restricted.</li>
            <li><span style="color:yellow;">Low Risk:</span> Allows broad access but on less sensitive resources. These roles should be reviewed for necessity and minimized.</li>
        </ul>
        <table>
            <tr>
                <th>Resource</th>
                <th>IAM Policy</th>
                <th>Actions</th>
                <th>Resources</th>
                <th>Access Type</th>
                <th>Risk Level</th>
                <th>MITRE Techniques</th>
            </tr>
    """

    for role_names, policy_name, actions, resources, access_type, risk_level, mitre_techniques in overly_permissive_policies:
        resource = ', '.join(role_names) if role_names else 'No roles attached'
        risk_class = risk_level.lower().replace(' ', '-') + '-risk'
        html_content += f"""
            <tr class="{risk_class}">
                <td>{resource}</td>
                <td>{policy_name}</td>
                <td>{', '.join(actions)}</td>
                <td>{', '.join(resources)}</td>
                <td>{access_type}</td>
                <td>{risk_level}</td>
                <td>{', '.join(mitre_techniques)}</td>
            </tr>
        """

    html_content += """
        </table>
    </body>
    </html>
    """

    with open(filename, 'w') as file:
        file.write(html_content)


def main():
    """
    Main function to detect overly permissive IAM policies and their associated roles.
    """
    logging.info("Starting Johndcyber IAM Resource Scanner...")

    policies = get_all_policies()
    overly_permissive_policies = []

    for policy in policies:
        policy_arn = policy['Arn']
        policy_name = policy['PolicyName']
        policy_document = get_policy_document(policy_arn)
        if policy_document:
            permissive_details = find_overly_permissive_details(policy_document)
            for detail in permissive_details:
                roles = get_roles_with_policy(policy_arn)
                role_names = [role['RoleName'] for role in roles]
                access_type = describe_policy_access(detail["Actions"])
                overly_permissive_policies.append((role_names, policy_name, detail["Actions"], detail["Resources"],
                                                   access_type, detail["Risk"], detail["MITRE Techniques"]))

    if overly_permissive_policies:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        csv_filename = f'overly_permissive_policies_{timestamp}.csv'
        html_filename = f'overly_permissive_policies_{timestamp}.html'

        # Generate CSV
        with open(csv_filename, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(
                ['Resource', 'IAM Policy', 'Actions', 'Resources', 'Access Type', 'Risk Level', 'MITRE Techniques'])
            for role_names, policy_name, actions, resources, access_type, risk_level, mitre_techniques in overly_permissive_policies:
                resource = ', '.join(role_names) if role_names else 'No roles attached'
                writer.writerow(
                    [resource, policy_name, ', '.join(actions), ', '.join(resources), access_type, risk_level,
                     ', '.join(mitre_techniques)])

        logging.info(f"Overly permissive policies found and written to '{csv_filename}'")

        # Generate HTML Report
        generate_html_report(overly_permissive_policies, html_filename)
        logging.info(f"HTML report generated at '{html_filename}'")

    else:
        logging.info("No overly permissive policies found.")

    logging.info("Johndcyber IAM Resource Scanner completed.")


if __name__ == "__main__":
    main()

