import boto3
import json
import os
from datetime import datetime, timezone

iam = boto3.client('iam')
dynamodb = boto3.resource('dynamodb')
sns = boto3.client('sns')

DENY_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Deny",
        "Action": "*",
        "Resource": "*"
    }]
})

def lambda_handler(event, context):
    print(f"[icorp-IR] Event received: {json.dumps(event)}")

    # Extract GuardDuty finding details from EventBridge event
    detail = event.get('detail', {})
    finding_type = detail.get('type', 'UNKNOWN')
    severity = detail.get('severity', 0)
    account_id = detail.get('accountId', 'UNKNOWN')
    region = detail.get('region', 'UNKNOWN')

    # Extract affected IAM principal
    access_key_details = (
        detail.get('resource', {})
              .get('accessKeyDetails', {})
    )
    username = access_key_details.get('userName', 'UNKNOWN')
    access_key_id = access_key_details.get('accessKeyId', 'UNKNOWN')

    print(f"[icorp-IR] Compromised principal: {username} | Key: {access_key_id}")

    containment_actions = []

    # Step 1: Revoke the access key immediately
    if access_key_id != 'UNKNOWN':
        try:
            iam.update_access_key(
                UserName=username,
                AccessKeyId=access_key_id,
                Status='Inactive'
            )
            containment_actions.append(f"ACCESS_KEY_REVOKED:{access_key_id}")
            print(f"[icorp-IR] Access key {access_key_id} revoked.")
        except Exception as e:
            print(f"[icorp-IR] Failed to revoke key: {e}")

    # Step 2: Attach explicit Deny-All inline policy
    if username != 'UNKNOWN':
        try:
            iam.put_user_policy(
                UserName=username,
                PolicyName='IREmergencyDenyAll',
                PolicyDocument=DENY_POLICY
            )
            containment_actions.append("DENY_ALL_POLICY_ATTACHED")
            print(f"[icorp-IR] Deny-All policy attached to {username}.")
        except Exception as e:
            print(f"[icorp-IR] Failed to attach deny policy: {e}")

    # Step 3: Record case in DynamoDB
    case_id = f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    table = dynamodb.Table(os.environ['DYNAMODB_TABLE'])
    case_record = {
        'case_id': case_id,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'finding_type': finding_type,
        'severity': str(severity),
        'affected_principal': username,
        'affected_key': access_key_id,
        'account_id': account_id,
        'region': region,
        'containment_actions': containment_actions,
        'status': 'CONTAINED',
        'analyst_reviewed': False
    }
    table.put_item(Item=case_record)
    print(f"[icorp-IR] Case recorded: {case_id}")

    # Step 4: Send SNS alert to security team
    alert_message = f"""
[/!\ icorp-IR ALERT] — IAM Identity Compromised

Case ID     : {case_id}
Finding     : {finding_type}
Severity    : {severity}
Principal   : {username}
Access Key  : {access_key_id}
Account     : {account_id}
Region      : {region}
Time        : {datetime.now(timezone.utc).isoformat()}

Containment Actions Taken:
{chr(10).join(f'  ✓ {a}' for a in containment_actions)}

Status      : CONTAINED — Pending analyst review.
Dashboard   : https://console.aws.amazon.com/guardduty/home

This is an automated response by icorp-IR.
iCorp Security
    """

    sns.publish(
        TopicArn=os.environ['SNS_TOPIC_ARN'],
        Subject=f"[icorp-IR] IAM Compromise Detected — {username} — {case_id}",
        Message=alert_message
    )
    print(f"[icorp-IR] SNS alert sent.")

    return {
        'statusCode': 200,
        'case_id': case_id,
        'status': 'CONTAINED'
    }
