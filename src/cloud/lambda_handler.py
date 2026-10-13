"""Optional AWS Lambda handler for forwarding a matching finding to SNS.

Deployment requires an SNS_TOPIC_ARN environment variable and an execution role
permitted to publish to that topic. This handler does not remediate resources.
"""
import json
import os


def lambda_handler(event, context):
    import boto3  # Imported inside the handler so local imports don't require AWS setup.

    topic_arn = os.environ.get("SNS_TOPIC_ARN")
    if not topic_arn:
        raise ValueError("SNS_TOPIC_ARN environment variable is required.")

    detail = event.get("detail", {}) if isinstance(event, dict) else {}
    title = detail.get("title") or detail.get("type") or event.get("source", "Security finding")
    severity = detail.get("severity", "Unknown")
    account = event.get("account", "Unknown")
    region = event.get("region", "Unknown")
    finding_id = detail.get("id", "Not provided")

    message = (
        "AWS security finding for investigation\n\n"
        f"Title/type: {title}\n"
        f"Severity: {severity}\n"
        f"Account: {account}\n"
        f"Region: {region}\n"
        f"Finding ID: {finding_id}\n\n"
        "This notification is a triage signal. Validate the underlying evidence before taking action."
    )

    sns = boto3.client("sns")
    response = sns.publish(
        TopicArn=topic_arn,
        Subject="AWS Suspicious Activity Alert"[:100],
        Message=message,
    )
    return {"statusCode": 200, "body": json.dumps({"messageId": response.get("MessageId")})}
