import boto3, os, json, logging

log = logging.getLogger()
log.setLevel(logging.INFO)

ec2 = boto3.client("ec2")
sns = boto3.client("sns")

# tolerate either env var name
SNS_TOPIC_ARN = (
    os.environ.get("SNS_TOPIC_ARN") or
    os.environ.get("SNS_TOPIC_ARN_NEW") or
    ""
)
TAG_KEY        = os.environ.get("INSTANCE_TAG_KEY", "IncidentStatus")
RESTORED_VALUE = os.environ.get("RESTORED_VALUE", "Healthy")

def _notify_restored(instance_id, original_sg_ids):
    if not SNS_TOPIC_ARN:
        return
    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject="[GuardDuty] EC2 Restored",
            Message=(
                "GuardDuty Restore:\n"
                f"Instance {instance_id} restored to original security groups "
                f"({', '.join(original_sg_ids)}) and tagged {TAG_KEY}={RESTORED_VALUE}."
            ),
        )
    except Exception as e:
        log.exception("SNS publish failed: %s", e)

def _notify_skipped(instance_id, reason):
    if not SNS_TOPIC_ARN:
        return
    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject="[GuardDuty] Restore Skipped",
            Message=f"Restore skipped for {instance_id}: {reason}",
        )
    except Exception as e:
        log.exception("SNS publish failed: %s", e)

def lambda_handler(event, context):
    """
    Accepts:
      - {"InstanceIds": ["i-...","i-..."]}  OR
      - {"InstanceId": "i-..."}            OR
      - {"instanceId": "i-..."}            (from approval link)
    """
    log.info("EVENT: %s", json.dumps(event))

    # accept lowercase instanceId too
    instance_ids = []
    if event.get("InstanceIds"):
        instance_ids = event["InstanceIds"]
    elif event.get("InstanceId"):
        instance_ids = [event["InstanceId"]]
    elif event.get("instanceId"):
        instance_ids = [event["instanceId"]]
    else:
        raise ValueError("Must supply InstanceId(s) in payload")

    restored, skipped = [], []

    for instance_id in instance_ids:
        details = ec2.describe_instances(InstanceIds=[instance_id])
        ins = details["Reservations"][0]["Instances"][0]

        # pull OriginalSGs tag
        original_tag = next(
            (t["Value"] for t in ins.get("Tags", []) if t["Key"] == "OriginalSGs"),
            None
        )
        if not original_tag:
            log.warning("%s: no OriginalSGs tag – skipping", instance_id)
            _notify_skipped(instance_id, "missing OriginalSGs tag")
            skipped.append(instance_id)
            continue

        original_sg_ids = original_tag.split(",")

        # restore SGs on every ENI
        for eni in ins["NetworkInterfaces"]:
            eni_id = eni["NetworkInterfaceId"]
            ec2.modify_network_interface_attribute(
                NetworkInterfaceId=eni_id,
                Groups=original_sg_ids
            )
            log.info("%s: ENI %s restored to %s", instance_id, eni_id, original_sg_ids)

        # update tags: delete OriginalSGs, set IncidentStatus=Healthy
        ec2.delete_tags(Resources=[instance_id], Tags=[{"Key": "OriginalSGs"}])
        ec2.create_tags(Resources=[instance_id], Tags=[{"Key": TAG_KEY, "Value": RESTORED_VALUE}])
        log.info("%s: tags updated to %s=%s", instance_id, TAG_KEY, RESTORED_VALUE)

        _notify_restored(instance_id, original_sg_ids)
        restored.append(instance_id)

    # return summary (no JSON email sent)
    return {
        "event": "RestoreApproved",
        "restored": restored,
        "skipped_no_original_sgs": skipped,
        "source": event.get("source"),
        "findingId": event.get("findingId"),
    }
