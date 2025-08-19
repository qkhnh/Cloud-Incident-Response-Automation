import os, re, json, time, uuid, hmac, hashlib, logging
from urllib.parse import quote_plus
import boto3
from botocore.exceptions import ClientError

log = logging.getLogger()
log.setLevel(logging.INFO)

# --- clients ---
ec2  = boto3.client("ec2")
sns  = boto3.client("sns")
ssm  = boto3.client("ssm")
ddb  = boto3.resource("dynamodb")

# --- env ---
BLOCKING_SG_ID       = os.environ["BLOCKING_SG_ID"]
SNS_TOPIC_ARN        = os.environ["SNS_TOPIC_ARN_NEW"]
APPROVAL_BASE_URL    = (os.environ.get("APPROVAL_BASE_URL")
                        or os.environ.get("APPROVAL_FUNCTION_URL", "")).rstrip("/")
APPROVAL_SECRET_PARAM= os.environ["APPROVAL_SECRET_PARAM"]
TOKENS_TABLE_NAME    = os.environ["INCIDENT_TOKENS_TABLE"]
EXPIRE_MINUTES       = int(os.environ.get("EXPIRE_MINUTES", "60"))
INSTANCE_TAG_KEY     = os.environ.get("INSTANCE_TAG_KEY", "IncidentStatus")
QUARANTINED_VALUE    = os.environ.get("QUARANTINED_VALUE", "Quarantined")

# --- sample finding override (keep) ---
TEST_INSTANCE_ID = "i-014802609759663a1"
SAMPLE_ID_REGEX  = r"i-9{8,17}"

# --- helpers ---
def _get_secret_bytes():
    p = ssm.get_parameter(Name=APPROVAL_SECRET_PARAM, WithDecryption=True)
    return p["Parameter"]["Value"].encode("utf-8")

def _sign(secret: bytes, instance_id: str, finding_id: str, token: str) -> str:
    msg = f"{instance_id}|{finding_id}|{token}".encode("utf-8")
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()

def _create_token_and_link(instance_id: str, finding_id: str, finding_title: str) -> str:
    token = uuid.uuid4().hex
    now   = int(time.time())

    # Ensure EXPIRE_MINUTES is non-negative and use it to calculate expires_at
    expire_minutes = max(0, int(os.environ.get("EXPIRE_MINUTES", "60")))
    exp   = now + expire_minutes * 60

    # store token record (TTL handled by table's expires_at attribute)
    table = ddb.Table(TOKENS_TABLE_NAME)
    table.put_item(Item={
        "token": token,
        "instanceId": instance_id,
        "findingId": finding_id,
        "findingTitle": finding_title or "",
        "created_at": now,
        "expires_at": exp,
        "used": False
    })

    sig = _sign(_get_secret_bytes(), instance_id, finding_id, token)

    # build approval link
    return (
        f"{APPROVAL_BASE_URL}"
        f"?instanceId={quote_plus(instance_id)}"
        f"&findingId={quote_plus(finding_id)}"
        f"&findingTitle={quote_plus(finding_title or '')}"
        f"&token={token}"
        f"&sig={sig}"
    )

def lambda_handler(event, context):
    log.info("Received event: %s", json.dumps(event))

    # 1) normalize GuardDuty/SecurityHub shape
    detail  = event.get("detail", {})
    finding = detail["findings"][0] if "findings" in detail else detail

    # 2) instance details
    inst_det = (
        finding.get("resource", {}).get("instanceDetails")
        or finding.get("Resource", {}).get("InstanceDetails")
        or {}
    )
    instance_id = inst_det.get("instanceId") or inst_det.get("InstanceId")
    if not instance_id:
        raise Exception("No instanceId found in finding")

    finding_id    = (finding.get("id") or finding.get("Id")
                     or finding.get("findingId") or finding.get("FindingId") or "")
    finding_title = (finding.get("title") or finding.get("Title") or "")

    # 3) swap fake sample ID for your real test instance
    if re.fullmatch(SAMPLE_ID_REGEX, instance_id):
        log.warning("Sample finding detected – swapping %s -> %s", instance_id, TEST_INSTANCE_ID)
        instance_id = TEST_INSTANCE_ID

    # 4) describe once, then quarantine each ENI
    try:
        res = ec2.describe_instances(InstanceIds=[instance_id])
    except ClientError as e:
        log.error("describe_instances failed for %s: %s", instance_id, e)
        raise

    interfaces = res["Reservations"][0]["Instances"][0]["NetworkInterfaces"]

    for eni in interfaces:
        eni_id          = eni["NetworkInterfaceId"]
        original_sg_ids = [g["GroupId"] for g in eni["Groups"]]
        log.info("Original SGs for %s : %s", eni_id, original_sg_ids)

        # tag instance with original SGs + quarantined status
        ec2.create_tags(
            Resources=[instance_id],
            Tags=[
                {"Key": "OriginalSGs",      "Value": ",".join(original_sg_ids)},
                {"Key": INSTANCE_TAG_KEY,   "Value": QUARANTINED_VALUE}
            ]
        )

        ec2.modify_network_interface_attribute(
            NetworkInterfaceId=eni_id,
            Groups=[BLOCKING_SG_ID]
        )
        log.info("ENI %s quarantined with SG %s", eni_id, BLOCKING_SG_ID)

    # 5) approval link (tokenized)
    approve_link_line = ""
    if APPROVAL_BASE_URL:
        try:
            approve_link = _create_token_and_link(instance_id, finding_id, finding_title)
            approve_link_line = (
                "\n\nAction:\n"
                "Approve restore (opens confirmation page):\n"
                f"{approve_link}\n"
            )
        except Exception as e:
            log.exception("Failed to create approval token/link: %s", e)
            approve_link_line = "\n\nAction:\nApproval link unavailable due to an error.\n"
    else:
        log.warning("APPROVAL_BASE_URL not set – quarantine email will NOT include approval link")

    # 6) notify via SNS
    msg = (
        "GuardDuty Alert:\n"
        f"Instance {instance_id} quarantined.\n"
        f"Title: {finding_title}"
        f"{approve_link_line}"
    )
    resp = sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject="[GuardDuty] EC2 Quarantined",
        Message=msg
    )
    if not resp.get("MessageId"):
        raise Exception("SNS publish failed")

    log.info("SNS sent MessageId=%s", resp["MessageId"])
    return {"status": "done"}
